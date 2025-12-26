from __future__ import annotations
from io import BytesIO
from typing import Optional
import base64
import hashlib

import fitz  # PyMuPDF
from cryptography.fernet import Fernet, InvalidToken

from src.watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
)


class AxelWatermark(WatermarkingMethod):
    name = "axel"

    @staticmethod
    def get_usage() -> str:
        return "Embeds an encrypted secret in visible and invisible watermarks. Key decrypts to reveal the secret."

    @staticmethod
    def _derive_fernet_key(key: str) -> bytes:
        """Derive a 32-byte urlsafe base64 key for Fernet from an arbitrary-length key."""
        h = hashlib.sha256(key.encode("utf-8")).digest()  # 32 bytes
        return base64.urlsafe_b64encode(h)  # Fernet expects base64-encoded 32 bytes

    @staticmethod
    def _encrypt_secret(secret: str, key: str) -> str:
        fkey = AxelWatermark._derive_fernet_key(key)
        f = Fernet(fkey)
        token = f.encrypt(secret.encode("utf-8"))
        return token.decode("utf-8")

    @staticmethod
    def _decrypt_secret(encrypted: str, key: str) -> str:
        fkey = AxelWatermark._derive_fernet_key(key)
        f = Fernet(fkey)
        try:
            plain = f.decrypt(encrypted.encode("utf-8"))
            return plain.decode("utf-8")
        except InvalidToken as e:
            raise ValueError("decryption failed") from e

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,       # this is the session key to embed
        key: str,          # this is the master key used for encryption
        position: Optional[str] = None,  # unused but accepted
        intended_for: Optional[str] = None,  # optional metadata
    ) -> bytes:
        if not key:
            raise ValueError("key (master key) must be provided")
        if not secret:
            raise ValueError("secret (session key) must be provided")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")

        encrypted_token = self._encrypt_secret(secret, key)
        fingerprint = hashlib.sha256(secret.encode("utf-8")).hexdigest()

        visible_text = f"Watermarked with Axel-Watermark\nFingerprint: {fingerprint}\nDo not distribute"
        invisible_text = f"Watermarked with Axel-Watermark (encrypted) {encrypted_token} Do not distribute"

        for page in doc:
            width, height = page.rect.width, page.rect.height
            fontsize = min(max(int(height * 0.012), 10), 12)

            line_count = visible_text.count("\n") + 1
            line_spacing = fontsize * 1.1
            block_height = line_count * line_spacing

            x_step = width * 1.5
            y_step = block_height * 2
            y = -height
            while y < height * 1.5:
                x = -width
                while x < width * 1.5:
                    char_width = fontsize * 0.6
                    max_line_length = max(len(line) for line in visible_text.splitlines())
                    text_width = char_width * max_line_length

                    shape = page.new_shape()
                    shape.insert_text(
                        fitz.Point(x - text_width / 2, y),
                        visible_text,
                        fontsize=fontsize,
                        fontname="courier",
                        rotate=0,
                        color=(0, 0, 0),
                        fill_opacity=0.3,
                    )
                    shape.commit()
                    x += x_step
                y += y_step

            x_step_inv = width * 0.5
            y_step_inv = height * 0.1
            y = 0
            while y < height:
                x = 0
                while x < width:
                    shape = page.new_shape()
                    shape.insert_text(
                        fitz.Point(x, y),
                        invisible_text,
                        fontsize=1,
                        fontname="courier",
                        rotate=0,
                        color=(1, 1, 1),
                        fill_opacity=0,
                    )
                    shape.commit()
                    x += x_step_inv
                y += y_step_inv

        out = BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            ok = len(doc) > 0
            doc.close()
            return ok
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not key:
            raise ValueError("key (master key) must be provided")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")

        invisible_prefix = "Watermarked with Axel-Watermark (encrypted) "
        suffix = "Do not distribute"

        def try_decrypt(token: str) -> Optional[str]:
            try:
                return self._decrypt_secret(token, key)
            except Exception:
                return None

        for page in doc:
            try:
                txt = page.get_text("text")
            except Exception:
                txt = ""
            if not txt:
                continue

            lines = txt.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith(invisible_prefix) and line.endswith(suffix):
                    token = line[len(invisible_prefix):-len(suffix)].strip()
                    plain = try_decrypt(token)
                    if plain is not None:
                        doc.close()
                        return plain

        doc.close()
        raise SecretNotFoundError("Encrypted watermark not found or decryption failed.")