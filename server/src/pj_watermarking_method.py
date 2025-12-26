import os
import base64
import hashlib
import hmac
from .watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    WatermarkingError,
    SecretNotFoundError,
    InvalidKeyError,
    load_pdf_bytes,
)
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MyWatermarkingMethod(WatermarkingMethod):
    name = "my-method-secure"


    @staticmethod
    def get_usage() -> str:
        return (
            "Adds a watermark text to each page in the pdf"
        )


    def _derive_key(self, key: str) -> bytes:
        # Derive a 256-bit key from the user key
        return hashlib.sha256(key.encode("utf-8")).digest()


    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        try:
            data = load_pdf_bytes(pdf)
            original = PdfReader(BytesIO(data))
            if not original.pages:
                raise WatermarkingError("Cannot add watermark: PDF has zero pages.")

            writer = PdfWriter()
            for page in original.pages:
                # Create a watermark PDF matching the current page size
                page_width = float(page.mediabox.width)
                page_height = float(page.mediabox.height)
                watermark_pdf = BytesIO()
                c = canvas.Canvas(watermark_pdf, pagesize=(page_width, page_height))
                c.setFont("Helvetica-Bold", 36)
                c.setFillColorRGB(0.7, 0.7, 0.7, alpha=0.3)
                c.drawCentredString(page_width / 2, page_height / 2, "Watermark")
                c.save()
                watermark_pdf.seek(0)
                watermark = PdfReader(watermark_pdf)
                page.merge_page(watermark.pages[0])
                writer.add_page(page)

            # Encrypt the secret as before
            aes_key = self._derive_key(key)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, secret.encode("utf-8"), None)
            encrypted_blob = (
                f"{base64.urlsafe_b64encode(nonce).decode('ascii')}:"
                f"{base64.urlsafe_b64encode(ct).decode('ascii')}"
            )

            #Store encrypted secret in PDF metadata
            writer.add_metadata({"/X": encrypted_blob})

            #Write the final PDF once
            output_pdf = BytesIO()
            writer.write(output_pdf)
            output_pdf.seek(0)
            return output_pdf.read()
        except Exception as e:
            print(f"add_watermark error: {e}")
            raise WatermarkingError("Failed to add watermark") from e


    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        data = load_pdf_bytes(pdf)
        return data.startswith(b"%PDF-")


    def read_secret(self, pdf: PdfSource, key: str) -> str:
        try:
            data = load_pdf_bytes(pdf)
            reader = PdfReader(BytesIO(data))
            metadata = reader.metadata
            if not metadata or "/X" not in metadata:
                raise SecretNotFoundError("No watermark found.")
            encrypted_blob = metadata.get("/X")
            if not encrypted_blob:
                raise SecretNotFoundError("No watermark found.")
            try:
                nonce_b64, ct_b64 = encrypted_blob.split(":", 1)
                nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
                ct = base64.urlsafe_b64decode(ct_b64.encode("ascii"))
            except Exception:
                raise WatermarkingError("Malformed watermark.")
            aes_key = self._derive_key(key)
            aesgcm = AESGCM(aes_key)
            try:
                secret = aesgcm.decrypt(nonce, ct, None).decode("utf-8")
            except Exception:
                raise InvalidKeyError("wrong key")
            return secret
        except Exception as e:
            print(f"read_secret error: {e}")
            raise
