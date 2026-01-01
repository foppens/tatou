import fitz  # PyMuPDF
from pathlib import Path
import hashlib
import secrets
import pytest
from src.watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    WatermarkingError,
    SecretNotFoundError,
    InvalidKeyError,
    load_pdf_bytes,
)

class LogoWatermark(WatermarkingMethod):
    name = "logo-watermark"

    @staticmethod
    def get_usage() -> str:
        return "Adds a watermark to each page in the pdf with a logo image."

   
    @staticmethod
    def _derive_key_stream(key: str, length: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            h = hashlib.sha256()
            h.update(key.encode("utf-8"))
            h.update(counter.to_bytes(4, "big"))
            out += h.digest()
            counter += 1
        return out[:length]

    @staticmethod
    def _encrypt_secret(secret: str, key: str) -> str:
        plain = secret.encode("utf-8")
        ks = LogoWatermark._derive_key_stream(key, len(plain))
        enc = bytes(a ^ b for a, b in zip(plain, ks))
        return enc.hex()

    @staticmethod
    def _decrypt_secret(enc_hex: str, key: str) -> str:
        enc = bytes.fromhex(enc_hex)
        ks = LogoWatermark._derive_key_stream(key, len(enc))
        plain = bytes(a ^ b for a, b in zip(enc, ks))
        return plain.decode("utf-8", errors="replace")

    
    def add_watermark(self, pdf: PdfSource, secret: str | None, key: str, position: str | None = None) -> bytes:
        try:
            if not secret:
                secret = secrets.token_hex(16)

            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")

            # Kryptera secret
            enc = self._encrypt_secret(secret, key)            

            # Placera logga på varje sida
            logo_path = Path(__file__).parent / "unknown.jpg"
            if not logo_path.exists():
                raise FileNotFoundError(f"Logo not found at {logo_path}")

            for page in doc:
                r = page.rect
                rect = fitz.Rect(r.width - 120, r.height - 120, r.width - 20, r.height - 20)
                page.insert_image(rect, filename=str(logo_path), overlay=True)

            
            meta = dict(doc.metadata) if doc.metadata else {}
            meta["subject"] = enc  
            doc.set_metadata(meta)

            return doc.write()
        except Exception as e:
            raise WatermarkingError(f"Failed to add logo watermark: {e}") from e

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            
            enc = doc.metadata.get("subject")
            if not enc:
                raise SecretNotFoundError("Encrypted secret not found in PDF metadata.")
            return self._decrypt_secret(enc, key)
        except SecretNotFoundError:
            raise
        except Exception as e:
            raise InvalidKeyError(f"Failed to read secret from logo watermark: {e}") from e

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            _ = load_pdf_bytes(pdf)
            return True
        except Exception:
            return False


@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    pdf_path = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    doc.new_page()
    doc.save(pdf_path)
    doc.close()
    return pdf_path