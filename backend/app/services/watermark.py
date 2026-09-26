from __future__ import annotations

import hashlib
import re
import secrets

import pymupdf

WATERMARK_PATTERN = re.compile(r"WM-[0-9A-F]{32}")


class WatermarkService:
    """
    Deterministic forensic identifier for the MVP.
    The PDF pixel/DCT embedding layer is kept behind this service so it can
    be upgraded without changing provenance or ledger code.
    """

    @staticmethod
    def generate_watermark_id() -> str:
        return "WM-" + secrets.token_hex(16).upper()

    @staticmethod
    def fingerprint_payload(
        document_hash: str,
        watermark_id: str,
        session_id: str,
    ) -> str:
        payload = f"{document_hash}|{watermark_id}|{session_id}".encode()
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def embed_pdf(pdf_bytes: bytes, watermark_id: str) -> bytes:
        """Write the watermark ID as invisible text on every page and in the metadata."""
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        for page in doc:
            # render_mode=3 draws the text invisibly, but it can still be extracted.
            page.insert_text((10, page.rect.height - 10), watermark_id, fontsize=4, render_mode=3)
        metadata = doc.metadata
        metadata["keywords"] = watermark_id
        doc.set_metadata(metadata)
        return doc.tobytes()

    @staticmethod
    def extract_pdf(pdf_bytes: bytes) -> str | None:
        """Return the first watermark ID found in the page text or metadata."""
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        text = (doc.metadata.get("keywords") or "") + "".join(page.get_text() for page in doc)
        match = WATERMARK_PATTERN.search(text)
        return match.group(0) if match else None


watermark_service = WatermarkService()
