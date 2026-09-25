from __future__ import annotations

import hashlib
import secrets


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


watermark_service = WatermarkService()
