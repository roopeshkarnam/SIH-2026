from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from app.services.hashing import hashing_service
from app.services.pqc import pqc_service


class ProvenanceService:
    @staticmethod
    def build_record(
        document_id: str,
        document_hash: str,
        recipient_id: str,
        session_id: str,
        watermark_id: str,
    ) -> dict:
        record = {
            "document_id": document_id,
            "document_hash": document_hash,
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signature_algorithm": pqc_service.SIGNATURE_ALGORITHM,
        }
        record["record_hash"] = hashing_service.canonical_json_hash(record)
        return record

    @staticmethod
    def sign_record(record: dict, private_key: bytes) -> dict:
        message = record["record_hash"].encode()
        signature = pqc_service.sign(private_key, message)
        result = dict(record)
        result["signature"] = base64.b64encode(signature).decode()
        return result

    @staticmethod
    def verify_record(record: dict, public_key: bytes) -> bool:
        signature = base64.b64decode(record["signature"])
        return pqc_service.verify(
            public_key,
            record["record_hash"].encode(),
            signature,
        )


provenance_service = ProvenanceService()
