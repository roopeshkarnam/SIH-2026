from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from app.db.models import DecryptionSession, Document, ProvenanceRecord
from app.services.hashing import hashing_service
from app.services.key_store import key_store
from app.services.ledger import ledger_service
from app.services.pqc import pqc_service


class ProvenanceService:
    @staticmethod
    def build_record(
        document_id: str,
        document_hash: str,
        recipient_id: str,
        session_id: str,
        watermark_id: str,
        session_nonce: str,
    ) -> dict:
        record = {
            "document_id": document_id,
            "document_hash": document_hash,
            "recipient_id": recipient_id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "session_nonce": session_nonce,
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


    @staticmethod
    def sign_session(db, session: DecryptionSession, document: Document) -> ProvenanceRecord:
        """Sign the decryption record with the recipient's ML-DSA-65 key and commit it to the
        ledger. Called as part of decryption: no signed record, no plaintext.

        Raises FileNotFoundError if the recipient has no signing key.
        """
        private_key = key_store.load_private_key(f"{session.recipient_id}_sig")
        record = ProvenanceService.build_record(
            document_id=document.id,
            document_hash=document.document_hash,
            recipient_id=session.recipient_id,
            session_id=session.id,
            watermark_id=session.watermark_id,
            session_nonce=session.session_nonce,
        )
        signed = ProvenanceService.sign_record(record, private_key)
        db_record = ProvenanceRecord(
            id=hashing_service.sha256_bytes(f"{session.id}:{session.watermark_id}".encode())[:64],
            document_id=document.id,
            recipient_id=session.recipient_id,
            session_id=session.id,
            watermark_id=session.watermark_id,
            document_hash=document.document_hash,
            record_hash=signed["record_hash"],
            signature=signed["signature"],
            signature_algorithm=signed["signature_algorithm"],
            ledger_transaction_id=ledger_service.commit_provenance(db, signed),
        )
        db.add(db_record)
        session.status = "provenance-committed"
        return db_record


provenance_service = ProvenanceService()
