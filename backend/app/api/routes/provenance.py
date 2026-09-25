import base64
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import DecryptionSession, Document, ProvenanceRecord, User
from app.services.hashing import hashing_service
from app.services.key_store import key_store
from app.services.ledger import ledger_service
from app.services.provenance import provenance_service

router = APIRouter(prefix="/provenance", tags=["Provenance"])


@router.post("/create/{session_id}")
def create_provenance(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.get(DecryptionSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")

    if session.recipient_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized.")

    document = db.get(Document, session.document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found.")

    private_key = key_store.load_private_key(f"{current_user.id}_sig")

    record = provenance_service.build_record(
        document_id=document.id,
        document_hash=document.document_hash,
        recipient_id=current_user.id,
        session_id=session.id,
        watermark_id=session.watermark_id,
    )
    signed = provenance_service.sign_record(record, private_key)

    transaction_id = ledger_service.commit_provenance(signed)

    db_record = ProvenanceRecord(
        id=hashing_service.sha256_bytes(
            f"{session.id}:{session.watermark_id}".encode()
        )[:64],
        document_id=document.id,
        recipient_id=current_user.id,
        session_id=session.id,
        watermark_id=session.watermark_id,
        document_hash=document.document_hash,
        record_hash=signed["record_hash"],
        signature=signed["signature"],
        signature_algorithm=signed["signature_algorithm"],
        ledger_transaction_id=transaction_id,
    )
    db.add(db_record)
    session.status = "provenance-committed"
    db.commit()

    return {
        "watermark_id": session.watermark_id,
        "record_hash": signed["record_hash"],
        "signature": signed["signature"],
        "signature_algorithm": signed["signature_algorithm"],
        "ledger_transaction_id": transaction_id,
    }


@router.get("/{watermark_id}")
def lookup_provenance(
    watermark_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    record = (
        db.query(ProvenanceRecord)
        .filter(ProvenanceRecord.watermark_id == watermark_id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Provenance not found.")

    public_key = key_store.load_public_key(f"{record.recipient_id}_sig")
    verified = provenance_service.verify_record(
        {
            "record_hash": record.record_hash,
            "signature": record.signature,
        },
        public_key,
    )

    return {
        "watermark_id": record.watermark_id,
        "document_id": record.document_id,
        "recipient_id": record.recipient_id,
        "session_id": record.session_id,
        "record_hash": record.record_hash,
        "signature_algorithm": record.signature_algorithm,
        "signature_verified": verified,
        "ledger_transaction_id": record.ledger_transaction_id,
    }
