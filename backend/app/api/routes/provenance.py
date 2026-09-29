from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import DecryptionSession, Document, ProvenanceRecord, User
from app.services.key_store import key_store
from app.services.provenance import provenance_service

router = APIRouter(prefix="/provenance", tags=["Provenance"])


@router.post("/create/{session_id}")
def create_provenance(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The record is signed during decryption; this returns it (kept for older clients)."""
    session = db.get(DecryptionSession, session_id)
    if not session or session.recipient_id != current_user.id:
        raise HTTPException(status_code=404, detail="Session not found.")
    record = db.query(ProvenanceRecord).filter_by(session_id=session.id).first()
    if not record:
        record = provenance_service.sign_session(db, session, db.get(Document, session.document_id))
        db.commit()
    return {
        "watermark_id": record.watermark_id,
        "record_hash": record.record_hash,
        "signature": record.signature,
        "signature_algorithm": record.signature_algorithm,
        "ledger_transaction_id": record.ledger_transaction_id,
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
