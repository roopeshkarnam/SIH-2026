from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import ProvenanceRecord, User

router = APIRouter(prefix="/forensics", tags=["Forensics"])


@router.get("/lookup/{watermark_id}")
def lookup_watermark(
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
        raise HTTPException(status_code=404, detail="Watermark not found.")

    return {
        "watermark_id": watermark_id,
        "matched": True,
        "recipient_id": record.recipient_id,
        "session_id": record.session_id,
        "document_id": record.document_id,
        "ledger_transaction_id": record.ledger_transaction_id,
    }
