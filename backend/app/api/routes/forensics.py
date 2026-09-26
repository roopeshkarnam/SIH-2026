from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import ProvenanceRecord, User
from app.services.watermark import watermark_service

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


@router.post("/extract")
async def extract_from_leaked_pdf(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        watermark_id = watermark_service.extract_pdf(await file.read())
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not read this file as a PDF.") from exc
    if not watermark_id:
        raise HTTPException(status_code=404, detail="No watermark found in this PDF.")
    return lookup_watermark(watermark_id, db, current_user)
