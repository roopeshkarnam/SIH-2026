from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import AccessEvent, DecryptionSession, Document, ProvenanceRecord, User
from app.services.key_store import key_store
from app.services.ledger import ledger_service
from app.services.provenance import provenance_service
from app.services.watermark import watermark_service

router = APIRouter(prefix="/forensics", tags=["Forensics"])


def _attribution(db: Session, session: DecryptionSession) -> dict:
    """Who opened it, when, what they did with it, and the signed record."""
    document = db.get(Document, session.document_id)
    recipient = db.get(User, session.recipient_id)
    record = db.query(ProvenanceRecord).filter_by(session_id=session.id).first()
    verified = None
    if record:
        try:
            verified = provenance_service.verify_record(
                {"record_hash": record.record_hash, "signature": record.signature},
                key_store.load_public_key(f"{record.recipient_id}_sig"),
            )
        except (FileNotFoundError, KeyError):
            verified = False
    events = (
        db.query(AccessEvent).filter_by(session_id=session.id).order_by(AccessEvent.created_at).all()
    )
    return {
        "watermark_id": session.watermark_id,
        "session_id": session.id,
        "document_id": session.document_id,
        "filename": document.filename if document else None,
        "recipient_id": session.recipient_id,
        "recipient": recipient.username if recipient else None,
        "signed_record": record is not None,
        "signature_verified": verified,
        "ledger_transaction_id": record.ledger_transaction_id if record else None,
        "activity": [{"event": e.event, "at": e.created_at} for e in events],
    }


def _resolve(db: Session, layers: list[dict]) -> dict:
    """Match the recovered trace codes to a decryption session."""
    matches = {}
    for layer in layers:
        if not layer["found"]:
            continue
        sessions = (
            db.query(DecryptionSession)
            .filter(DecryptionSession.watermark_id.like(f"WM-{layer['code']}%"))
            .limit(2)
            .all()
        )
        layer["matched"] = len(sessions) == 1   # a 32-bit prefix could, rarely, be ambiguous
        if layer["matched"]:
            matches.setdefault(sessions[0].id, (sessions[0], []))[1].append(layer["layer"])
    result = {"layers": layers, "matched": False}
    if matches:
        # The session supported by the most layers.
        session, supporting = max(matches.values(), key=lambda item: len(item[1]))
        result.update(_attribution(db, session), matched=True, supporting_layers=sorted(supporting),
                      conflicting_sessions=len(matches) - 1)
    return result


@router.get("/ledger/verify")
def verify_ledger(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return ledger_service.verify(db)


@router.get("/lookup/{watermark_id}")
def lookup_watermark(
    watermark_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.query(DecryptionSession).filter_by(watermark_id=watermark_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Watermark not found.")
    return {**_attribution(db, session), "matched": True, "layers": []}


@router.post("/extract")
async def extract_from_leak(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        layers = watermark_service.trace(await file.read())
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not read this file.") from exc
    return _resolve(db, layers)


@router.post("/text")
def extract_from_text(
    text: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _resolve(db, watermark_service.trace(text.encode("utf-8")))
