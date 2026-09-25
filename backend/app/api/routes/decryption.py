from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.db.models import DecryptionSession, Document, User
from app.services.document_crypto import document_crypto_service
from app.services.watermark import watermark_service

router = APIRouter(prefix="/decryption", tags=["Decryption"])


@router.post("/{document_id}/{recipient_id}")
def decrypt_document(
    document_id: str,
    recipient_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.id != recipient_id:
        raise HTTPException(status_code=403, detail="Recipient mismatch.")

    document = db.get(Document, document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found.")

    package = json.loads(Path(document.storage_path).read_text(encoding="utf-8"))

    try:
        plaintext = document_crypto_service.decrypt_for_recipient(
            package,
            recipient_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session_id = uuid4().hex
    watermark_id = watermark_service.generate_watermark_id()

    session = DecryptionSession(
        id=session_id,
        document_id=document_id,
        recipient_id=recipient_id,
        watermark_id=watermark_id,
        status="decrypted",
    )
    db.add(session)
    db.commit()

    output_root = Path(settings.storage_root) / "decrypted"
    output_root.mkdir(parents=True, exist_ok=True)
    output_path = output_root / f"{session_id}_{document.filename}"
    output_path.write_bytes(plaintext)

    return {
        "session_id": session_id,
        "document_id": document_id,
        "recipient_id": recipient_id,
        "watermark_id": watermark_id,
        "output_path": str(output_path),
        "document_hash": document.document_hash,
        "watermark_status": "identifier-generated",
    }
