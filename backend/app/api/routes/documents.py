from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.db.models import AccessEvent, Document, DocumentRecipient, User
from app.services.document_crypto import document_crypto_service
from app.services.ledger import ledger_service

router = APIRouter(prefix="/documents", tags=["Documents"])


@router.get("/mine")
def list_my_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    documents = (
        db.query(Document)
        .filter(Document.owner_id == current_user.id)
        .order_by(Document.created_at.desc())
        .all()
    )
    return [
        {
            "document_id": d.id,
            "filename": d.filename,
            "document_hash": d.document_hash,
            "encrypted": d.encrypted,
            "created_at": d.created_at,
        }
        for d in documents
    ]


@router.get("/inbox")
def list_inbox(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    documents = (
        db.query(Document)
        .filter(
            or_(
                Document.recipients.any(DocumentRecipient.recipient_id == current_user.id),
                # Legacy single-recipient documents have no envelope rows; they were sealed for the owner.
                (Document.owner_id == current_user.id) & ~Document.recipients.any(),
            )
        )
        .order_by(Document.created_at.desc())
        .all()
    )
    return [
        {
            "document_id": d.id,
            "filename": d.filename,
            "document_hash": d.document_hash,
            "sender": d.owner.username,
            "created_at": d.created_at,
        }
        for d in documents
    ]


@router.get("/{document_id}/activity")
def document_activity(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """For the sender: who decrypted, previewed and downloaded their document."""
    document = db.get(Document, document_id)
    if not document or document.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Document not found.")
    rows = (
        db.query(AccessEvent, User.username)
        .join(User, User.id == AccessEvent.recipient_id)
        .filter(AccessEvent.document_id == document_id)
        .order_by(AccessEvent.created_at.desc())
        .all()
    )
    return [{"recipient": name, "event": e.event, "at": e.created_at, "session_id": e.session_id} for e, name in rows]


@router.post("/upload")
async def upload_document(
    recipient_ids: list[str] = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    recipient_ids = list(dict.fromkeys(r.strip() for r in recipient_ids if r.strip()))
    if not recipient_ids:
        raise HTTPException(status_code=422, detail="Choose at least one recipient.")
    if len(recipient_ids) > settings.max_recipients_per_document:
        raise HTTPException(
            status_code=422,
            detail=f"At most {settings.max_recipients_per_document} recipients per document.",
        )

    # All-or-nothing: every recipient must exist and have an ML-KEM public key.
    users = {u.id: u for u in db.query(User).filter(User.id.in_(recipient_ids)).all()}
    invalid = [r for r in recipient_ids if r not in users or not users[r].kem_public_key]
    if invalid:
        raise HTTPException(
            status_code=409,
            detail=f"Recipients not found or without ML-KEM keys: {', '.join(invalid)}",
        )

    data = await file.read()
    if len(data) > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large.")

    document_id = uuid4().hex
    package, envelopes = document_crypto_service.encrypt_for_recipients(
        data, document_id, {r: users[r].kem_public_key for r in recipient_ids}
    )

    root = Path(settings.storage_root) / "documents"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{document_id}.json"
    temp_path = path.with_suffix(".tmp")
    try:
        temp_path.write_text(json.dumps(package), encoding="utf-8")
        os.replace(temp_path, path)

        db.add(Document(
            id=document_id,
            owner_id=current_user.id,
            filename=file.filename or "document.bin",
            document_hash=package["document_hash"],
            storage_path=str(path),
            encrypted=True,
        ))
        db.add_all(
            DocumentRecipient(id=uuid4().hex, document_id=document_id, **envelope)
            for envelope in envelopes
        )
        ledger_service.append(db, "distributed", {"document_id": document_id, "sender_id": current_user.id,
                                                  "document_hash": package["document_hash"], "recipients": recipient_ids})
        db.commit()
    except Exception:
        db.rollback()
        temp_path.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        raise

    return {
        "document_id": document_id,
        "filename": file.filename or "document.bin",
        "document_hash": package["document_hash"],
        "encrypted": True,
        "format_version": package["format_version"],
        "recipients": recipient_ids,
        "envelopes_created": len(envelopes),
    }
