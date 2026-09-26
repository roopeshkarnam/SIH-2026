from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.db.models import Document, User
from app.services.document_crypto import document_crypto_service
from app.services.hashing import hashing_service

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


@router.post("/upload")
async def upload_document(
    recipient_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin" and current_user.id != recipient_id:
        raise HTTPException(status_code=403, detail="Not authorized.")

    recipient = db.get(User, recipient_id)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found.")

    data = await file.read()
    if len(data) > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large.")

    document_id = uuid4().hex
    try:
        encrypted_package = document_crypto_service.encrypt_for_recipient(data, recipient_id, document_id)
    except (FileNotFoundError, KeyError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    root = Path(settings.storage_root) / "documents"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{document_id}.json"
    path.write_text(json.dumps(encrypted_package), encoding="utf-8")

    document = Document(
        id=document_id,
        owner_id=current_user.id,
        filename=file.filename or "document.bin",
        document_hash=hashing_service.sha256_bytes(data),
        storage_path=str(path),
        encrypted=True,
    )
    db.add(document)
    db.commit()

    return {
        "document_id": document_id,
        "filename": document.filename,
        "document_hash": document.document_hash,
        "encrypted": True,
        "recipient_id": recipient_id,
    }
