from __future__ import annotations

import secrets
import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.db.models import AccessEvent, DecryptionSession, Document, DocumentRecipient, User
from app.services.document_crypto import document_crypto_service
from app.services.ledger import ledger_service
from app.services.provenance import provenance_service
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

    # Authorised by recipient-list membership. Non-recipients get the same 404 as a
    # missing document, so they cannot tell whether it exists.
    not_found = HTTPException(status_code=404, detail="Document not found.")
    document = db.get(Document, document_id)
    if not document:
        raise not_found
    row = (
        db.query(DocumentRecipient)
        .filter_by(document_id=document_id, recipient_id=recipient_id)
        .first()
    )
    # Legacy single-recipient documents have no envelope rows and were sealed for the owner.
    is_legacy_owner = document.owner_id == recipient_id and not document.recipients
    if row is None and not is_legacy_owner:
        raise not_found

    package = json.loads(Path(document.storage_path).read_text(encoding="utf-8"))
    envelope = None if row is None else {
        "format_version": row.format_version,
        "kem_ciphertext": row.kem_ciphertext,
        "wrapped_key": row.wrapped_key,
        "wrap_nonce": row.wrap_nonce,
        "kdf_info": row.kdf_info,
    }

    try:
        plaintext = document_crypto_service.decrypt(
            package,
            envelope,
            document_id,
            recipient_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Decryption failed: data was tampered with or does not match.") from exc

    session_id = uuid4().hex
    watermark_id = watermark_service.generate_watermark_id()
    copy = watermark_service.protect(plaintext, document.filename, watermark_id)

    session = DecryptionSession(
        id=session_id,
        document_id=document_id,
        recipient_id=recipient_id,
        session_nonce=secrets.token_hex(32),
        watermark_id=watermark_id,
        status="decrypted",
    )
    db.add(session)
    db.flush()
    # The recipient's key signs the decryption record before any plaintext is released.
    try:
        record = provenance_service.sign_session(db, session, document)
    except FileNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Create your keys before opening documents.") from exc
    _log(db, session, "decrypted")
    db.commit()

    # The recipient's watermarked copy: preview pages/text and the download file.
    folder = _session_dir(session_id)
    folder.mkdir(parents=True, exist_ok=True)
    for number, png in enumerate(copy.pages):
        (folder / f"page-{number}.png").write_bytes(png)
    if copy.text is not None:
        (folder / "preview.txt").write_text(copy.text, encoding="utf-8")
    (folder / "download").write_bytes(copy.download)
    (folder / "download-name").write_text(copy.download_name, encoding="utf-8")

    return {
        "session_id": session_id,
        "document_id": document_id,
        "recipient_id": recipient_id,
        "watermark_id": watermark_id,
        "document_hash": document.document_hash,
        "filename": document.filename,
        "preview": copy.kind,
        "pages": len(copy.pages),
        "record_hash": record.record_hash,
        "signature_algorithm": record.signature_algorithm,
        "ledger_transaction_id": record.ledger_transaction_id,
    }


def _session_dir(session_id: str) -> Path:
    return Path(settings.storage_root) / "decrypted" / session_id


def _log(db: Session, session: DecryptionSession, event: str) -> None:
    db.add(AccessEvent(id=uuid4().hex, session_id=session.id, document_id=session.document_id,
                       recipient_id=session.recipient_id, event=event))
    ledger_service.append(db, event, {"session_id": session.id, "document_id": session.document_id,
                                      "recipient_id": session.recipient_id, "watermark_id": session.watermark_id})


def _own_session(db: Session, session_id: str, user: User) -> DecryptionSession:
    session = db.get(DecryptionSession, session_id)
    if not session or session.recipient_id != user.id or not _session_dir(session_id).exists():
        raise HTTPException(status_code=404, detail="Session not found.")
    return session


@router.get("/{session_id}/page/{number}")
def preview_page(
    session_id: str,
    number: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _own_session(db, session_id, current_user)
    path = _session_dir(session_id) / f"page-{number}.png"
    if number < 0 or not path.exists():
        raise HTTPException(status_code=404, detail="Page not found.")
    if number == 0:                        # opening the preview
        _log(db, session, "previewed")
        db.commit()
    return FileResponse(path, media_type="image/png")


@router.get("/{session_id}/text")
def preview_text(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _own_session(db, session_id, current_user)
    path = _session_dir(session_id) / "preview.txt"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No text preview for this file.")
    _log(db, session, "previewed")
    db.commit()
    return {"text": path.read_text(encoding="utf-8")}


@router.get("/file/{session_id}")
def download_watermarked_file(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _own_session(db, session_id, current_user)
    folder = _session_dir(session_id)
    _log(db, session, "downloaded")
    db.commit()
    return FileResponse(folder / "download", filename=(folder / "download-name").read_text(encoding="utf-8"))
