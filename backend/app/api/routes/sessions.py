import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models import (
    DecryptionSession,
    Document,
    User,
)
from app.schemas.sessions import (
    SessionCreateRequest,
    SessionResponse,
)
from app.utils.ids import generate_id


router = APIRouter(
    prefix="/sessions",
    tags=["Decryption Sessions"],
)


@router.post(
    "/start",
    response_model=SessionResponse,
)
def start_session(
    request: SessionCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):

    document = db.scalar(
        select(Document).where(
            Document.id == request.document_id
        )
    )

    if not document:

        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    session = DecryptionSession(
        id=generate_id("SES"),
        document_id=document.id,
        recipient_id=user.id,
        status="started",
        session_nonce=secrets.token_hex(32),
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    return session


@router.post(
    "/{session_id}/complete",
    response_model=SessionResponse,
)
def complete_session(
    session_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):

    session = db.scalar(
        select(DecryptionSession).where(
            DecryptionSession.id == session_id,
            DecryptionSession.recipient_id == user.id,
        )
    )

    if not session:

        raise HTTPException(
            status_code=404,
            detail="Decryption session not found",
        )

    session.status = "completed"

    session.completed_at = datetime.now(
        timezone.utc
    )

    db.commit()
    db.refresh(session)

    return session