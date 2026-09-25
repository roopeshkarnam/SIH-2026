from datetime import datetime

from pydantic import BaseModel


class SessionCreateRequest(BaseModel):
    document_id: str


class SessionResponse(BaseModel):

    id: str
    document_id: str
    recipient_id: str
    status: str
    session_nonce: str
    started_at: datetime
    completed_at: datetime | None