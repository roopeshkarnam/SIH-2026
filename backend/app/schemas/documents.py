from datetime import datetime

from pydantic import BaseModel


class DocumentResponse(BaseModel):
    id: str
    filename: str
    mime_type: str
    file_size: int
    sha256: str
    encrypted: bool
    created_at: datetime