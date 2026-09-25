from datetime import datetime

from pydantic import BaseModel


class ProvenanceResponse(BaseModel):

    id: str
    session_id: str
    document_hash: str
    recipient_id: str
    watermark_id: str
    signature_algorithm: str
    signature: str | None
    record_hash: str
    ledger_transaction_id: str | None
    created_at: datetime