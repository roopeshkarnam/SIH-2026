from __future__ import annotations

import hashlib
import json


class LedgerService:
    """
    Development adapter.
    Production deployment must replace this adapter with Hyperledger Fabric
    multi-organization endorsement/commitment.
    """

    def commit_provenance(self, record: dict) -> str:
        canonical = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        return f"DEV-{digest[:32]}"

    def get_record(self, transaction_id: str) -> dict:
        return {
            "transaction_id": transaction_id,
            "status": "development-adapter",
        }


ledger_service = LedgerService()
