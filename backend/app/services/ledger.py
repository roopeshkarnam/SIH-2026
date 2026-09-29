"""Tamper-evident ledger: an append-only, hash-chained log signed with ML-DSA-65.

Every entry stores the hash of the previous entry, so changing or deleting any past entry
breaks every link after it. Each entry hash is also signed with this node's ML-DSA-65 key, so
entries cannot be forged by someone who only has database access. `verify` recomputes the
whole chain and reports the first broken entry.

This is the single integration point for a multi-organisation ledger (Hyperledger Fabric):
another backend can implement `append` / `verify` without changing the rest of the app.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from app.db.models import LedgerEntry
from app.services.hashing import hashing_service
from app.services.key_store import key_store
from app.services.pqc import pqc_service

GENESIS = "0" * 64
NODE_KEY = "ledger-node_sig"


def _node_private_key() -> bytes:
    try:
        return key_store.load_private_key(NODE_KEY)
    except FileNotFoundError:
        pair = pqc_service.generate_signature_keypair()
        key_store.save_private_key(NODE_KEY, base64.b64decode(pair["private_key"]), pair["algorithm"],
                                   public_key=base64.b64decode(pair["public_key"]))
        return base64.b64decode(pair["private_key"])


def _entry_hash(sequence: int, previous: str, body: str) -> str:
    return hashing_service.sha256_bytes(f"{sequence}|{previous}|{body}".encode())


class LedgerService:
    def append(self, db, kind: str, data: dict) -> LedgerEntry:
        """Add an entry (not committed: it commits with the caller's transaction)."""
        last = db.query(LedgerEntry).order_by(LedgerEntry.sequence.desc()).first()
        sequence = (last.sequence + 1) if last else 1
        previous = last.entry_hash if last else GENESIS
        body = json.dumps({"kind": kind, "at": datetime.now(timezone.utc).isoformat(), "data": data},
                          sort_keys=True, separators=(",", ":"))
        entry_hash = _entry_hash(sequence, previous, body)
        signature = base64.b64encode(pqc_service.sign(_node_private_key(), entry_hash.encode())).decode()
        entry = LedgerEntry(sequence=sequence, kind=kind, body=body, previous_hash=previous,
                            entry_hash=entry_hash, signature=signature)
        db.add(entry)
        db.flush()
        return entry

    def commit_provenance(self, db, record: dict) -> str:
        entry = self.append(db, "decryption-record", record)
        return f"L{entry.sequence}-{entry.entry_hash[:16]}"

    def verify(self, db) -> dict:
        """Recompute the chain; report the first entry that was changed, removed or forged."""
        entries = db.query(LedgerEntry).order_by(LedgerEntry.sequence).all()
        if not entries:
            return {"intact": True, "entries": 0, "broken_at": None, "reason": None}
        public_key = key_store.load_public_key(NODE_KEY)
        previous = GENESIS
        for expected, entry in enumerate(entries, start=1):
            problem = None
            if entry.sequence != expected:
                problem = "an entry is missing"
            elif entry.previous_hash != previous:
                problem = "chain link broken"
            elif _entry_hash(entry.sequence, entry.previous_hash, entry.body) != entry.entry_hash:
                problem = "entry content was changed"
            elif not pqc_service.verify(public_key, entry.entry_hash.encode(), base64.b64decode(entry.signature)):
                problem = "signature invalid"
            if problem:
                return {"intact": False, "entries": len(entries), "broken_at": expected, "reason": problem}
            previous = entry.entry_hash
        return {"intact": True, "entries": len(entries), "broken_at": None, "reason": None,
                "head": previous}


ledger_service = LedgerService()
