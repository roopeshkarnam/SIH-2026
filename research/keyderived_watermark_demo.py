"""
Standalone demo: watermark IDs derived from each recipient's key + the document.
Does not touch the app or the database. Run from the project root:

    PYTHONPATH=backend .venv/bin/python research/keyderived_watermark_demo.py
"""
import base64
import hashlib
import hmac
import os
from datetime import datetime, timezone

import pymupdf

from app.services.pqc import pqc_service
from app.services.watermark import watermark_service


def make_pdf(text: str) -> bytes:
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), text, fontsize=14)
    return doc.tobytes()


def hmac_watermark(shared_secret: bytes, doc_hash: str, session_id: str) -> str:
    """Option A: one-way hash of the recipient's decryption secret + document + session."""
    tag = hmac.new(shared_secret, f"WM|{doc_hash}|{session_id}".encode(), hashlib.sha256).digest()
    return "WM-" + tag[:16].hex().upper()


def signed_receipt(sig_private: bytes, doc_hash: str, session_id: str) -> dict:
    """Option B: recipient signs an access receipt; the watermark is a hash of that signature."""
    message = f"{doc_hash}|{session_id}|{os.urandom(16).hex()}|{datetime.now(timezone.utc).isoformat()}".encode()
    signature = pqc_service.sign(sig_private, message)
    return {"message": message, "signature": signature,
            "watermark_id": "WM-" + hashlib.sha256(signature).digest()[:16].hex().upper()}


print("=" * 72)
print("Key-derived watermark demo")
print("=" * 72)

original = make_pdf("CONFIDENTIAL: Operation plan, page 1")
doc_hash = hashlib.sha256(original).hexdigest()
print(f"Original document SHA-256: {doc_hash[:16]}…\n")

# Each recipient has their own ML-KEM (decryption) and ML-DSA (signing) key pairs.
recipients = {}
for name in ("Alice", "Bob"):
    kem = pqc_service.generate_kem_keypair()
    sig = pqc_service.generate_signature_keypair()
    recipients[name] = {
        "kem_pk": base64.b64decode(kem["public_key"]), "kem_sk": base64.b64decode(kem["private_key"]),
        "sig_pk": base64.b64decode(sig["public_key"]), "sig_sk": base64.b64decode(sig["private_key"]),
    }

ledger = {}   # watermark_id -> record (stands in for the signed provenance table)
copies = {}

print("--- Each recipient opens the SAME document (Alice opens it twice) ---")
for name, session_no in (("Alice", 1), ("Alice", 2), ("Bob", 1)):
    r = recipients[name]
    session_id = f"{name.lower()}-session-{session_no}"
    # Sender side: ML-KEM encapsulation. Recipient side: decapsulation gives the same secret.
    enc = pqc_service.encapsulate(r["kem_pk"])
    shared_secret = pqc_service.decapsulate(r["kem_sk"], enc["ciphertext"])

    wm_a = hmac_watermark(shared_secret, doc_hash, session_id)
    receipt = signed_receipt(r["sig_sk"], doc_hash, session_id)
    wm_b = receipt["watermark_id"]

    copy = watermark_service.embed_pdf(original, wm_b)
    copies[(name, session_no)] = copy
    ledger[wm_b] = {"recipient": name, "session_id": session_id, "doc_hash": doc_hash, **receipt}
    print(f"{name:5} session {session_no}:  A (HMAC of key)      = {wm_a}")
    print(f"{'':5}             B (hash of signature) = {wm_b}")

print("\nEvery watermark is different: per user AND per opening.\n")

print("--- Is the secret key visible inside the leaked file? ---")
leak = copies[("Alice", 2)]
r = recipients["Alice"]
print("ML-KEM private key bytes inside PDF:", r["kem_sk"] in leak)
print("ML-DSA private key bytes inside PDF:", r["sig_sk"] in leak)

print("\n--- Investigator traces Alice's 2nd copy ---")
found = watermark_service.extract_pdf(leak)
record = ledger.get(found)
print("Extracted watermark:", found)
print("Matches recipient:  ", record["recipient"], "/", record["session_id"])
sig_ok = pqc_service.verify(recipients[record["recipient"]]["sig_pk"], record["message"], record["signature"])
print("Receipt signature verified with Alice's PUBLIC key:", sig_ok)
print("Receipt is bound to this document:", record["doc_hash"] == doc_hash)
print("Watermark = hash(signature):", "WM-" + hashlib.sha256(record["signature"]).digest()[:16].hex().upper() == found)

print("\n--- Framing attempt: paste Alice's watermark onto a FAKE document ---")
fake_original = make_pdf("FAKE leak blaming Alice")
fake = watermark_service.embed_pdf(fake_original, found)
fake_hash = hashlib.sha256(fake_original).hexdigest()
rec = ledger[watermark_service.extract_pdf(fake)]
print("Watermark found and matches Alice:", rec["recipient"] == "Alice")
print("But document binding check passes:", rec["doc_hash"] == fake_hash, " -> fake detected")

print("\n--- Forgery attempt: Bob tries to sign a receipt as Alice ---")
bob_forgery = pqc_service.sign(recipients["Bob"]["sig_sk"], record["message"])
print("Bob's signature accepted as Alice's:", pqc_service.verify(recipients["Alice"]["sig_pk"], record["message"], bob_forgery))
