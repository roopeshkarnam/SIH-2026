import base64
import json
from pathlib import Path

from app.services.document_crypto import document_crypto_service
from app.services.key_store import key_store
from app.services.pqc import pqc_service


def test_document_crypto_round_trip(tmp_path):
    recipient = "test-recipient"

    pair = pqc_service.generate_kem_keypair()
    key_store.save_private_key(
        f"{recipient}_kem",
        base64.b64decode(pair["private_key"]),
        pair["algorithm"],
        public_key=base64.b64decode(pair["public_key"]),
    )

    plaintext = b"confidential SIH document"
    package = document_crypto_service.encrypt_for_recipient(
        plaintext,
        recipient,
    )
    recovered = document_crypto_service.decrypt_for_recipient(
        package,
        recipient,
    )

    assert recovered == plaintext

    key_file = Path(key_store.root / f"{recipient}_kem.json")
    if key_file.exists():
        key_file.unlink()
