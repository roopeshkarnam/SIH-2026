import base64

import pytest
from cryptography.exceptions import InvalidTag

from app.services.document_crypto import _document_aad, document_crypto_service
from app.services.encryption import encryption_service
from app.services.hashing import hashing_service
from app.services.key_store import key_store
from app.services.pqc import pqc_service

PLAINTEXT = b"confidential SIH broadcast document" * 100


def make_recipient():
    pair = pqc_service.generate_kem_keypair()
    return base64.b64decode(pair["private_key"]), pair["public_key"]


@pytest.fixture
def three():
    return {name: make_recipient() for name in ("alice", "bob", "carol")}


def encrypt(document_id, recipients):
    return document_crypto_service.encrypt_for_recipients(
        PLAINTEXT, document_id, {r: pub for r, (_, pub) in recipients.items()}
    )


def open_as(package, envelope, document_id, recipient_id, private_key):
    return document_crypto_service.open_envelope(
        package, envelope, document_id, recipient_id, private_key
    )


def flip(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def test_each_recipient_decrypts_single_ciphertext(three):
    package, envelopes = encrypt("doc-1", three)

    assert package["format_version"] == 2
    assert len(envelopes) == 3
    assert all("ciphertext" not in e for e in envelopes)
    for envelope in envelopes:
        private_key = three[envelope["recipient_id"]][0]
        assert open_as(package, envelope, "doc-1", envelope["recipient_id"], private_key) == PLAINTEXT


def test_fresh_encapsulation_per_recipient_and_distribution(three):
    _, first = encrypt("doc-1", three)
    _, second = encrypt("doc-2", three)
    kem_ciphertexts = [e["kem_ciphertext"] for e in first + second]
    assert len(set(kem_ciphertexts)) == 6


def test_recipient_cannot_open_another_recipients_envelope(three):
    package, envelopes = encrypt("doc-1", three)
    bob_envelope = next(e for e in envelopes if e["recipient_id"] == "bob")
    alice_key = three["alice"][0]

    # Alice presents Bob's envelope as her own: the recipient binding does not match.
    with pytest.raises(ValueError):
        open_as(package, bob_envelope, "doc-1", "alice", alice_key)
    # Alice claims to be Bob but only has her own private key: ML-KEM gives a wrong secret.
    with pytest.raises(InvalidTag):
        open_as(package, bob_envelope, "doc-1", "bob", alice_key)


@pytest.mark.parametrize("field", ["kem_ciphertext", "wrapped_key", "wrap_nonce"])
def test_tampered_envelope_is_rejected(three, field):
    package, envelopes = encrypt("doc-1", three)
    envelope = dict(envelopes[0], **{field: flip(envelopes[0][field])})
    with pytest.raises(InvalidTag):
        open_as(package, envelope, "doc-1", envelope["recipient_id"], three[envelope["recipient_id"]][0])


@pytest.mark.parametrize("field", ["ciphertext", "nonce"])
def test_tampered_ciphertext_is_rejected(three, field):
    package, envelopes = encrypt("doc-1", three)
    package = dict(package, **{field: flip(package[field])})
    envelope = envelopes[0]
    with pytest.raises(InvalidTag):
        open_as(package, envelope, "doc-1", envelope["recipient_id"], three[envelope["recipient_id"]][0])


def test_envelope_swapped_between_documents_is_rejected(three):
    package_1, envelopes_1 = encrypt("doc-1", three)
    package_2, _ = encrypt("doc-2", three)
    alice_env_1 = next(e for e in envelopes_1 if e["recipient_id"] == "alice")
    alice_key = three["alice"][0]

    # Doc-1 envelope used for doc-2: binding check fails.
    with pytest.raises(ValueError):
        open_as(package_2, alice_env_1, "doc-2", "alice", alice_key)
    # Attacker also rewrites the stored kdf_info: the derived wrapping key is wrong.
    forged = dict(alice_env_1, kdf_info="SIH-2026-DOCUMENT-WRAP|v2|doc-2|alice")
    with pytest.raises(InvalidTag):
        open_as(package_2, forged, "doc-2", "alice", alice_key)


def test_ciphertext_swapped_between_documents_is_rejected(three):
    package_1, _ = encrypt("doc-1", three)
    _, envelopes_2 = encrypt("doc-2", three)
    alice_env_2 = next(e for e in envelopes_2 if e["recipient_id"] == "alice")
    alice_key = three["alice"][0]

    # Doc-1 ciphertext stored under doc-2.
    with pytest.raises(ValueError):
        open_as(package_1, alice_env_2, "doc-2", "alice", alice_key)
    forged = dict(package_1, document_id="doc-2")
    with pytest.raises(InvalidTag):
        open_as(forged, alice_env_2, "doc-2", "alice", alice_key)


def test_document_cloned_under_new_id_is_rejected(three):
    package, envelopes = encrypt("doc-1", three)
    alice_env = next(e for e in envelopes if e["recipient_id"] == "alice")
    forged_package = dict(package, document_id="doc-clone")
    forged_env = dict(alice_env, kdf_info="SIH-2026-DOCUMENT-WRAP|v2|doc-clone|alice")
    with pytest.raises(InvalidTag):
        open_as(forged_package, forged_env, "doc-clone", "alice", three["alice"][0])


def test_ciphertext_is_bound_to_document_id_by_aad():
    key = encryption_service.generate_document_key()
    encrypted = encryption_service.encrypt_document(PLAINTEXT, key, _document_aad("doc-1"))
    assert encryption_service.decrypt_document(encrypted, key, _document_aad("doc-1")) == PLAINTEXT
    with pytest.raises(InvalidTag):
        encryption_service.decrypt_document(encrypted, key, _document_aad("doc-2"))


def test_v2_package_without_envelope_is_rejected(three):
    package, _ = encrypt("doc-1", three)
    with pytest.raises(ValueError):
        document_crypto_service.decrypt(package, None, "doc-1", "alice")


def store_kem_keys(recipient_id):
    pair = pqc_service.generate_kem_keypair()
    key_store.save_private_key(
        f"{recipient_id}_kem",
        base64.b64decode(pair["private_key"]),
        pair["algorithm"],
        public_key=base64.b64decode(pair["public_key"]),
    )
    return base64.b64decode(pair["public_key"])


def test_legacy_package_with_kdf_info_still_decrypts():
    store_kem_keys("legacy-a")
    package = document_crypto_service.encrypt_for_recipient(PLAINTEXT, "legacy-a", "old-doc")
    assert "format_version" not in package and "kdf_info" in package
    assert document_crypto_service.decrypt(package, None, "old-doc", "legacy-a") == PLAINTEXT


def test_legacy_package_without_kdf_info_still_decrypts():
    # Oldest format: fixed HKDF context string, no kdf_info field.
    public_key = store_kem_keys("legacy-b")
    document_key = encryption_service.generate_document_key()
    encrypted = encryption_service.encrypt_document(PLAINTEXT, document_key)
    kem = pqc_service.encapsulate(public_key)
    wrapping_key = encryption_service.derive_wrapping_key(kem["shared_secret"], b"SIH-2026-DOCUMENT-WRAP")
    package = {
        "algorithm": "AES-256-GCM",
        "kem_algorithm": "ML-KEM-768",
        "document_hash": hashing_service.sha256_bytes(PLAINTEXT),
        "nonce": base64.b64encode(encrypted.nonce).decode(),
        "ciphertext": base64.b64encode(encrypted.ciphertext).decode(),
        "kem_ciphertext": base64.b64encode(kem["ciphertext"]).decode(),
        "wrapped_key": encryption_service.wrap_document_key(document_key, wrapping_key),
    }
    assert document_crypto_service.decrypt(package, None, "oldest-doc", "legacy-b") == PLAINTEXT
