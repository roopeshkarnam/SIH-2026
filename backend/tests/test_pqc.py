import base64

from app.services.pqc import pqc_service


def test_ml_kem_round_trip():
    pair = pqc_service.generate_kem_keypair()
    result = pqc_service.encapsulate(base64.b64decode(pair["public_key"]))
    recovered = pqc_service.decapsulate(
        base64.b64decode(pair["private_key"]),
        result["ciphertext"],
    )
    assert recovered == result["shared_secret"]


def test_ml_dsa_signature():
    pair = pqc_service.generate_signature_keypair()
    message = b"SIH-2026"
    signature = pqc_service.sign(
        base64.b64decode(pair["private_key"]),
        message,
    )
    assert pqc_service.verify(
        base64.b64decode(pair["public_key"]),
        message,
        signature,
    )
