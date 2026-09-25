from fastapi import APIRouter

from app.services.pqc import pqc_service

router = APIRouter(prefix="/crypto", tags=["Cryptography"])


@router.get("/status")
def crypto_status():
    return {
        "kem": pqc_service.KEM_ALGORITHM,
        "signature": pqc_service.SIGNATURE_ALGORITHM,
        "status": "available",
    }


@router.post("/test")
def crypto_test():
    kem = pqc_service.generate_kem_keypair()
    kem_result = pqc_service.encapsulate(
        __import__("base64").b64decode(kem["public_key"])
    )
    shared_a = kem_result["shared_secret"]
    shared_b = pqc_service.decapsulate(
        __import__("base64").b64decode(kem["private_key"]),
        kem_result["ciphertext"],
    )

    sig = pqc_service.generate_signature_keypair()
    message = b"SIH-2026-PQC-TEST"
    signature = pqc_service.sign(
        __import__("base64").b64decode(sig["private_key"]),
        message,
    )
    verified = pqc_service.verify(
        __import__("base64").b64decode(sig["public_key"]),
        message,
        signature,
    )

    return {
        "ml_kem_round_trip": shared_a == shared_b,
        "ml_dsa_signature_verified": verified,
    }
