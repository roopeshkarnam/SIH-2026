from __future__ import annotations

import base64

from pqcrypto.kem.ml_kem_768 import decaps, encaps, keygen
from pqcrypto.sign.ml_dsa_65 import keygen as sig_keygen
from pqcrypto.sign.ml_dsa_65 import sign as sig_sign
from pqcrypto.sign.ml_dsa_65 import verify as sig_verify


class PQCService:
    KEM_ALGORITHM = "ML-KEM-768"
    SIGNATURE_ALGORITHM = "ML-DSA-65"

    @staticmethod
    def generate_kem_keypair() -> dict:
        public_key, private_key = keygen()
        return {
            "algorithm": PQCService.KEM_ALGORITHM,
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode(),
        }

    @staticmethod
    def encapsulate(public_key: bytes) -> dict:
        ciphertext, shared_secret = encaps(public_key)
        return {"ciphertext": ciphertext, "shared_secret": shared_secret}

    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
        return decaps(private_key, ciphertext)

    @staticmethod
    def generate_signature_keypair() -> dict:
        public_key, private_key = sig_keygen()
        return {
            "algorithm": PQCService.SIGNATURE_ALGORITHM,
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode(),
        }

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        return sig_sign(private_key, message)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            sig_verify(public_key, message, signature)
            return True
        except Exception:
            return False


pqc_service = PQCService()
