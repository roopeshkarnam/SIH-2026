from __future__ import annotations

"""
PQC service for the SIH 2026 application.

This is a backward-compatible enhancement of the existing PQC service.
The application continues to use pqcrypto for:
    - ML-KEM-768 (FIPS 203)
    - ML-DSA-65 (FIPS 204)

Enhancements taken from the teammate's pqc.py:
    - explicit algorithm availability check
    - algorithm/implementation metadata
    - key/signature size reporting
    - standalone end-to-end self-test
    - tamper/signature-failure self-test
    - SHA-256 helper

Existing public methods are intentionally preserved so the rest of the
application does not need to change.
"""

import base64
import hashlib
import os
from typing import Any

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from pqcrypto.kem.ml_kem_768 import decaps, encaps, keygen
from pqcrypto.sign.ml_dsa_65 import keygen as sig_keygen
from pqcrypto.sign.ml_dsa_65 import sign as sig_sign
from pqcrypto.sign.ml_dsa_65 import verify as sig_verify


class PQCService:
    KEM_ALGORITHM = "ML-KEM-768"
    SIGNATURE_ALGORITHM = "ML-DSA-65"

    # ------------------------------------------------------------------
    # Existing application API - DO NOT CHANGE
    # ------------------------------------------------------------------

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
        return {
            "ciphertext": ciphertext,
            "shared_secret": shared_secret,
        }

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
    def verify(
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        try:
            sig_verify(public_key, message, signature)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Enhancements adapted from the supplied pqc.py
    # ------------------------------------------------------------------

    @staticmethod
    def check_algorithms_available() -> dict[str, Any]:
        """
        Confirm that the configured NIST-standardized algorithms can be
        imported and expose their expected API.

        This replaces the teammate file's liboqs mechanism-discovery check
        without adding the liboqs/oqs native dependency.
        """
        checks = {
            "kem_algorithm": PQCService.KEM_ALGORITHM,
            "signature_algorithm": PQCService.SIGNATURE_ALGORITHM,
            "kem_available": callable(keygen)
            and callable(encaps)
            and callable(decaps),
            "signature_available": callable(sig_keygen)
            and callable(sig_sign)
            and callable(sig_verify),
        }

        checks["available"] = (
            checks["kem_available"] and checks["signature_available"]
        )
        return checks

    @staticmethod
    def algorithm_info() -> dict[str, Any]:
        """
        Return useful PQC metadata for diagnostics/security-status UI.

        These values come from the installed pqcrypto modules rather than
        being manually hard-coded.
        """
        return {
            "kem": {
                "name": PQCService.KEM_ALGORITHM,
                "standard": "NIST FIPS 203",
                "public_key_bytes": ml_kem_768.PUBLIC_KEY_SIZE,
                "private_key_bytes": ml_kem_768.SECRET_KEY_SIZE,
                "ciphertext_bytes": ml_kem_768.CIPHERTEXT_SIZE,
                "shared_secret_bytes": ml_kem_768.SHARED_SECRET_SIZE,
            },
            "signature": {
                "name": PQCService.SIGNATURE_ALGORITHM,
                "standard": "NIST FIPS 204",
                "public_key_bytes": ml_dsa_65.PUBLIC_KEY_SIZE,
                "private_key_bytes": ml_dsa_65.SECRET_KEY_SIZE,
                "signature_bytes": ml_dsa_65.SIGNATURE_SIZE,
            },
        }

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        """Return a SHA-256 hexadecimal digest."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def self_test() -> dict[str, Any]:
        """
        Run a local end-to-end PQC sanity test.

        Test flow:
            ML-KEM key generation
            -> encapsulation
            -> decapsulation
            -> shared-secret equality
            -> ML-DSA key generation
            -> signing
            -> signature verification
            -> modified-message rejection

        This is deliberately independent of the database, filesystem,
        FastAPI routes, watermark service, and ledger.
        """
        checks = PQCService.check_algorithms_available()
        if not checks["available"]:
            raise RuntimeError("Required PQC algorithms are unavailable.")

        # ML-KEM round trip.
        kem_keys = keygen()
        kem_public, kem_private = kem_keys

        kem_ciphertext, sender_secret = encaps(kem_public)
        recipient_secret = decaps(kem_private, kem_ciphertext)

        kem_match = sender_secret == recipient_secret
        if not kem_match:
            raise AssertionError("ML-KEM shared secrets do not match.")

        # ML-DSA signing round trip.
        sig_public, sig_private = sig_keygen()
        message = (
            b"SIH-2026-PQC-SELF-TEST|"
            + os.urandom(16)
        )

        signature = sig_sign(sig_private, message)

        signature_valid = True
        try:
            sig_verify(sig_public, message, signature)
        except Exception:
            signature_valid = False

        if not signature_valid:
            raise AssertionError("ML-DSA signature verification failed.")

        # Ensure a modified message is rejected.
        tampered_message = message + b"-tampered"
        tampered_rejected = False
        try:
            sig_verify(sig_public, tampered_message, signature)
        except Exception:
            tampered_rejected = True

        if not tampered_rejected:
            raise AssertionError(
                "ML-DSA verification unexpectedly accepted tampered data."
            )

        return {
            "status": "passed",
            "kem_algorithm": PQCService.KEM_ALGORITHM,
            "signature_algorithm": PQCService.SIGNATURE_ALGORITHM,
            "kem_shared_secret_match": kem_match,
            "signature_valid": signature_valid,
            "tampered_signature_rejected": tampered_rejected,
        }


pqc_service = PQCService()
