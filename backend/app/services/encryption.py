from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class EncryptedData:
    ciphertext: bytes
    nonce: bytes


class EncryptionService:
    @staticmethod
    def generate_document_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_document(
        plaintext: bytes,
        key: bytes,
        associated_data: bytes | None = None,
    ) -> EncryptedData:
        if len(key) != 32:
            raise ValueError("AES-256 key must contain exactly 32 bytes.")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return EncryptedData(ciphertext=ciphertext, nonce=nonce)

    @staticmethod
    def decrypt_document(
        encrypted_data: EncryptedData,
        key: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        return AESGCM(key).decrypt(
            encrypted_data.nonce,
            encrypted_data.ciphertext,
            associated_data,
        )

    @staticmethod
    def derive_wrapping_key(shared_secret: bytes, context: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context,
        ).derive(shared_secret)

    @staticmethod
    def wrap_document_key(document_key: bytes, wrapping_key: bytes) -> dict:
        nonce = os.urandom(12)
        ciphertext = AESGCM(wrapping_key).encrypt(
            nonce, document_key, b"SIH-DOCUMENT-KEY"
        )
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

    @staticmethod
    def unwrap_document_key(wrapped_data: dict, wrapping_key: bytes) -> bytes:
        return AESGCM(wrapping_key).decrypt(
            base64.b64decode(wrapped_data["nonce"]),
            base64.b64decode(wrapped_data["ciphertext"]),
            b"SIH-DOCUMENT-KEY",
        )


encryption_service = EncryptionService()
