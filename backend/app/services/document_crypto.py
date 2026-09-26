from __future__ import annotations

import base64
import json
from pathlib import Path

from app.services.encryption import encryption_service
from app.services.hashing import hashing_service
from app.services.key_store import key_store
from app.services.pqc import pqc_service


class DocumentCryptoService:
    @staticmethod
    def encrypt_for_recipient(plaintext: bytes, recipient_id: str, document_id: str) -> dict:
        document_key = encryption_service.generate_document_key()
        encrypted = encryption_service.encrypt_document(plaintext, document_key)

        key_path = Path(key_store.root / f"{recipient_id}_kem.json")
        if not key_path.exists():
            raise FileNotFoundError(
                f"PQC keys for recipient '{recipient_id}' not found."
            )

        key_data = json.loads(key_path.read_text(encoding="utf-8"))
        if not key_data.get("public_key"):
            raise KeyError(f"Recipient '{recipient_id}' has no ML-KEM public key.")

        public_key = base64.b64decode(key_data["public_key"])
        kem_result = pqc_service.encapsulate(public_key)

        # Domain separation: bind the derived key to this document and recipient.
        kdf_info = f"SIH-2026-DOCUMENT-WRAP|{document_id}|{recipient_id}"
        wrapping_key = encryption_service.derive_wrapping_key(
            kem_result["shared_secret"],
            kdf_info.encode(),
        )
        wrapped_key = encryption_service.wrap_document_key(
            document_key,
            wrapping_key,
        )

        return {
            "algorithm": "AES-256-GCM",
            "kem_algorithm": "ML-KEM-768",
            "document_hash": hashing_service.sha256_bytes(plaintext),
            "nonce": base64.b64encode(encrypted.nonce).decode(),
            "ciphertext": base64.b64encode(encrypted.ciphertext).decode(),
            "kem_ciphertext": base64.b64encode(kem_result["ciphertext"]).decode(),
            "wrapped_key": wrapped_key,
            "kdf_info": kdf_info,
        }

    @staticmethod
    def decrypt_for_recipient(package: dict, recipient_id: str) -> bytes:
        private_key = key_store.load_private_key(f"{recipient_id}_kem")
        kem_ciphertext = base64.b64decode(package["kem_ciphertext"])

        shared_secret = pqc_service.decapsulate(
            private_key,
            kem_ciphertext,
        )
        # Older packages were wrapped with the fixed context string.
        kdf_info = package.get("kdf_info", "SIH-2026-DOCUMENT-WRAP")
        wrapping_key = encryption_service.derive_wrapping_key(
            shared_secret,
            kdf_info.encode(),
        )
        document_key = encryption_service.unwrap_document_key(
            package["wrapped_key"],
            wrapping_key,
        )

        from app.services.encryption import EncryptedData

        encrypted = EncryptedData(
            ciphertext=base64.b64decode(package["ciphertext"]),
            nonce=base64.b64decode(package["nonce"]),
        )

        plaintext = encryption_service.decrypt_document(
            encrypted,
            document_key,
        )

        expected_hash = hashing_service.sha256_bytes(plaintext)
        if expected_hash != package["document_hash"]:
            raise ValueError("Document integrity verification failed.")

        return plaintext


document_crypto_service = DocumentCryptoService()
