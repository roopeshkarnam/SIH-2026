from __future__ import annotations

import base64
import json
from pathlib import Path

from app.services.encryption import EncryptedData, encryption_service
from app.services.hashing import hashing_service
from app.services.key_store import key_store
from app.services.pqc import pqc_service

# Format 2: one ciphertext per document, one ML-KEM envelope per recipient.
# Format 1 (no format_version field): one package per single recipient.
FORMAT_VERSION = 2


def _document_aad(document_id: str) -> bytes:
    # Binds the ciphertext to its document ID, so it cannot be moved to another document.
    return f"SIH-2026-DOCUMENT|v{FORMAT_VERSION}|{document_id}".encode()


def _kdf_info(document_id: str, recipient_id: str) -> str:
    return f"SIH-2026-DOCUMENT-WRAP|v{FORMAT_VERSION}|{document_id}|{recipient_id}"


class DocumentCryptoService:
    @staticmethod
    def encrypt_for_recipients(
        plaintext: bytes,
        document_id: str,
        recipient_public_keys: dict[str, str],
    ) -> tuple[dict, list[dict]]:
        """Encrypt once, then seal the document key for each recipient.

        recipient_public_keys maps recipient ID -> Base64 ML-KEM-768 public key.
        Returns the package (ciphertext, stored once) and one envelope per recipient.
        """
        document_key = encryption_service.generate_document_key()
        encrypted = encryption_service.encrypt_document(
            plaintext, document_key, _document_aad(document_id)
        )
        package = {
            "format_version": FORMAT_VERSION,
            "document_id": document_id,
            "algorithm": "AES-256-GCM",
            "kem_algorithm": "ML-KEM-768",
            "document_hash": hashing_service.sha256_bytes(plaintext),
            "nonce": base64.b64encode(encrypted.nonce).decode(),
            "ciphertext": base64.b64encode(encrypted.ciphertext).decode(),
        }

        envelopes = []
        for recipient_id, public_key in recipient_public_keys.items():
            # Fresh encapsulation per recipient per distribution.
            kem_result = pqc_service.encapsulate(base64.b64decode(public_key))
            kdf_info = _kdf_info(document_id, recipient_id)
            wrapping_key = encryption_service.derive_wrapping_key(
                kem_result["shared_secret"], kdf_info.encode()
            )
            wrapped = encryption_service.wrap_document_key(
                document_key, wrapping_key, kdf_info.encode()
            )
            envelopes.append({
                "format_version": FORMAT_VERSION,
                "recipient_id": recipient_id,
                "kem_ciphertext": base64.b64encode(kem_result["ciphertext"]).decode(),
                "wrapped_key": wrapped["ciphertext"],
                "wrap_nonce": wrapped["nonce"],
                "kdf_info": kdf_info,
            })
        return package, envelopes

    @staticmethod
    def open_envelope(
        package: dict,
        envelope: dict,
        document_id: str,
        recipient_id: str,
        private_key: bytes,
    ) -> bytes:
        """Decrypt a format-2 document with one recipient's envelope.

        The bindings are recomputed from the trusted document and recipient IDs,
        never taken from the stored data. Needs only the recipient's private key,
        so it can run on the recipient's device later.
        """
        kdf_info = _kdf_info(document_id, recipient_id)
        if (
            package.get("format_version") != FORMAT_VERSION
            or envelope.get("format_version") != FORMAT_VERSION
        ):
            raise ValueError("Unsupported package format.")
        if package.get("document_id") != document_id or envelope.get("kdf_info") != kdf_info:
            raise ValueError("Envelope does not belong to this document and recipient.")

        shared_secret = pqc_service.decapsulate(
            private_key, base64.b64decode(envelope["kem_ciphertext"])
        )
        wrapping_key = encryption_service.derive_wrapping_key(
            shared_secret, kdf_info.encode()
        )
        document_key = encryption_service.unwrap_document_key(
            {"nonce": envelope["wrap_nonce"], "ciphertext": envelope["wrapped_key"]},
            wrapping_key,
            kdf_info.encode(),
        )
        plaintext = encryption_service.decrypt_document(
            EncryptedData(
                ciphertext=base64.b64decode(package["ciphertext"]),
                nonce=base64.b64decode(package["nonce"]),
            ),
            document_key,
            _document_aad(document_id),
        )
        if hashing_service.sha256_bytes(plaintext) != package["document_hash"]:
            raise ValueError("Document integrity verification failed.")
        return plaintext

    @staticmethod
    def decrypt(
        package: dict,
        envelope: dict | None,
        document_id: str,
        recipient_id: str,
    ) -> bytes:
        """Server-side decryption for either package format."""
        if "format_version" not in package:
            return DocumentCryptoService.decrypt_for_recipient(package, recipient_id)
        if envelope is None:
            raise ValueError("No key envelope for this recipient.")
        private_key = key_store.load_private_key(f"{recipient_id}_kem")
        return DocumentCryptoService.open_envelope(
            package, envelope, document_id, recipient_id, private_key
        )

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
