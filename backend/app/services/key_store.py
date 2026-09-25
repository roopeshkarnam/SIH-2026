from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


class KeyStore:
    """Local AES-256-GCM encrypted private-key store."""

    def __init__(self):
        self.root = Path(settings.key_storage_path)
        self.root.mkdir(parents=True, exist_ok=True)

    def _file_path(self, key_id: str) -> Path:
        return self.root / f"{key_id}.json"

    def _get_master_key(self) -> bytes:
        try:
            key = base64.b64decode(settings.keystore_master_key)
        except Exception as exc:
            raise RuntimeError("KEYSTORE_MASTER_KEY must be valid Base64.") from exc
        if len(key) != 32:
            raise RuntimeError("KEYSTORE_MASTER_KEY must decode to exactly 32 bytes.")
        return key

    def save_private_key(
        self,
        key_id: str,
        private_key: bytes,
        algorithm: str,
        public_key: bytes | None = None,
    ) -> None:
        master_key = self._get_master_key()
        nonce = os.urandom(12)
        encrypted_key = AESGCM(master_key).encrypt(
            nonce, private_key, key_id.encode()
        )
        data = {
            "key_id": key_id,
            "algorithm": algorithm,
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_private_key": base64.b64encode(encrypted_key).decode(),
            "public_key": (
                base64.b64encode(public_key).decode()
                if public_key is not None
                else None
            ),
        }
        self._file_path(key_id).write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )

    def load_private_key(self, key_id: str) -> bytes:
        path = self._file_path(key_id)
        if not path.exists():
            raise FileNotFoundError(f"Private key '{key_id}' was not found.")
        data = json.loads(path.read_text(encoding="utf-8"))
        return AESGCM(self._get_master_key()).decrypt(
            base64.b64decode(data["nonce"]),
            base64.b64decode(data["encrypted_private_key"]),
            key_id.encode(),
        )

    def load_public_key(self, key_id: str) -> bytes:
        path = self._file_path(key_id)
        if not path.exists():
            raise FileNotFoundError(f"Key '{key_id}' was not found.")
        data = json.loads(path.read_text(encoding="utf-8"))
        public_key = data.get("public_key")
        if not public_key:
            raise KeyError(f"No public key stored for '{key_id}'.")
        return base64.b64decode(public_key)


key_store = KeyStore()
