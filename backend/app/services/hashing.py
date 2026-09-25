import hashlib
import json
from pathlib import Path


class HashingService:
    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_file(path: str) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as file:
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def canonical_json_hash(data: dict) -> str:
        canonical = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(canonical).hexdigest()


hashing_service = HashingService()
