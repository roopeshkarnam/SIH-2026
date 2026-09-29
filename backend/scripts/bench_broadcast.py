"""Benchmark multi-recipient upload: time and storage vs number of recipients.

Runs the real /documents/upload endpoint (HTTP + crypto + file write + DB insert)
against a throwaway SQLite database built with `alembic upgrade head`.
Never touches the database or storage configured in .env.

    PYTHONPATH=backend .venv/bin/python backend/scripts/bench_broadcast.py [--runs 5]
"""

import argparse
import base64
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path

ROOT = Path(tempfile.mkdtemp(prefix="sih-bench-"))
os.environ["DATABASE_URL"] = f"sqlite:///{ROOT / 'bench.db'}"
os.environ["STORAGE_ROOT"] = str(ROOT / "storage")
os.environ["KEY_STORAGE_PATH"] = str(ROOT / "keys")
os.environ["KEYSTORE_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["JWT_SECRET"] = "bench-only-secret"

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
RECIPIENT_COUNTS = [1, 10, 50, 100]
FILE_SIZES_MB = [1, 10]


def main(runs: int) -> None:
    config = Config(str(REPO / "alembic.ini"))
    config.set_main_option("script_location", str(REPO / "backend" / "alembic"))
    command.upgrade(config, "head")

    from app.db.database import SessionLocal
    from app.db.models import DocumentRecipient, User
    from app.main import app
    from app.services.document_crypto import document_crypto_service
    from app.services.pqc import pqc_service

    client = TestClient(app)
    client.post("/auth/register", json={"username": "sender", "password": "password123"})
    token = client.post("/auth/login", data={"username": "sender", "password": "password123"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Recipients only need an ML-KEM public key to be encrypted to.
    recipient_ids = [f"bench-recipient-{i:03d}" for i in range(max(RECIPIENT_COUNTS))]
    with SessionLocal() as db:
        for rid in recipient_ids:
            db.add(User(id=rid, username=rid, password_hash="-", role="recipient", is_active=True,
                        kem_public_key=pqc_service.generate_kem_keypair()["public_key"]))
        db.commit()
        public_keys = {u.id: u.kem_public_key for u in db.query(User).filter(User.id.in_(recipient_ids))}

    print(f"Machine: {platform.platform()}, {platform.machine()}, Python {platform.python_version()}")
    print(f"Median of {runs} runs per cell.\n")
    print("| File | Recipients | Upload, API end-to-end (ms) | Crypto only (ms) | Package file | Envelopes total | Per envelope | Total stored | Overhead vs plaintext | N separate encrypted copies |")
    print("|---|---|---|---|---|---|---|---|---|---|")

    for size_mb in FILE_SIZES_MB:
        plaintext = os.urandom(size_mb * 1024 * 1024)
        for n in RECIPIENT_COUNTS:
            ids = recipient_ids[:n]
            api_ms, crypto_ms = [], []
            for _ in range(runs):
                start = time.perf_counter()
                response = client.post("/documents/upload", headers=headers, data={"recipient_ids": ids},
                                       files={"file": ("bench.bin", plaintext, "application/octet-stream")})
                api_ms.append((time.perf_counter() - start) * 1000)
                assert response.status_code == 200, response.text
                document_id = response.json()["document_id"]

                start = time.perf_counter()
                document_crypto_service.encrypt_for_recipients(plaintext, "bench", {r: public_keys[r] for r in ids})
                crypto_ms.append((time.perf_counter() - start) * 1000)

            package_bytes = (ROOT / "storage" / "documents" / f"{document_id}.json").stat().st_size
            with SessionLocal() as db:
                rows = db.query(DocumentRecipient).filter_by(document_id=document_id).all()
                envelope_bytes = sum(len(r.kem_ciphertext) + len(r.wrapped_key) + len(r.wrap_nonce) + len(r.kdf_info) for r in rows)
            total = package_bytes + envelope_bytes
            print(
                f"| {size_mb} MB | {n} | {statistics.median(api_ms):.1f} | {statistics.median(crypto_ms):.1f} "
                f"| {package_bytes / 1e6:.2f} MB | {envelope_bytes / 1e3:.1f} KB | {envelope_bytes / n:.0f} B "
                f"| {total / 1e6:.2f} MB | {(total - len(plaintext)) / len(plaintext) * 100:.1f}% "
                f"| {n * package_bytes / 1e6:.1f} MB |"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    main(parser.parse_args().runs)
