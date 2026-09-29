"""End-to-end multi-recipient flow through the real API on a fresh Alembic-migrated SQLite DB."""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pymupdf
import pytest
from fastapi.testclient import TestClient

from tests.conftest import REPO_ROOT, TEST_ROOT


@pytest.fixture(scope="module")
def client(migrated_db):
    from app.main import app

    return TestClient(app)


def make_user(client, username, with_keys=True):
    client.post("/auth/register", json={"username": username, "password": "password123"})
    login = client.post("/auth/login", data={"username": username, "password": "password123"}).json()
    user = {"id": login["user_id"], "username": username, "headers": {"Authorization": f"Bearer {login['access_token']}"}}
    if with_keys:
        assert client.post(f"/users/{user['id']}/pqc-keys", headers=user["headers"]).status_code == 200
    return user


@pytest.fixture(scope="module")
def users(client):
    return {
        "alice": make_user(client, "alice"),
        "bob": make_user(client, "bob"),
        "carol": make_user(client, "carol"),
        "dave": make_user(client, "dave", with_keys=False),
    }


def make_pdf() -> bytes:
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "SIH 2026 confidential circular")
    return doc.tobytes()


def upload(client, sender, recipient_ids, content=None):
    return client.post(
        "/documents/upload",
        headers=sender["headers"],
        data={"recipient_ids": recipient_ids},
        files={"file": ("circular.pdf", content or make_pdf(), "application/pdf")},
    )


def stored_state():
    db = sqlite3.connect(os.environ["DATABASE_URL"].removeprefix("sqlite:///"))
    counts = (
        db.execute("select count(*) from documents").fetchone()[0],
        db.execute("select count(*) from document_recipients").fetchone()[0],
    )
    db.close()
    files = sorted((TEST_ROOT / "storage" / "documents").glob("*"))
    return counts, files


def test_database_was_built_by_alembic(migrated_db):
    db = sqlite3.connect(migrated_db.removeprefix("sqlite:///"))
    assert db.execute("select version_num from alembic_version").fetchone()[0] == "7c1f4b9e0d52"
    columns = [row[1] for row in db.execute("pragma table_info(decryption_sessions)")]
    assert "session_nonce" in columns


def test_recipient_listing_exposes_only_id_and_username(client, users):
    listed = client.get("/users/recipients", headers=users["alice"]["headers"]).json()
    names = {u["username"] for u in listed}
    assert {"alice", "bob", "carol"} <= names and "dave" not in names
    assert all(set(u) == {"id", "username"} for u in listed)


def test_upload_with_invalid_recipient_stores_nothing(client, users):
    before = stored_state()
    bad = upload(client, users["alice"], [users["bob"]["id"], users["dave"]["id"], "no-such-user"])
    assert bad.status_code == 409
    assert users["dave"]["id"] in bad.json()["detail"] and "no-such-user" in bad.json()["detail"]
    assert users["bob"]["id"] not in bad.json()["detail"]
    assert stored_state() == before


def test_full_multi_recipient_flow(client, users):
    alice, bob, carol, dave = (users[n] for n in ("alice", "bob", "carol", "dave"))
    ids = [alice["id"], bob["id"], carol["id"], bob["id"]]  # duplicate on purpose

    response = upload(client, alice, ids)
    assert response.status_code == 200, response.text
    result = response.json()
    document_id = result["document_id"]
    assert result["recipients"] == [alice["id"], bob["id"], carol["id"]]
    assert result["envelopes_created"] == 3 and result["format_version"] == 2

    # One ciphertext on disk, no per-recipient key material in it.
    package = json.loads((TEST_ROOT / "storage" / "documents" / f"{document_id}.json").read_text())
    assert "kem_ciphertext" not in package and package["document_id"] == document_id

    # Sent vs inbox.
    assert document_id in [d["document_id"] for d in client.get("/documents/mine", headers=alice["headers"]).json()]
    for user in (alice, bob, carol):
        inbox = client.get("/documents/inbox", headers=user["headers"]).json()
        assert document_id in [d["document_id"] for d in inbox]
    assert document_id not in [d["document_id"] for d in client.get("/documents/inbox", headers=dave["headers"]).json()]

    # Non-recipient: indistinguishable from a missing document.
    denied = client.post(f"/decryption/{document_id}/{dave['id']}", headers=dave["headers"])
    missing = client.post(f"/decryption/{'0' * 32}/{dave['id']}", headers=dave["headers"])
    assert denied.status_code == missing.status_code == 404
    assert denied.json() == missing.json()

    watermarks = {}
    for user in (alice, bob, carol):
        opened = client.post(f"/decryption/{document_id}/{user['id']}", headers=user["headers"])
        assert opened.status_code == 200, opened.text
        session = opened.json()

        # The watermarked preview is ready right away; opening it and downloading are logged.
        assert session["preview"] == "pdf" and session["pages"] == 1
        page = client.get(f"/decryption/{session['session_id']}/page/0", headers=user["headers"])
        assert page.status_code == 200 and page.headers["content-type"] == "image/png"
        copy = client.get(f"/decryption/file/{session['session_id']}", headers=user["headers"])
        assert copy.status_code == 200
        # Another user cannot fetch this recipient's preview.
        assert client.get(f"/decryption/{session['session_id']}/page/0", headers=dave["headers"]).status_code == 404
        watermarks[user["username"]] = session["watermark_id"]

        # Signed as part of opening; the old endpoint just returns the same record.
        assert session["signature_algorithm"] == "ML-DSA-65"
        signed = client.post(f"/provenance/create/{session['session_id']}", headers=user["headers"])
        assert signed.status_code == 200 and signed.json()["record_hash"] == session["record_hash"]
        record = client.get(f"/provenance/{session['watermark_id']}", headers=user["headers"]).json()
        assert record["signature_verified"] is True and record["recipient_id"] == user["id"]

        # Investigator traces the leaked copy back to this recipient.
        trace = client.post(
            "/forensics/extract",
            headers=alice["headers"],
            files={"file": ("leak.pdf", copy.content, "application/pdf")},
        ).json()
        assert trace["watermark_id"] == session["watermark_id"]
        assert trace["recipient_id"] == user["id"]
        assert 3 in trace["supporting_layers"] and trace["signature_verified"] is True
        assert [a["event"] for a in trace["activity"]] == ["decrypted", "previewed", "downloaded"]

    assert len(set(watermarks.values())) == 3
    activity = client.get(f"/documents/{document_id}/activity", headers=alice["headers"]).json()
    assert sorted({(a["recipient"], a["event"]) for a in activity}) == sorted(
        (name, event) for name in ("alice", "bob", "carol") for event in ("decrypted", "previewed", "downloaded"))
    assert client.get(f"/documents/{document_id}/activity", headers=bob["headers"]).status_code == 404


def test_legacy_single_recipient_document_still_decrypts(client, users):
    from app.db.database import SessionLocal
    from app.db.models import Document
    from app.services.document_crypto import document_crypto_service

    bob, carol = users["bob"], users["carol"]
    plaintext = make_pdf()
    package = document_crypto_service.encrypt_for_recipient(plaintext, bob["id"], "legacy-doc")
    path = TEST_ROOT / "storage" / "documents" / "legacy-doc.json"
    path.write_text(json.dumps(package))
    with SessionLocal() as db:
        db.add(Document(
            id="legacy-doc", owner_id=bob["id"], filename="old.pdf",
            document_hash=package["document_hash"], storage_path=str(path), encrypted=True,
        ))
        db.commit()

    assert "legacy-doc" in [d["document_id"] for d in client.get("/documents/inbox", headers=bob["headers"]).json()]
    assert client.post(f"/decryption/legacy-doc/{bob['id']}", headers=bob["headers"]).status_code == 200
    assert client.post(f"/decryption/legacy-doc/{carol['id']}", headers=carol["headers"]).status_code == 404


def test_session_nonce_migration_is_idempotent_on_existing_column(tmp_path):
    """Simulates the shared DB: schema at the initial revision, but session_nonce already added by hand."""
    db_path = tmp_path / "shared-like.db"
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{db_path}", PYTHONPATH=str(REPO_ROOT / "backend"))

    def alembic(*args):
        subprocess.run([sys.executable, "-m", "alembic", *args], cwd=REPO_ROOT, env=env, check=True, capture_output=True)

    alembic("upgrade", "bc7be07d1985")
    db = sqlite3.connect(db_path)
    db.execute("alter table decryption_sessions add column session_nonce varchar not null default ''")
    db.commit()
    alembic("upgrade", "head")
    columns = [row[1] for row in db.execute("pragma table_info(decryption_sessions)")]
    assert columns.count("session_nonce") == 1
    assert db.execute("select version_num from alembic_version").fetchone()[0] == "7c1f4b9e0d52"
    db.close()


def test_ledger_is_tamper_evident(client, users):
    alice = users["alice"]
    verified = client.get("/forensics/ledger/verify", headers=alice["headers"]).json()
    assert verified["intact"] is True and verified["entries"] > 0
    kinds = {row[0] for row in sqlite3.connect(os.environ["DATABASE_URL"].removeprefix("sqlite:///")).execute("select kind from ledger_entries")}
    assert {"distributed", "decryption-record", "decrypted", "previewed", "downloaded"} <= kinds

    db = sqlite3.connect(os.environ["DATABASE_URL"].removeprefix("sqlite:///"))
    original = db.execute("select body from ledger_entries where sequence = 2").fetchone()[0]
    db.execute("update ledger_entries set body = replace(body, 'recipient', 'RECIPIENT') where sequence = 2")
    db.commit()
    tampered = client.get("/forensics/ledger/verify", headers=alice["headers"]).json()
    assert tampered == {**tampered, "intact": False, "broken_at": 2, "reason": "entry content was changed"}

    db.execute("update ledger_entries set body = ? where sequence = 2", (original,))
    db.execute("delete from ledger_entries where sequence = 3")
    db.commit()
    removed = client.get("/forensics/ledger/verify", headers=alice["headers"]).json()
    assert removed["intact"] is False and removed["broken_at"] == 3
    db.close()
