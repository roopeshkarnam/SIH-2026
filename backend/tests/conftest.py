import base64
import os
import tempfile
from pathlib import Path

import pytest

# Tests must never touch the shared database, real key store or real storage.
# These are set before any app module is imported, so they override .env.
TEST_ROOT = Path(tempfile.mkdtemp(prefix="sih-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_ROOT / 'test.db'}"
os.environ["STORAGE_ROOT"] = str(TEST_ROOT / "storage")
os.environ["KEY_STORAGE_PATH"] = str(TEST_ROOT / "keys")
os.environ["KEYSTORE_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["JWT_SECRET"] = "test-only-secret"

REPO_ROOT = Path(__file__).resolve().parents[2]


def alembic_config():
    from alembic.config import Config

    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
    return config


@pytest.fixture(scope="session")
def migrated_db():
    """Fresh database built by `alembic upgrade head` (not create_all)."""
    from alembic import command

    command.upgrade(alembic_config(), "head")
    return os.environ["DATABASE_URL"]
