"""Backend entry point for the MUDRA desktop app.

Runs fully offline: a local SQLite database, storage and key store inside
--data-dir, migrated with Alembic on every start. It never reads a developer
.env: JWT_SECRET and KEYSTORE_MASTER_KEY must be passed in by the desktop app.

From source (for development):
    PYTHONPATH=backend JWT_SECRET=... KEYSTORE_MASTER_KEY=... \
        .venv/bin/python backend/desktop_server.py --data-dir /tmp/mudra --ui-dir frontend/dist
"""

import argparse
import os
import sys
from pathlib import Path

# In the PyInstaller bundle, data files (migrations, UI) are unpacked here.
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--ui-dir", default=str(BUNDLE_DIR / "ui"))
    args = parser.parse_args()

    for name in ("JWT_SECRET", "KEYSTORE_MASTER_KEY"):
        if not os.environ.get(name):
            sys.exit(f"{name} must be provided by the desktop app.")

    data_dir = Path(args.data_dir).resolve()
    ui_dir = Path(args.ui_dir).resolve()
    (data_dir / "storage").mkdir(parents=True, exist_ok=True)
    (data_dir / "keys").mkdir(parents=True, exist_ok=True)
    # Settings also reads ".env" from the working directory; run from the data dir
    # so a developer .env (e.g. the shared database) can never be picked up.
    os.chdir(data_dir)
    os.environ["DATABASE_URL"] = f"sqlite:///{data_dir / 'mudra.db'}"
    os.environ["STORAGE_ROOT"] = str(data_dir / "storage")
    os.environ["KEY_STORAGE_PATH"] = str(data_dir / "keys")
    os.environ["FRONTEND_DIST"] = str(ui_dir)

    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(BUNDLE_DIR / "alembic"))
    command.upgrade(config, "head")

    import uvicorn

    from app.main import app

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
