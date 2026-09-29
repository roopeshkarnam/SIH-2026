# PyInstaller spec for the MUDRA desktop backend (one folder, no Python install needed).
# Built by `npm run dist` in desktop/ (see scripts/build.mjs); needs frontend/dist built first.
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

repo = Path(SPECPATH).parent

datas = [
    (str(repo / "backend" / "alembic"), "alembic"),
    (str(repo / "frontend" / "dist"), "ui"),
]
binaries = []
hiddenimports = [
    # Loaded dynamically at runtime, so PyInstaller cannot see them.
    "sqlalchemy.dialects.sqlite",
    "passlib.handlers.bcrypt",
    "jose.backends.cryptography_backend",
    "python_multipart",
    "multipart",
]
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("alembic", filter=lambda name: not name.startswith("alembic.testing"))
hiddenimports += collect_submodules("app")
# pqcrypto builds its ML-KEM / ML-DSA modules at import time from one compiled library,
# PyMuPDF ships native libraries, and pymupdf_fonts carries the Noto font used for the
# zero-width (copy-paste) watermark layer: bundle these packages whole.
for package in ("pqcrypto", "pymupdf", "pymupdf_fonts"):
    package_datas, package_binaries, package_hidden = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hidden

a = Analysis(
    [str(repo / "backend" / "desktop_server.py")],
    pathex=[str(repo / "backend")],
    datas=datas,
    binaries=binaries,
    hiddenimports=hiddenimports,
    excludes=["cv2", "tkinter", "matplotlib", "psycopg", "pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="mudra-server", console=True)
coll = COLLECT(exe, a.binaries, a.datas, name="mudra-server")
