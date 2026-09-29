from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import auth, crypto, decryption, documents, forensics, health, provenance, users
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Cryptographic attribution backend for multi-recipient encrypted documents. "
        "Uses AES-256-GCM, ML-KEM-768, ML-DSA-65, session provenance and a ledger adapter."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(crypto.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(documents.router)
app.include_router(decryption.router)
app.include_router(provenance.router)
app.include_router(forensics.router)

if settings.frontend_dist:
    app.mount("/ui", StaticFiles(directory=settings.frontend_dist, html=True), name="ui")


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "pqc": {
            "kem": settings.pqc_kem_algorithm,
            "signature": settings.pqc_signature_algorithm,
        },
        "watermark_mode": "identifier-mvp",
        "ledger_mode": "development-adapter" if not settings.ledger_enabled else "fabric",
    }
