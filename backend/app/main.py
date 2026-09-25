from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import (
    auth,
    crypto,
    decryption,
    documents,
    forensics,
    health,
    provenance,
    users,
)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Cryptographic attribution backend using AES-256-GCM, "
        "ML-KEM-768, ML-DSA-65, forensic watermark identifiers, "
        "and a ledger adapter."
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


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
    }
