# SIH 2026 — Cryptographic Attribution System

Backend-first implementation for **SIH 26237: Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution**.

## Current implemented core

- FastAPI REST backend
- JWT authentication with Swagger-compatible OAuth2 password flow
- PostgreSQL + SQLAlchemy + Alembic
- AES-256-GCM document encryption
- ML-KEM-768 key establishment
- ML-DSA-65 digital signatures
- HKDF document-key wrapping
- SHA-256 integrity and canonical-record hashing
- AES-256-GCM encrypted local private-key store
- Recipient decryption sessions
- Session-specific watermark identifiers and fingerprint payloads
- Signed provenance records
- Development ledger adapter
- Forensic watermark-ID lookup
- Basic React/Vite security dashboard

## Important implementation boundary

The current MVP deliberately keeps two SIH modules behind service boundaries:

1. Real PDF pixel/DCT/DWT/SVD forensic watermark embedding and extraction.
2. Production Hyperledger Fabric multi-organization endorsement and commit.

The existing `watermark.py` and `ledger.py` services are the integration points for those next stages. They must not be described as completed production modules yet.

## 1. Create the backend environment

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2. Create `.env`

The repository intentionally does **not** contain `.env` or `.env.example`. Do not commit credentials.

Create `sih/.env` with:

```env
APP_NAME=Cryptographic Attribution System
APP_VERSION=1.0.0
DATABASE_URL=YOUR_POSTGRESQL_URL
JWT_SECRET=GENERATE_A_LONG_RANDOM_SECRET
JWT_ALGORITHM=HS256
ACCESS_TOKEN_MINUTES=30
STORAGE_ROOT=storage
KEY_STORAGE_PATH=storage/keys
MAX_UPLOAD_SIZE_MB=100
PQC_KEM_ALGORITHM=ML-KEM-768
PQC_SIGNATURE_ALGORITHM=ML-DSA-65
KEYSTORE_MASTER_KEY=YOUR_BASE64_32_BYTE_KEY
LEDGER_ENABLED=false
FABRIC_GATEWAY_URL=
WATERMARK_ENABLED=true
FRONTEND_ORIGINS=["http://localhost:5173","http://localhost:3000"]
ENVIRONMENT=development
```

Generate secrets locally:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
```

## 3. Database

For a fresh database:

```powershell
alembic upgrade head
```

For the existing development PostgreSQL database, keep its current data and migration state. Do not reset the database just to install this cleaned project.

## 4. Start backend

```powershell
$env:PYTHONPATH="backend"
python -m uvicorn app.main:app --reload
```

Swagger:

`http://127.0.0.1:8000/docs`

## 5. Start frontend

```powershell
cd frontend
npm install
npm run dev
```

Open:

`http://localhost:5173`

## Basic demo flow

1. Register recipient.
2. Sign in.
3. Generate ML-KEM-768 + ML-DSA-65 keys.
4. Upload a document.
5. Decrypt it to create a session and watermark identifier.
6. Create the signed provenance record.
7. Run forensic lookup using the watermark identifier.

## Repository hygiene

This clean distribution intentionally excludes:

- `.git`
- Python virtual environment
- Node modules/build output
- `.env` and secret material
- pytest/cache/compiled files
- obsolete duplicate ORM models
- obsolete session route/service
- unused schema layer
- old test files
- empty placeholder deployment files

The project is now intended to be the clean working base. Team members can extend the watermark, Fabric, UI, security-testing and deployment layers without carrying the obsolete files forward.
