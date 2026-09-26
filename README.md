# CRYPTA: Cryptographic Attribution System

**SIH 2026 · Problem 26237:** Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution.

CRYPTA lets an office send a confidential document so that only the intended recipient can open it. Every opening produces a uniquely watermarked copy and a signed, tamper-evident record. If a copy leaks, an investigator can upload it and find out whose copy it was.

All key establishment and signatures use NIST post-quantum standards (ML-KEM, ML-DSA).

---

## How it works

The dashboard walks through the full story as three roles. In the current demo one account plays all three.

| Step | Role | What happens | Cryptography |
|---|---|---|---|
| 1 | Recipient | Create keys | ML-KEM-768 key pair (for receiving) and a separate ML-DSA-65 key pair (for signing). Private keys are stored AES-256-GCM encrypted. |
| 2 | Sender | Encrypt & send a document | A fresh AES-256-GCM key encrypts the file. ML-KEM encapsulation produces a shared secret, and HKDF-SHA256 (bound to the document ID and recipient ID) turns it into a key that wraps the AES key. |
| 3 | Recipient | Open the document | ML-KEM decapsulation → HKDF → unwrap → decrypt → SHA-256 integrity check. A decryption session gets a unique watermark ID, which is embedded invisibly in the PDF copy. |
| 4 | Recipient | Sign the access record | The record (document, hash, recipient, session, watermark ID, session nonce, timestamp) is hashed and signed with ML-DSA-65, then committed to the ledger adapter. |
| 5 | Investigator | Trace a leaked copy | The watermark ID is extracted from the leaked PDF and matched to the signed record, identifying the recipient and session. |

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, SQLAlchemy, Alembic |
| Database | PostgreSQL (team instance hosted on Supabase) |
| Post-quantum crypto | `pqcrypto`: ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) |
| Symmetric crypto | `cryptography`: AES-256-GCM, HKDF-SHA256, SHA-256 |
| PDF watermarking | PyMuPDF |
| Auth | JWT (OAuth2 password flow) |
| Frontend | React + Vite + TypeScript |

---

## Project status

| Area | Status |
|---|---|
| FastAPI backend, PostgreSQL, JWT auth | ✅ Done |
| ML-KEM-768 key establishment, ML-DSA-65 signatures | ✅ Done |
| AES-256-GCM encryption with HKDF key wrapping | ✅ Done |
| HKDF domain separation (document ID + recipient ID) | ✅ Done |
| Decryption sessions with unique watermark IDs | ✅ Done |
| Signed provenance records (including session nonce) | ✅ Done |
| Invisible PDF watermark: embed + extract from leaked copy | ✅ Done (text layer) |
| Leak → watermark → signed record → recipient attribution | ✅ Done |
| Guided three-role dashboard (Sender / Recipient / Investigator) | ✅ Done |
| Screenshot/print-resistant image watermark (DCT/DWT) | ⏳ Planned |
| Hyperledger Fabric multi-organization ledger | ⏳ Planned (development adapter in place) |
| Separate sender / recipient / investigator accounts (RBAC) | ⏳ Planned |
| Tamper/attack security tests, air-gapped deployment | ⏳ Planned |

**Known limitations**

- The current watermark lives in the PDF text layer and metadata. It survives forwarding, copying and re-saving, but not screenshots, print-and-scan, or flattening to images. The image-domain watermark will cover those.
- The ledger is a development adapter (`backend/app/services/ledger.py`). It is the integration point for Hyperledger Fabric.
- Encrypted files and private keys live in the local `storage/` folder of the machine that created them, so documents uploaded on one laptop cannot be decrypted on another.

---

## Getting started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Access to a PostgreSQL database (ask the team for the Supabase connection string)

### 1. Backend environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Create `.env` in the project root

`.env` is git-ignored. **Never commit it**, because it holds the database password and master keys.

```env
APP_NAME=Cryptographic Attribution System
APP_VERSION=1.0.0
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require
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

Generate the two secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"                    # JWT_SECRET
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"  # KEYSTORE_MASTER_KEY
```

**Supabase connection string tips**

- In Supabase, go to **Connect → URI → Session pooler**. The direct connection is IPv6-only and often fails on home and college networks.
- Change the `postgresql://` prefix to `postgresql+psycopg://` and add `?sslmode=require`.
- URL-encode special characters in the password (`@` → `%40`, `#` → `%23`).

### 3. Database

- **Shared team database** (already set up): do **not** run migrations. Just check that you are connected:

  ```bash
  PYTHONPATH=backend alembic current     # should print: bc7be07d1985 (head)
  ```

- **Fresh, empty database:**

  ```bash
  PYTHONPATH=backend alembic upgrade head
  ```

On Windows, set the variable first with `$env:PYTHONPATH="backend"`.

### 4. Start the backend

From the project root:

```bash
PYTHONPATH=backend python -m uvicorn app.main:app --reload
```

The API docs (Swagger) are at http://127.0.0.1:8000/docs.

### 5. Start the frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

### 6. Run the demo

1. Register an account and sign in.
2. Follow the highlighted step. The page switches between Sender, Recipient and Investigator automatically.
3. In step 3, click **Download your watermarked copy**.
4. In step 5, upload that downloaded file as the "leaked" PDF. It is traced back to your account.

Logins expire after 30 minutes. The app then returns you to the sign-in page.

---

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/auth/register` | Create an account |
| POST | `/auth/login` | Get a JWT access token |
| POST | `/users/{user_id}/pqc-keys` | Generate ML-KEM + ML-DSA key pairs |
| POST | `/documents/upload?recipient_id=` | Encrypt and store a document |
| GET | `/documents/mine` | List your documents |
| POST | `/decryption/{document_id}/{recipient_id}` | Decrypt, create session, embed watermark |
| GET | `/decryption/file/{session_id}` | Download your watermarked copy |
| POST | `/provenance/create/{session_id}` | Create the ML-DSA-signed provenance record |
| GET | `/provenance/{watermark_id}` | Fetch a record and verify its signature |
| GET | `/forensics/lookup/{watermark_id}` | Look up a watermark ID |
| POST | `/forensics/extract` | Upload a leaked PDF and trace its source |

---

## Project structure

```
backend/
  app/
    api/routes/      # auth, users, documents, decryption, provenance, forensics
    services/        # pqc, encryption, document_crypto, key_store, watermark, provenance, ledger
    db/              # SQLAlchemy models and session
    core/            # settings (.env), security helpers
  alembic/           # database migrations
  tests/             # crypto unit tests
frontend/
  src/main.tsx       # three-role guided dashboard
  src/styles.css
storage/             # local encrypted documents, keys, decrypted copies (git-ignored)
blockchain/fabric/   # Hyperledger Fabric integration (planned)
deployment/          # deployment notes (planned)
```

## Running tests

```bash
PYTHONPATH=backend python -m pytest backend/tests
```

---

## Research references

- NIST FIPS 203: [ML-KEM](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)
- NIST FIPS 204: [ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- NIST FIPS 205: [SLH-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) (considered; ML-DSA chosen)
- Balachandran, S. and Sivankalai, S. "A Post-Quantum Digital Preservation and Secure File Sharing Framework for Library Repositories." *Preservation, Digital Technology & Culture*, 2026. https://doi.org/10.1515/pdtc-2025-0090
- K. J. Brakas and M. Alanezi, "Watermarked PDF File Sharing and Security Blockchain-based System," *ICCR 2025*, Dubai. https://doi.org/10.1109/ICCR67387.2025.11292127
