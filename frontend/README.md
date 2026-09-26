# Frontend

Basic React/Vite dashboard for the SIH cryptographic attribution backend.

## Run

    npm install
    npm run dev

The frontend expects the backend at `http://127.0.0.1:8000`. To change it, create `frontend/.env.local` with:

    VITE_API_URL=http://127.0.0.1:8000
