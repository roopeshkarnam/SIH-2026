#!/usr/bin/env bash
# Run the backend fully offline: local SQLite database, local storage and key store.
# Nothing here touches the shared database in .env (these variables override it).
# JWT_SECRET and KEYSTORE_MASTER_KEY still come from .env.
#
#   ./run-offline.sh          migrate the offline DB, then start the API on this machine only
#   ./run-offline.sh lan      same, but reachable by teammates on the same Wi-Fi/hotspot
#   ./run-offline.sh migrate  only migrate
#   PORT=8010 ./run-offline.sh ...   use another port (then set VITE_API_URL for the frontend)
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
OFFLINE="$REPO/offline"
PORT="${PORT:-8000}"
HOST=127.0.0.1
mkdir -p "$OFFLINE/storage" "$OFFLINE/keys"

export DATABASE_URL="sqlite:///$OFFLINE/offline.db"
export STORAGE_ROOT="$OFFLINE/storage"
export KEY_STORAGE_PATH="$OFFLINE/keys"
export PYTHONPATH="$REPO/backend"

if [ "${1:-}" = "lan" ]; then
  LAN_IP="$(ipconfig getifaddr en0 || ipconfig getifaddr en1 || true)"
  if [ -z "$LAN_IP" ]; then echo "No Wi-Fi/LAN address found. Connect to the shared network first." >&2; exit 1; fi
  HOST=0.0.0.0
  export FRONTEND_ORIGINS="[\"http://localhost:5173\",\"http://127.0.0.1:5173\",\"http://$LAN_IP:5173\"]"
  echo "LAN mode. In another terminal run:  cd frontend && npm run dev -- --host"
  echo "Teammates open:  http://$LAN_IP:5173   (only use a trusted network or your own hotspot)"
fi

cd "$REPO"
.venv/bin/alembic upgrade head

if [ "${1:-}" != "migrate" ]; then
  exec .venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT"
fi
