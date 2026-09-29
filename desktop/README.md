# MUDRA desktop app

An offline desktop app: the FastAPI backend is bundled with PyInstaller (no Python needed on the
target machine) and shown in an Electron window. Nothing needs the internet or a cloud service.

On start, a launcher offers three modes:

| Mode | What it does |
|---|---|
| This computer only | Runs everything locally (one-laptop demo). Listens on 127.0.0.1 only. |
| Host for my team | This computer is the server. Teammates on the same Wi-Fi/hotspot join with its IP (shown in the launcher). Use only a trusted network. |
| Join a host | Connects to a teammate's computer that is hosting. |

Data lives in the app's profile folder (macOS: `~/Library/Application Support/MUDRA`,
Windows: `%APPDATA%\MUDRA`): SQLite database, encrypted documents, key store and `backend.log`.
The JWT secret and key-store master key are generated on first run and kept encrypted by the OS
(macOS Keychain / Windows DPAPI). Deleting the profile folder resets the app, and files encrypted
before that can no longer be opened.

**Screenshot protection:** the app window asks the OS to exclude it from screenshots, screen
recordings and screen sharing. On Windows 10 (2004+) and 11 the window is captured as black. On
macOS 14 the system screenshot tools cannot capture it (tested); newer macOS capture methods may
ignore this. Nothing can stop a phone camera, which is why every opened copy is watermarked.
Note: screen-sharing the app in a video call also shows a black window; present via HDMI mirroring.

## Build an installer

PyInstaller cannot cross-compile: build the macOS app on a Mac and the Windows app on Windows.

Prerequisites: the repo `.venv` with `pip install -r backend/requirements-backend.txt pyinstaller`,
Node.js 18+, and `npm install` in both `frontend/` and `desktop/`.

```bash
cd desktop
npm run dist
```

Output in `desktop/dist/`: `MUDRA-<version>-arm64.dmg` on macOS, `MUDRA Setup <version>.exe` on Windows.

The macOS build is ad-hoc signed, not notarized (that needs a paid Apple Developer ID). On
another Mac, the first launch needs right-click → Open, or System Settings → Privacy & Security →
Open Anyway. Apple Silicon builds do not run on Intel Macs.

## Run from source (development)

```bash
cd frontend && npm run build   # the app serves this build
cd ../desktop && npm start
```

`npm start` removes `ELECTRON_RUN_AS_NODE`, which VS Code terminals set and which would otherwise
make Electron behave like plain Node.

Self-check (starts the app with a throwaway profile, saves pictures of each window and real OS
screenshots of the protected app window, then quits):

```bash
MUDRA_SELFTEST_OUT=/tmp/mudra-check npm start -- scripts/selftest.js
```
