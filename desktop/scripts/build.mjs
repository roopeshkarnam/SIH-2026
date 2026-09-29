// Builds the MUDRA installer for the current OS: UI -> bundled backend -> Electron app.
// macOS gives dist/MUDRA-<version>-arm64.dmg (or x64); Windows gives an NSIS .exe installer.
// PyInstaller cannot cross-compile, so build each OS on that OS.
// Needs: the repo .venv with requirements + pyinstaller, and `npm install` in frontend/ and desktop/.
import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const desktop = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const repo = path.join(desktop, '..')
const python = process.platform === 'win32'
  ? path.join(repo, '.venv', 'Scripts', 'python.exe')
  : path.join(repo, '.venv', 'bin', 'python')

if (!existsSync(python)) throw new Error(`Python virtualenv not found at ${python}`)

const run = (command, cwd) => {
  console.log(`\n> ${command}`)
  execSync(command, { cwd, stdio: 'inherit' })
}

run('npm run build', path.join(repo, 'frontend'))
run(`"${python}" -m PyInstaller mudra-server.spec --distpath build/backend --workpath build/pyinstaller --noconfirm --log-level WARN`, desktop)
run('npx electron-builder', desktop)
