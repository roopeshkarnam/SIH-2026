// MUDRA desktop shell: starts the bundled offline backend and shows the UI in its own window.
const { app, BrowserWindow, ipcMain, Menu, safeStorage, session } = require('electron')
const { spawn } = require('node:child_process')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

// One fixed port, so teammates know where to join a host.
const PORT = 8765

let backend = null
let launcher = null

const userData = () => app.getPath('userData')
const configPath = () => path.join(userData(), 'config.json')
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function readConfig() {
  try { return JSON.parse(fs.readFileSync(configPath(), 'utf8')) } catch { return { mode: 'local', address: '' } }
}

// JWT secret and key-store master key: generated on first run, kept encrypted by the
// OS (macOS Keychain / Windows DPAPI). No .env and no cloud key service.
function loadSecrets() {
  if (!safeStorage.isEncryptionAvailable()) throw new Error('The operating system secure storage (Keychain / DPAPI) is not available.')
  const file = path.join(userData(), 'secrets.bin')
  if (fs.existsSync(file)) return JSON.parse(safeStorage.decryptString(fs.readFileSync(file)))
  const secrets = { jwtSecret: crypto.randomBytes(48).toString('base64url'), masterKey: crypto.randomBytes(32).toString('base64') }
  fs.writeFileSync(file, safeStorage.encryptString(JSON.stringify(secrets)), { mode: 0o600 })
  return secrets
}

function lanAddresses() {
  return Object.values(os.networkInterfaces()).flat().filter(a => a && a.family === 'IPv4' && !a.internal).map(a => a.address)
}

async function reachable(url) {
  try { return (await fetch(`${url}/health`, { signal: AbortSignal.timeout(1500) })).ok } catch { return false }
}

function backendCommand() {
  if (app.isPackaged) {
    const exe = process.platform === 'win32' ? 'mudra-server.exe' : 'mudra-server'
    return { command: path.join(process.resourcesPath, 'backend', exe), args: [], env: {} }
  }
  // Development: run the backend from source with the repo's virtualenv and the built UI.
  const repo = path.join(__dirname, '..')
  const python = process.platform === 'win32' ? path.join(repo, '.venv', 'Scripts', 'python.exe') : path.join(repo, '.venv', 'bin', 'python')
  return {
    command: python,
    args: [path.join(repo, 'backend', 'desktop_server.py'), '--ui-dir', path.join(repo, 'frontend', 'dist')],
    env: { PYTHONPATH: path.join(repo, 'backend') },
  }
}

async function startBackend(listenHost) {
  const url = `http://127.0.0.1:${PORT}`
  if (await reachable(url)) throw new Error(`Port ${PORT} is already in use by another program. Close it and try again.`)

  const secrets = loadSecrets()
  const { command, args, env } = backendCommand()
  const logPath = path.join(userData(), 'backend.log')
  const log = fs.openSync(logPath, 'a')
  const baseEnv = { ...process.env }
  delete baseEnv.PYTHONHOME
  delete baseEnv.PYTHONPATH
  let exitCode = null
  backend = spawn(command, [...args, '--data-dir', path.join(userData(), 'data'), '--host', listenHost, '--port', String(PORT)], {
    env: { ...baseEnv, ...env, JWT_SECRET: secrets.jwtSecret, KEYSTORE_MASTER_KEY: secrets.masterKey },
    stdio: ['ignore', log, log],
    windowsHide: true,
  })
  backend.on('error', () => { exitCode = -1 })
  backend.on('exit', code => { exitCode = code; backend = null })

  for (let i = 0; i < 120; i++) {
    if (exitCode !== null) throw new Error(`The MUDRA service stopped during start-up. Details: ${logPath}`)
    if (await reachable(url)) return url
    await sleep(500)
  }
  throw new Error(`The MUDRA service did not start in time. Details: ${logPath}`)
}

async function start(mode, address) {
  let url
  if (mode === 'join') {
    address = (address || '').trim()
    if (!/^[\w.-]+$/.test(address)) throw new Error('Enter the host computer\'s IP address, for example 192.168.1.20.')
    url = `http://${address}:${PORT}`
    if (!(await reachable(url))) throw new Error(`No MUDRA host answered at ${address}:${PORT}. Check the address and that you are on the same network.`)
  } else {
    url = await startBackend(mode === 'host' ? '0.0.0.0' : '127.0.0.1')
  }
  fs.writeFileSync(configPath(), JSON.stringify({ mode, address: address || '' }))
  openApp(url)
}

function openApp(url) {
  const win = new BrowserWindow({
    width: 1200, height: 860, minWidth: 900, minHeight: 640, title: 'MUDRA', backgroundColor: '#f6f5ee',
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false, devTools: !app.isPackaged },
  })
  // Ask the OS to leave this window out of screenshots, screen recordings and screen sharing.
  // Windows 10 2004+/11: the window is captured as black. macOS: honoured by the system
  // screenshot tools on macOS 14; newer macOS capture APIs may ignore it. Cannot stop a phone camera.
  win.setContentProtection(true)
  const origin = new URL(url).origin
  // Stay inside the app: no pop-ups and no navigation to other sites.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  win.webContents.on('will-navigate', (event, target) => { if (new URL(target).origin !== origin) event.preventDefault() })
  win.loadURL(`${url}/ui/`)
  launcher?.close()
}

function createLauncher() {
  launcher = new BrowserWindow({
    width: 560, height: 640, resizable: false, title: 'MUDRA', backgroundColor: '#f6f5ee',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false, devTools: !app.isPackaged },
  })
  launcher.on('closed', () => { launcher = null })
  launcher.loadFile(path.join(__dirname, 'launcher.html'))
}

ipcMain.handle('launcher:info', () => ({ ...readConfig(), lan: lanAddresses(), port: PORT }))
ipcMain.handle('launcher:start', async (_event, mode, address) => {
  try { await start(mode, address); return { ok: true } } catch (error) {
    backend?.kill()
    return { ok: false, error: error.message }
  }
})

if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  app.whenReady().then(() => {
    // No camera, microphone, notifications etc. for any page.
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false))
    const template = [
      ...(process.platform === 'darwin' ? [{ role: 'appMenu' }] : [{ role: 'fileMenu' }]),
      { role: 'editMenu' },
      ...(app.isPackaged ? [] : [{ role: 'viewMenu' }]),
      { role: 'windowMenu' },
    ]
    Menu.setApplicationMenu(Menu.buildFromTemplate(template))
    createLauncher()
  })
  app.on('second-instance', () => BrowserWindow.getAllWindows()[0]?.focus())
  app.on('window-all-closed', () => app.quit())
  app.on('will-quit', () => backend?.kill())
}
