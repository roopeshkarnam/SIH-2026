// `npm start`: run the desktop app from source. VS Code terminals set ELECTRON_RUN_AS_NODE=1,
// which would make Electron behave like plain Node, so it is removed here.
//   npm start                     normal app
//   npm start -- scripts/selftest.js   development self-check
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import electron from 'electron'

const env = { ...process.env }
delete env.ELECTRON_RUN_AS_NODE
const desktop = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const entry = process.argv[2] || '.'
spawn(electron, [entry], { cwd: desktop, env, stdio: 'inherit' }).on('exit', code => process.exit(code ?? 0))
