// Development check (not shipped): runs the real desktop app with a throwaway profile,
// clicks Start in the launcher ("This computer only"), saves a picture of each window and a real
// OS screenshot of the app window (to check screenshot protection), then quits.
//   MUDRA_SELFTEST_OUT=/some/dir npm start -- scripts/selftest.js
const { app } = require('electron')
const { execFile } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const out = process.env.MUDRA_SELFTEST_OUT
app.setPath('userData', fs.mkdtempSync(path.join(out, 'profile-')))
let shot = 0

app.on('browser-window-created', (_event, win) => {
  win.webContents.on('did-finish-load', async () => {
    await new Promise(resolve => setTimeout(resolve, 2000))
    const url = win.webContents.getURL()
    const name = url.endsWith('launcher.html') ? 'launcher' : 'app'
    fs.writeFileSync(path.join(out, `${++shot}-${name}.png`), (await win.webContents.capturePage()).toPNG())
    console.log(`captured ${name}: ${url}`)
    if (name === 'launcher') return win.webContents.executeJavaScript("document.getElementById('start').click()")
    // Control run: MUDRA_SELFTEST_UNPROTECTED=1 turns protection off to compare.
    if (process.env.MUDRA_SELFTEST_UNPROTECTED) win.setContentProtection(false)
    win.focus()
    await new Promise(resolve => setTimeout(resolve, 1000))
    // Real OS screenshots: of only this window (like Cmd+Shift+4, window mode), and of the
    // screen area under the window (like Cmd+Shift+3, cropped to the window).
    const windowId = win.getMediaSourceId().split(':')[1]
    const b = win.getContentBounds()
    const captures = [
      ['window', ['-x', '-o', '-l', windowId]],
      ['screen-area', ['-x', `-R${b.x},${b.y},${b.width},${b.height}`]],
    ]
    for (const [label, args] of captures) {
      await new Promise(resolve => execFile('screencapture', [...args, path.join(out, `system-${label}.png`)], (error, _stdout, stderr) => {
        console.log(`system screenshot (${label}): ${error ? `failed: ${stderr.trim()}` : 'saved'}`)
        resolve()
      }))
    }
    app.quit()
  })
})

require('../main.js')
