// Only the launcher window gets this bridge; the app window has no access to Electron.
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('mudra', {
  info: () => ipcRenderer.invoke('launcher:info'),
  start: (mode, address) => ipcRenderer.invoke('launcher:start', mode, address),
})
