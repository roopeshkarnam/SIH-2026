import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Relative asset paths: the desktop backend serves the built UI under /ui/.
  base: './',
  server: { port: 5173 },
})
