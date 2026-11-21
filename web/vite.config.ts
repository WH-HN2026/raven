/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev: the Go server runs on ASI_HTTP_PORT (scripts/wt-env.sh picks it), and
// Vite proxies /api to it. Prod: `make build` embeds dist/ into the binary.
const apiPort = process.env.ASI_HTTP_PORT ?? '8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: Number(process.env.ASI_VITE_PORT ?? 5173),
    strictPort: true,
    proxy: { '/api': `http://127.0.0.1:${apiPort}` },
  },
  build: { outDir: 'dist', emptyOutDir: true },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
  },
})
