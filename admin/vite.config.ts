/// <reference types="vitest" />
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Served by AllSet Identity at /admin/ and, through the Firebase rewrite, at
// /identity/admin/. Relative asset paths work under both, and the app routes
// with URL hashes, so the server only ever returns index.html.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const identityUrl = (env.IDENTITY_URL || 'http://localhost:8100').replace(/\/+$/, '')

  return {
    base: './',
    plugins: [react()],
    build: { outDir: 'dist', sourcemap: false },
    server: {
      port: 5174,
      proxy: { '/v1': { target: identityUrl, changeOrigin: true } },
    },
    test: { environment: 'node', include: ['src/**/*.test.ts'] },
  }
})
