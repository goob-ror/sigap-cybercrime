/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

/**
 * Injects a strict Content-Security-Policy into the built index.html to enforce offline-first:
 * scripts only from the app itself, and `connect-src 'self'` so the app cannot make any outbound
 * request. Build-only, so Vite's dev server (HMR websocket) keeps working.
 */
function offlineCsp(): Plugin {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'", // inline style attributes (entity colours, score bars)
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "worker-src 'self' blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'none'",
  ].join('; ')
  return {
    name: 'sigap-offline-csp',
    apply: 'build',
    transformIndexHtml: (html) => html.replace('</head>', `    <meta http-equiv="Content-Security-Policy" content="${csp}" />\n  </head>`),
  }
}

// https://vite.dev/config/
export default defineConfig({
  // Relative base so the built app also works from a subfolder, a USB drive, or file shares.
  base: './',
  plugins: [react(), tailwindcss(), offlineCsp()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    port: 5173,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // The on-disk module cache keeps stale `import.meta.glob` results, so a new rules/*.yml file
    // would be missed by the tests. The suite runs in about a second without it.
    fsModuleCache: false,
  },
})
