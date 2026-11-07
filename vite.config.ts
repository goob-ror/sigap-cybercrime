/// <reference types="vitest/config" />
import { defineConfig, loadEnv, type Connect, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { createApi } from './server/api.mjs'

/**
 * Serves the online API in `npm run dev` and `npm run preview`, with keys from `.env`. They are read
 * here, on the server: only `VITE_`-prefixed variables reach the browser bundle, and none are used.
 */
function onlineApi(): Plugin {
  const attach = (middlewares: Connect.Server, mode: string, root: string) => {
    const api = createApi({ env: loadEnv(mode, root, '') })
    middlewares.use((req, res, next) => {
      api.handle(req, res).then((handled) => { if (!handled) next() }, next)
    })
  }
  return {
    name: 'sigap-online-api',
    configureServer: (server) => attach(server.middlewares, server.config.mode, server.config.root),
    configurePreviewServer: (server) => attach(server.middlewares, server.config.mode, server.config.root),
  }
}

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

/**
 * Emits `sw.js`: `src/sw/sw.template.js` with the list of built files to keep for offline use, and a
 * version derived from their content, so the browser installs a new worker only when the app changed.
 */
function serviceWorker(): Plugin {
  return {
    name: 'sigap-service-worker',
    apply: 'build',
    enforce: 'post',
    generateBundle(_, bundle) {
      const names = Object.keys(bundle).sort()
      const hash = createHash('sha256')
      for (const name of names) {
        const item = bundle[name]
        hash.update(name).update(item.type === 'asset' ? item.source : item.code)
      }
      const fromPublic = ['./favicon.svg', './manifest.webmanifest', './icons/icon.svg', './icons/icon-maskable.svg']
      const precache = ['./', ...fromPublic, ...names.filter((name) => name !== 'index.html').map((name) => `./${name}`)]
      const template = readFileSync(path.resolve(import.meta.dirname, 'src/sw/sw.template.js'), 'utf8')
      const source = template.replace('__VERSION__', hash.digest('hex').slice(0, 12)).replace('__PRECACHE__', () => JSON.stringify(precache))
      this.emitFile({ type: 'asset', fileName: 'sw.js', source })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  // Relative base so the built app works from any subfolder. It must still be served over HTTPS or
  // localhost (browsers refuse module scripts from file://, and Web Crypto needs a secure context):
  // that is what the offline kit's launcher in kit/ is for.
  base: './',
  plugins: [react(), tailwindcss(), offlineCsp(), serviceWorker(), onlineApi()],
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
    include: ['src/**/*.test.ts', 'server/**/*.test.ts'],
    // The on-disk module cache keeps stale `import.meta.glob` results, so a new rules/*.yml file
    // would be missed by the tests. The suite runs in about a second without it.
    fsModuleCache: false,
  },
})
