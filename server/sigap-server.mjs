// Serves the built app and the online API from one small process. The key comes from the environment:
//   node --env-file-if-exists=.env server/sigap-server.mjs
//   docker run --env-file .env -p 8080:8080 sigap
// Without a key it is a plain static server, and SIGAP works fully without the online feature.
// Put HTTPS and a password in front of it: see docs/DEPLOYMENT.md.
import { createReadStream, statSync } from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { createApi } from './api.mjs'

const root = path.resolve(process.env.SIGAP_DIST ?? path.join(import.meta.dirname, '..', 'dist'))
const port = Number(process.env.PORT) || 8080
const host = process.env.HOST || '0.0.0.0'
const api = createApi({ env: process.env })

const TYPES = { '.html': 'text/html; charset=utf-8', '.webmanifest': 'application/manifest+json', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.json': 'application/json; charset=utf-8', '.zip': 'application/zip', '.sha256': 'text/plain; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.map': 'application/json; charset=utf-8' }

function fileIn(relative) {
  const full = path.join(root, relative)
  if (full !== root && !full.startsWith(root + path.sep)) return null
  try {
    return statSync(full).isFile() ? full : null
  } catch {
    return null
  }
}

function reply(res, status, text) {
  res.statusCode = status
  res.setHeader('Content-Type', 'text/plain; charset=utf-8')
  res.end(text)
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Frame-Options', 'DENY')
  try {
    if (await api.handle(req, res)) return
    if (req.method !== 'GET' && req.method !== 'HEAD') return reply(res, 405, 'Metode tidak didukung')

    let pathname
    try {
      pathname = decodeURIComponent(new URL(req.url ?? '/', 'http://sigap').pathname)
    } catch {
      return reply(res, 400, 'Alamat tidak valid')
    }

    let file = pathname === '/' ? null : fileIn(pathname)
    // A missing file under these must be a 404, not the app's page: a client treats that page as the file.
    if (!file && /^\/(assets|unduh|api)\//.test(pathname)) return reply(res, 404, 'Tidak ditemukan')
    file ??= fileIn('index.html')
    if (!file) return reply(res, 500, 'Aplikasi belum dibangun: jalankan npm run build:kit')

    // Hashed files never change. Everything else is revalidated, so a new deployment arrives on the next visit.
    res.setHeader('Cache-Control', pathname.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-cache')
    res.setHeader('Content-Type', TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream')
    res.setHeader('Content-Length', statSync(file).size)
    if (req.method === 'HEAD') return res.end()
    createReadStream(file).on('error', () => res.destroy()).pipe(res)
  } catch {
    if (!res.headersSent) reply(res, 500, 'Terjadi kesalahan')
  }
})

server.listen(port, host, () => {
  console.log(`SIGAP: http://localhost:${port}  (${root})`)
  console.log(`  Google Safe Browsing: ${api.status().safeBrowsing ? 'aktif' : 'tidak aktif'}`)
})

for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)))
