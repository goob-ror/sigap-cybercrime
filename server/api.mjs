// The only part of SIGAP that talks to an outside service, and the only part that holds its key.
// The browser calls this on its own origin, so its `connect-src 'self'` policy stays as it is and the key
// never reaches a page. The offline kit does not include this file, so nothing online exists there.
// No dependencies: runs under Vite in development and under `sigap-server.mjs` in production.

const SAFE_BROWSING = 'https://safebrowsing.googleapis.com/v5alpha1/hashes:search'
const MAX_BODY_BYTES = 16 * 1024
const MAX_PREFIXES = 60
const TIMEOUT_MS = 20_000
const HOUR_MS = 60 * 60_000
/** Real keys are far longer. A shorter value is a placeholder left in `.env`. */
const MIN_KEY_LENGTH = 20
const THREAT_TYPES = { 1: 'MALWARE', 2: 'SOCIAL_ENGINEERING', 3: 'UNWANTED_SOFTWARE', 4: 'POTENTIALLY_HARMFUL_APPLICATION' }
/** `CANARY` and `FRAME_ONLY`: Google says neither is for warning about a page the user is looking at. */
const IGNORED_ATTRIBUTES = new Set([1, 2])

class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

function readVarint(bytes, start) {
  let value = 0
  let shift = 0
  for (let i = start; i < bytes.length; i++) {
    value += (bytes[i] & 0x7f) * 2 ** shift
    if (!(bytes[i] & 0x80)) return [value, i + 1]
    shift += 7
  }
  throw new Error('protobuf terpotong')
}

/** Field number and value of each field in a protobuf message. Enough for this one response; hashes:search has no JSON form. */
function protoFields(bytes) {
  const fields = []
  let at = 0
  while (at < bytes.length) {
    const [tag, next] = readVarint(bytes, at)
    at = next
    const number = Math.floor(tag / 8)
    const wire = tag % 8
    if (wire === 0) {
      const [value, after] = readVarint(bytes, at)
      fields.push([number, value])
      at = after
    } else if (wire === 2) {
      const [length, after] = readVarint(bytes, at)
      fields.push([number, bytes.subarray(after, after + length)])
      at = after + length
    } else if (wire === 1) at += 8
    else if (wire === 5) at += 4
    else throw new Error('protobuf tidak dikenal')
  }
  return fields
}

/** `SearchHashesResponse`: full_hashes = 1 { full_hash = 1, full_hash_details = 2 { threat_type = 1, attributes = 2 } }, cache_duration = 2 { seconds = 1 }. */
export function decodeHashesResponse(bytes) {
  const matches = []
  let cacheSeconds = 0
  for (const [number, value] of protoFields(bytes)) {
    if (number === 2) {
      for (const [field, seconds] of protoFields(value)) if (field === 1) cacheSeconds = seconds
      continue
    }
    if (number !== 1) continue
    let hash = ''
    const threats = []
    for (const [field, inner] of protoFields(value)) {
      if (field === 1) hash = Buffer.from(inner).toString('base64')
      if (field !== 2) continue
      let threat
      let ignored = false
      for (const [detailField, detail] of protoFields(inner)) {
        if (detailField === 1) threat = THREAT_TYPES[detail]
        if (detailField === 2) ignored ||= IGNORED_ATTRIBUTES.has(detail)
      }
      if (threat && !ignored) threats.push(threat)
    }
    if (hash && threats.length) matches.push({ hash, threats })
  }
  return { matches, cacheSeconds }
}

/** Requests per hour, so a public demo link cannot use up the key's whole quota. */
function hourlyLimit(max, now) {
  let windowStart = now()
  let used = 0
  return () => {
    if (now() - windowStart >= HOUR_MS) {
      windowStart = now()
      used = 0
    }
    if (used >= max) throw new ApiError(429, 'Batas pemakaian per jam tercapai. Coba lagi nanti; seluruh analisis SIGAP tetap berjalan tanpa layanan ini.')
    used++
  }
}

const usableKey = (value) => (typeof value === 'string' && value.trim().length >= MIN_KEY_LENGTH ? value.trim() : null)

async function readJson(req) {
  if (!(req.headers['content-type'] ?? '').includes('application/json')) throw new ApiError(415, 'Permintaan harus berupa JSON.')
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > MAX_BODY_BYTES) throw new ApiError(413, 'Data terlalu besar.')
    chunks.push(chunk)
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('bukan objek')
    return value
  } catch {
    throw new ApiError(400, 'JSON tidak valid.')
  }
}

const isBase64Prefix = (v) => typeof v === 'string' && /^[A-Za-z0-9+/]{5}[AQgw]==$/.test(v)

/** A browser names the page that sent a POST. `Origin: null`, from a sandboxed frame or a local file, is refused. */
function sameOrigin(req) {
  const { origin, host } = req.headers
  if (!origin) return true
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}

/** Sets up the handler. The key comes from `env`; nothing here writes it, or request contents, anywhere. */
export function createApi({ env, fetchImpl = fetch, now = Date.now }) {
  const safeBrowsingKey = usableKey(env.SAFE_BROWSING_API)
  const limitSafeBrowsing = hourlyLimit(Number(env.SAFE_BROWSING_LIMIT_PER_HOUR) || 300, now)

  const status = () => ({ safeBrowsing: !!safeBrowsingKey })

  async function handleSafeBrowsing(req) {
    if (!safeBrowsingKey) throw new ApiError(503, 'Google Safe Browsing tidak diaktifkan di server ini.')
    const { hashPrefixes } = await readJson(req)
    if (!Array.isArray(hashPrefixes) || !hashPrefixes.length || hashPrefixes.length > MAX_PREFIXES || !hashPrefixes.every(isBase64Prefix)) throw new ApiError(400, 'Prefiks hash tidak valid.')
    limitSafeBrowsing()
    const query = [...new Set(hashPrefixes)].map((p) => `hashPrefixes=${encodeURIComponent(p)}`).join('&')
    let response
    try {
      response = await fetchImpl(`${SAFE_BROWSING}?${query}`, { headers: { 'x-goog-api-key': safeBrowsingKey }, signal: AbortSignal.timeout(TIMEOUT_MS) })
    } catch {
      throw new ApiError(502, 'Google Safe Browsing tidak dapat dihubungi.')
    }
    if (response.status === 429) throw new ApiError(429, 'Kuota Google Safe Browsing habis. Coba lagi nanti.')
    if (!response.ok) throw new ApiError(502, 'Google Safe Browsing sedang tidak dapat dipakai.')
    try {
      return decodeHashesResponse(new Uint8Array(await response.arrayBuffer()))
    } catch {
      throw new ApiError(502, 'Jawaban Google Safe Browsing tidak dapat dibaca.')
    }
  }

  function send(res, code, value) {
    res.statusCode = code
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.end(JSON.stringify(value))
  }

  /** Answers `/api/*` requests. False for anything else, so the caller can serve the app. */
  async function handle(req, res) {
    const path = new URL(req.url ?? '/', 'http://sigap').pathname
    const route = /\/api\/(status|safe-browsing)$/.exec(path)?.[1]
    if (!route) return false
    try {
      if (route === 'status') {
        if (req.method !== 'GET' && req.method !== 'HEAD') throw new ApiError(405, 'Metode tidak didukung.')
        send(res, 200, status())
        return true
      }
      if (req.method !== 'POST') throw new ApiError(405, 'Metode tidak didukung.')
      // This API answers only its own pages. No CORS headers are ever sent, and this also stops cross-site form posts.
      if (!sameOrigin(req)) throw new ApiError(403, 'Asal permintaan ditolak.')
      send(res, 200, await handleSafeBrowsing(req))
    } catch (err) {
      send(res, err instanceof ApiError ? err.status : 500, { error: err instanceof ApiError ? err.message : 'Terjadi kesalahan di server.' })
    }
    return true
  }

  return { handle, status }
}
