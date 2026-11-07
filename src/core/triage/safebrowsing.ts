/**
 * Google Safe Browsing, by hash prefix. The URL itself never leaves this browser: only the first 4 bytes
 * of the SHA-256 of a few URL fragments are sent, and the full hashes that come back are compared here.
 * Canonicalization and expressions follow Google's published rules and test vectors:
 * https://developers.google.com/safe-browsing/v4/urls-hashing
 */

const textBytes = new TextEncoder()

/** The string's UTF-8 bytes as one character each, so percent-escapes can be handled as bytes. */
function toBinary(text: string): string {
  return String.fromCharCode(...textBytes.encode(text))
}

function unescapeFully(binary: string): string {
  let current = binary
  for (let i = 0; i < 1024; i++) {
    const next = current.replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
    if (next === current) return next
    current = next
  }
  return current
}

function escapeBinary(binary: string): string {
  let out = ''
  for (const char of binary) {
    const code = char.charCodeAt(0)
    out += code <= 32 || code >= 127 || char === '#' || char === '%' ? `%${code.toString(16).toUpperCase().padStart(2, '0')}` : char
  }
  return out
}

/** Any legal IPv4 spelling (`3279880203`, `0xC3.0177.0.11`) as four decimals, or null when it is not one. */
function normalizeIpv4(host: string): string | null {
  const parts = host.split('.')
  if (parts.length < 1 || parts.length > 4) return null
  const values: number[] = []
  for (const part of parts) {
    if (!/^(0x[0-9a-f]*|[0-9]+)$/i.test(part)) return null
    const value = /^0x/i.test(part) ? parseInt(part.slice(2) || '0', 16) : /^0[0-7]+$/.test(part) ? parseInt(part, 8) : /^0/.test(part) && part.length > 1 ? NaN : parseInt(part, 10)
    if (!Number.isFinite(value)) return null
    values.push(value)
  }
  const last = values.pop()!
  if (values.some((v) => v > 255) || last >= 256 ** (4 - values.length)) return null
  let total = last
  values.forEach((v, i) => { total += v * 256 ** (3 - i) })
  return [total / 2 ** 24, (total / 2 ** 16) % 256, (total / 2 ** 8) % 256, total % 256].map((n) => Math.floor(n)).join('.')
}

function canonicalPath(binary: string): string {
  const segments: string[] = []
  const pieces = binary.split('/').slice(1)
  const trailing = ['', '.', '..'].includes(pieces.at(-1) ?? '')
  for (const piece of pieces) {
    if (piece === '' || piece === '.') continue
    if (piece === '..') segments.pop()
    else segments.push(piece)
  }
  if (!segments.length) return '/'
  return `/${segments.join('/')}${trailing ? '/' : ''}`
}

export type CanonicalUrl = { url: string; host: string; path: string; query: string | null; isIp: boolean }

/** The canonical form of a URL as Safe Browsing defines it, or null when there is no host. */
export function canonicalize(input: string): CanonicalUrl | null {
  let text = input.trim().replace(/[\t\r\n]/g, '')
  const hash = text.indexOf('#')
  if (hash >= 0) text = text.slice(0, hash)
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text)
  const rest = scheme ? text.slice(scheme[0].length) : text
  const cut = rest.search(/[/?]/)
  const authority = (cut >= 0 ? rest.slice(0, cut) : rest).replace(/^.*@/, '').replace(/:\d*$/, '')
  const tail = cut >= 0 ? rest.slice(cut) : '/'
  const queryAt = tail.indexOf('?')
  const rawPath = queryAt >= 0 ? tail.slice(0, queryAt) : tail
  const rawQuery = queryAt >= 0 ? tail.slice(queryAt + 1) : null

  let host = unescapeFully(toBinary(authority)).replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.').toLowerCase()
  if (!host) return null
  const ip = normalizeIpv4(host)
  if (ip) host = ip
  // International names become punycode, which is what a browser would have asked for.
  else if (/[^\x00-\x7f]/.test(authority)) {
    try {
      host = new URL(`http://${authority}`).hostname
    } catch {
      return null
    }
  }
  const safeHost = escapeBinary(host)
  const path = escapeBinary(canonicalPath(unescapeFully(toBinary(rawPath.startsWith('/') ? rawPath : `/${rawPath}`))))
  const query = rawQuery === null ? null : escapeBinary(unescapeFully(toBinary(rawQuery)))
  return { url: `${(scheme?.[1] ?? 'http').toLowerCase()}://${safeHost}${path}${query === null ? '' : `?${query}`}`, host: safeHost, path, query, isIp: !!ip }
}

/** The host-suffix / path-prefix strings that get hashed: at most 5 hosts and 6 paths. */
export function expressions(canonical: CanonicalUrl): string[] {
  const { host, path, query, isIp } = canonical
  const hosts = [host]
  if (!isIp) {
    const labels = host.split('.')
    for (let i = Math.max(1, labels.length - 5); i <= labels.length - 2; i++) hosts.push(labels.slice(i).join('.'))
  }
  const paths = [query === null ? path : `${path}?${query}`, path, '/']
  const folders = path.split('/').slice(1, -1)
  let prefix = '/'
  for (const folder of folders.slice(0, 3)) {
    prefix += `${folder}/`
    paths.push(prefix)
  }
  const out = new Set<string>()
  for (const h of hosts) for (const p of paths) out.add(`${h}${p}`)
  return [...out]
}

const toBase64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))

async function sha256(text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', textBytes.encode(text)))
}

export type HashSearch = (hashPrefixes: string[]) => Promise<{ matches: { hash: string; threats: string[] }[]; cacheSeconds: number }>
export type SafeBrowsingVerdict = { host: string; checked: number; threats: string[]; cacheSeconds: number }

/** Asks about a URL using `search`. Only a server's reply that matches a full hash computed here counts. */
export async function checkUrl(input: string, search: HashSearch): Promise<SafeBrowsingVerdict | null> {
  const canonical = canonicalize(input)
  if (!canonical) return null
  const hashes = await Promise.all(expressions(canonical).map(sha256))
  const full = new Set(hashes.map(toBase64))
  const prefixes = [...new Set(hashes.map((h) => toBase64(h.subarray(0, 4))))]
  const { matches, cacheSeconds } = await search(prefixes)
  const threats = new Set(matches.filter((m) => full.has(m.hash)).flatMap((m) => m.threats))
  return { host: canonical.host, checked: prefixes.length, threats: [...threats], cacheSeconds }
}

/** How each threat type reads on screen. Google requires qualified wording: "possible", never a certainty. */
export const THREAT_LABEL: Record<string, string> = {
  MALWARE: 'kemungkinan memuat malware',
  SOCIAL_ENGINEERING: 'kemungkinan situs pengelabuan (phishing)',
  UNWANTED_SOFTWARE: 'kemungkinan memuat perangkat lunak yang tidak diinginkan',
  POTENTIALLY_HARMFUL_APPLICATION: 'kemungkinan memuat aplikasi berbahaya',
}
