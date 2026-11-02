import type { Level } from '@/core/model'
import { ipv4ToInt } from '@/core/net'

/**
 * Offline, structural URL triage. Inspects the shape of a link (host, scheme, path, query) for
 * phishing/lure signals. It NEVER fetches the URL, resolves DNS, or contacts any reputation
 * service — every signal is derived from the string itself. The score is explainable:
 * `1 − Π(1 − weight)` over the signals, same model as the incident score.
 */

export type UrlSignal = { id: string; label: string; level: Level }

export type UrlReport = {
  input: string
  valid: boolean
  scheme?: string
  host?: string
  signals: UrlSignal[]
  /** 0–1, computed from the signals. */
  score: number
}

const LEVEL_WEIGHT: Record<Level, number> = { critical: 0.6, high: 0.4, medium: 0.2, low: 0.1, informational: 0.05 }

// Fictional / commonly-abused generic TLDs and shorteners. No real brand names.
const SUSPECT_TLDS = new Set(['top', 'xyz', 'click', 'zip', 'mov', 'country', 'gq', 'cf', 'tk', 'ml', 'work', 'rest', 'fit', 'link'])
const SHORTENERS = new Set(['bit.ly', 't.co', 'tinyurl.com', 'cutt.ly', 's.id', 'ow.ly', 'is.gd', 'rb.gy', 'shorturl.at'])
const LURE = ['login', 'logon', 'signin', 'masuk', 'verify', 'verif', 'verifikasi', 'secure', 'account', 'akun', 'update', 'confirm', 'konfirmasi', 'wallet', 'bank', 'sso', 'gaji', 'tukin', 'hadiah', 'bonus', 'otp', 'reset', 'unlock']
const SENSITIVE_PARAMS = new Set(['password', 'pass', 'pwd', 'token', 'otp', 'pin', 'nik', 'ktp', 'sandi', 'secret'])

function parse(raw: string): { url: URL; assumedScheme: boolean } | null {
  const text = raw.trim()
  if (!text) return null
  try {
    return { url: new URL(text), assumedScheme: false }
  } catch {
    // Keep working offline; new URL() never makes a request.
  }
  try {
    return { url: new URL(`http://${text}`), assumedScheme: true }
  } catch {
    return null
  }
}

function isIpHost(host: string): boolean {
  if (host.startsWith('[') && host.endsWith(']')) return true // bracketed IPv6
  return ipv4ToInt(host) !== null
}

export function analyzeUrl(input: string): UrlReport {
  const parsed = parse(input)
  if (!parsed) return { input, valid: false, signals: [], score: 0 }

  const { url, assumedScheme } = parsed
  const host = url.hostname.toLowerCase()
  const path = url.pathname.toLowerCase()
  const scheme = url.protocol.replace(':', '')
  const labels = host.split('.')
  const tld = labels.at(-1) ?? ''
  const signals: UrlSignal[] = []
  const add = (id: string, label: string, level: Level) => signals.push({ id, label, level })

  if (assumedScheme) add('scheme-missing', 'Skema (http/https) tidak ditulis; diasumsikan http', 'informational')
  else if (scheme !== 'http' && scheme !== 'https') add('scheme-odd', `Skema tidak biasa: ${scheme}`, 'high')

  if (url.username) add('userinfo', "URL memuat '@' (bagian sebelum '@' dapat menyamarkan tujuan sebenarnya)", 'high')

  if (isIpHost(host)) add('ip-host', 'Host berupa alamat IP, bukan nama domain', 'medium')

  // The URL API already converts IDN (incl. Cyrillic/Greek homoglyph) hosts to punycode, so an
  // xn-- host is the signal to watch.
  if (host.includes('xn--')) add('punycode', 'Domain ter-punycode (xn--) — dapat menyembunyikan huruf menipu (homoglyph)', 'high')

  if (!isIpHost(host) && SUSPECT_TLDS.has(tld)) add('tld', `Akhiran domain .${tld} termasuk daftar perhatian`, 'medium')
  if (SHORTENERS.has(host)) add('shortener', 'Layanan pemendek URL — tujuan asli tersembunyi', 'medium')
  if (url.port) add('port', `Port non-standar: ${url.port}`, 'low')
  if (host.length > 30) add('long-host', 'Nama domain relatif panjang', 'low')
  if (!isIpHost(host) && labels.length >= 5) add('subdomains', `Banyak subdomain (${labels.length} tingkat)`, 'low')
  if ((host.match(/-/g)?.length ?? 0) >= 3) add('hyphens', 'Banyak tanda hubung pada domain', 'low')

  const lure = LURE.find((w) => host.includes(w) || path.includes(w))
  if (lure) add('lure', `Kata kunci pengelabuan pada URL: "${lure}"`, 'medium')

  const sensitive = [...url.searchParams.keys()].find((k) => SENSITIVE_PARAMS.has(k.toLowerCase()))
  if (sensitive) add('sensitive-param', `Parameter sensitif pada URL: "${sensitive}"`, 'medium')
  else if (url.search.length > 40) add('long-query', 'Query string panjang', 'low')

  const score = 1 - signals.reduce((p, s) => p * (1 - LEVEL_WEIGHT[s.level]), 1)
  return { input, valid: true, scheme, host, signals, score }
}
