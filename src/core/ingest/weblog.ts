import type { FieldValue, NormalizedEvent } from '@/core/model'
import { cleanIp, normalizeUser, toNumber, truncate } from '@/core/ingest/util'

/**
 * Web server access logs in the "combined" family, shared by Apache, Nginx, LiteSpeed, cPanel
 * (domlogs and "Raw Access" downloads) and Plesk:
 *   `203.0.113.45 - - [02/Nov/2026:13:05:11 +0700] "GET /a.php?id=1 HTTP/1.1" 200 512 "-" "UA"`
 * Also "common" (no referer / user-agent) and Apache "vhost_combined" (`host:port` first).
 *
 * Fields follow the Sigma *webserver* taxonomy (`c-ip`, `cs-method`, `c-uri`, `cs-uri-stem`,
 * `cs-uri-query`, `sc-status`, `cs-user-agent`, …). `c-uri` is URL-decoded — twice, because
 * double encoding is a common evasion — so rules match readable payloads; `c-uri-raw` keeps the
 * request target exactly as logged.
 */

export type AccessLine = {
  vhost?: string
  client: string
  user: string
  time: string
  request: string
  status?: number
  bytes?: number
  referer?: string
  agent?: string
}

// vhost cannot contain ':' — so an IPv6 client address is never mistaken for `vhost:port`.
const ACCESS_RE = /^(?:([^\s:]+):\d+ )?(\S+) \S+ (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/

const MONTHS: Record<string, string> = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06', jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' }

const dash = (v: string | undefined) => (v === undefined || v === '-' || v === '' ? undefined : v)

export function parseAccessLine(line: string): AccessLine | null {
  const m = ACCESS_RE.exec(line)
  if (!m) return null
  return {
    vhost: m[1],
    client: m[2],
    user: m[3],
    time: m[4],
    request: m[5],
    status: toNumber(dash(m[6])),
    bytes: toNumber(dash(m[7])),
    referer: dash(m[8]),
    agent: dash(m[9]),
  }
}

/** `02/Nov/2026:13:05:11 +0700` -> epoch ms. */
export function clfTime(text: string): number | undefined {
  const m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3})\d*)?\s*([+-])(\d{2}):?(\d{2})$/.exec(text.trim())
  const month = m && MONTHS[m[2].toLowerCase()]
  if (!m || !month) return undefined
  const t = Date.parse(`${m[3]}-${month}-${m[1].padStart(2, '0')}T${m[4]}:${m[5]}:${m[6]}${m[7] ? `.${m[7].padEnd(3, '0')}` : ''}${m[8]}${m[9]}:${m[10]}`)
  return Number.isNaN(t) ? undefined : t
}

function decodeOnce(text: string, plusIsSpace: boolean): string {
  const s = plusIsSpace ? text.replace(/\+/g, ' ') : text
  try {
    return decodeURIComponent(s)
  } catch {
    // Malformed sequences (common in attack traffic): decode the valid %XX bytes only.
    return s.replace(/%([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
  }
}

/** URL-decodes up to twice; `+` is a space only in the query string. */
export function decodeUri(text: string, plusIsSpace = false): string {
  const once = decodeOnce(text, plusIsSpace)
  return /%[0-9a-f]{2}/i.test(once) ? decodeOnce(once, plusIsSpace) : once
}

// Tokens that name the log, not the machine: dropped when deriving a host from a file name.
const NOISE = new Set(['access', 'error', 'ssl', 'ssl_log', 'log', 'logs', 'nginx', 'apache', 'apache2', 'httpd', 'litespeed', 'lsws', 'auth', 'secure', 'syslog', 'messages', 'domlogs', 'other', 'vhosts', 'bytes'])
const MONTH_TOKEN = /^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)$/i
const DOMAIN_RE = /([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,24})(?=$|[-_])/i

/**
 * Access logs do not name the server, so the host comes from the file name:
 * `web-satuan-01-nginx-access.log` -> `WEB-SATUAN-01`, cPanel `satuan-contoh.example-Nov-2026.gz`
 * -> `satuan-contoh.example`, a bare `access.log` -> undefined. SIGAP's collectors name files
 * `<host>-<log>` so the host is always recoverable.
 */
export function hostFromFilename(filename: string): string | undefined {
  let stem = (filename.split(/[\\/]/).pop() ?? filename).replace(/(\.(gz|log|txt|\d+))+$/i, '')
  // Strip trailing noise like `.access`, `-ssl_log`, `_error`.
  for (let prev = ''; prev !== stem; ) {
    prev = stem
    const m = /^(.*?)[._-]([a-z_0-9]+)$/i.exec(stem)
    if (m && (NOISE.has(m[2].toLowerCase()) || MONTH_TOKEN.test(m[2]) || /^(19|20)\d{2}$/.test(m[2]) || /^\d{8}$/.test(m[2]))) stem = m[1]
  }
  const domain = DOMAIN_RE.exec(stem)
  if (domain && /[a-z]/i.test(domain[1].split('.').pop()!)) return domain[1].toLowerCase()
  const parts = stem.split(/[-_]+/).filter((p) => p && !NOISE.has(p.toLowerCase()) && !MONTH_TOKEN.test(p) && !/^(19|20)\d{2}$/.test(p) && !/^\d{8}$/.test(p))
  return parts.length ? parts.join('-').toUpperCase() : undefined
}

export function normalizeAccess(a: AccessLine, id: string, importId: string, host: string | undefined): NormalizedEvent | null {
  const ts = clfTime(a.time)
  if (ts === undefined) return null
  const parts = a.request.split(' ')
  const hasMethod = parts.length >= 2 && /^[A-Z]{3,10}$/.test(parts[0])
  const method = hasMethod ? parts[0] : '-'
  const protocol = hasMethod && /^HTTP\//.test(parts.at(-1)!) && parts.length >= 3 ? parts.at(-1)! : undefined
  const target = hasMethod ? parts.slice(1, protocol ? -1 : undefined).join(' ') : a.request
  const q = target.indexOf('?')
  const stem = decodeUri(q >= 0 ? target.slice(0, q) : target)
  const query = q >= 0 ? decodeUri(target.slice(q + 1), true) : ''
  const uri = query ? `${stem}?${query}` : stem
  const fields: Record<string, FieldValue> = {
    'c-ip': a.client,
    'cs-method': method,
    'c-uri': uri,
    'cs-uri-stem': stem,
    'cs-uri-query': query || null,
    'c-uri-raw': target,
    'sc-status': a.status ?? null,
    'sc-bytes': a.bytes ?? null,
    'cs-referer': a.referer ?? null,
    'cs-user-agent': a.agent ?? null,
    'cs-username': dash(a.user) ?? null,
    'cs-version': protocol ?? null,
    'cs-host': a.vhost ?? null,
  }
  return {
    id,
    ts,
    dataset: 'web.access',
    sourceKind: 'server',
    logsource: { category: 'webserver' },
    host,
    user: normalizeUser(a.user),
    srcIp: cleanIp(a.client),
    url: uri,
    // The site's own name is not an indicator, so `domain` stays empty (it would land on a blocklist).
    message: `${method} ${truncate(uri, 140)} → ${a.status ?? '-'}`,
    importId,
    fields,
  }
}
