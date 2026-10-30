import type { FieldValue, NormalizedEvent } from '@/core/model'
import { cleanIp, normalizeUser, parseTimestamp, toNumber } from '@/core/ingest/util'

/**
 * Firewall / UTM syslog in key=value form (FortiGate-style, also common on other vendors):
 * `<189>date=2026-11-02 time=09:44:09 devname="FW-SATUAN" srcip=10.20.1.5 dstip=… action="accept"`.
 */

const KV_RE = /([A-Za-z_][\w.-]*)=("((?:[^"\\]|\\.)*)"|[^\s]*)/g

/** Returns key=value pairs, or null when the line does not look like a kv log line. */
export function parseKvLine(line: string): Record<string, string> | null {
  const body = line.replace(/^<\d{1,3}>/, '')
  const out: Record<string, string> = {}
  let count = 0
  for (const m of body.matchAll(KV_RE)) {
    out[m[1]] = m[3] !== undefined ? m[3].replace(/\\(.)/g, '$1') : m[2]
    count++
  }
  return count >= 3 ? out : null
}

/** `+0700` / `+07:00` / `UTC+7` -> `+07:00`; falls back to the given default. */
function isoOffset(tz: string | undefined, fallback: string): string {
  const m = tz && /([+-])(\d{1,2}):?(\d{2})?/.exec(tz)
  if (!m) return fallback
  return `${m[1]}${m[2].padStart(2, '0')}:${m[3] ?? '00'}`
}

export function kvTimestamp(kv: Record<string, string>, defaultOffset: string): number | undefined {
  if (kv.date && kv.time) return parseTimestamp(`${kv.date}T${kv.time}${isoOffset(kv.tz, defaultOffset)}`)
  if (kv.eventtime) {
    const n = Number(kv.eventtime)
    // FortiGate eventtime is in nanoseconds on newer firmware.
    return Number.isFinite(n) ? Math.round(n > 1e17 ? n / 1e6 : n > 1e14 ? n / 1e3 : n > 1e11 ? n : n * 1000) : undefined
  }
  return parseTimestamp(kv.timestamp ?? kv.ts)
}

export function normalizeKv(kv: Record<string, string>, id: string, importId: string, defaultOffset = '+07:00'): NormalizedEvent | null {
  const ts = kvTimestamp(kv, defaultOffset)
  if (ts === undefined) return null
  const fields: Record<string, FieldValue> = { ...kv }
  const src = cleanIp(kv.srcip ?? kv.src)
  const dst = cleanIp(kv.dstip ?? kv.dst)
  const port = toNumber(kv.dstport ?? kv.dpt)
  const sent = toNumber(kv.sentbyte)
  const action = kv.action ?? kv.type ?? 'event'
  const target = kv.hostname ? `${kv.hostname} (${dst ?? '?'})` : dst ?? '?'
  return {
    id,
    ts,
    dataset: 'kv-syslog',
    sourceKind: 'network',
    logsource: { category: 'firewall' },
    host: kv.devname?.toUpperCase(),
    user: normalizeUser(kv.user ?? kv.srcuser),
    srcIp: src,
    dstIp: dst,
    dstPort: port,
    domain: kv.hostname?.toLowerCase(),
    message: `${action} ${src ?? '?'} → ${target}:${port ?? '?'} ${kv.service ?? ''}${sent !== undefined ? ` · keluar ${formatBytes(sent)}` : ''}`.trim(),
    importId,
    fields,
  }
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}
