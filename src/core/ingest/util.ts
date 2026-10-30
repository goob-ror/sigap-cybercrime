import type { FieldValue } from '@/core/model'

/** Last path segment of a Windows or POSIX path: `C:\Windows\cmd.exe` -> `cmd.exe`. */
export function basename(path: string | undefined): string | undefined {
  if (!path) return undefined
  return path.split(/[\\/]/).pop() || undefined
}

/** `SATUAN\serka.adi` or `serka.adi@satuan` -> `serka.adi`; placeholders become undefined. */
export function normalizeUser(user: unknown): string | undefined {
  if (typeof user !== 'string') return undefined
  const trimmed = user.trim()
  if (!trimmed || trimmed === '-' || trimmed.endsWith('$')) return undefined
  return trimmed.split('\\').pop()!.split('@')[0].toLowerCase()
}

/** Returns an IP string, or undefined for empty/placeholder values. */
export function cleanIp(ip: unknown): string | undefined {
  if (typeof ip !== 'string' && typeof ip !== 'number') return undefined
  const text = String(ip).trim()
  if (!text || text === '-' || text === '::1' || text === '127.0.0.1' || text === '0.0.0.0') return undefined
  return text.replace(/^::ffff:/, '')
}

export function toNumber(value: unknown): number | undefined {
  if (value === null || value === undefined || value === '') return undefined
  const n = Number(value)
  return Number.isFinite(n) ? n : undefined
}

/** Flattens nested objects into dotted keys and arrays into comma-joined strings. */
export function flatten(input: Record<string, unknown>, prefix = '', out: Record<string, FieldValue> = {}): Record<string, FieldValue> {
  for (const [key, value] of Object.entries(input)) {
    const name = prefix ? `${prefix}.${key}` : key
    if (value === null || value === undefined) out[name] = null
    else if (Array.isArray(value)) out[name] = value.map((v) => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(',')
    else if (typeof value === 'object') flatten(value as Record<string, unknown>, name, out)
    else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') out[name] = value
    else out[name] = String(value)
  }
  return out
}

export function truncate(text: string, max = 160): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** Parses ISO 8601, `/Date(ms)/` (PowerShell JSON) and epoch seconds/milliseconds. */
export function parseTimestamp(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? (value > 1e12 ? value : Math.round(value * 1000)) : undefined
  if (typeof value !== 'string' || !value.trim()) return undefined
  const ms = /\/Date\((-?\d+)\)\//.exec(value)
  if (ms) return Number(ms[1])
  if (/^\d+(\.\d+)?$/.test(value)) return parseTimestamp(Number(value))
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? undefined : parsed
}

/** Splits text into non-empty lines, keeping 1-based line numbers. */
export function* lines(text: string): Generator<[number, string]> {
  let lineNo = 0
  for (const line of text.split(/\r?\n/)) {
    lineNo++
    if (line.trim()) yield [lineNo, line]
  }
}
