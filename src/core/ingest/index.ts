import type { NormalizedEvent } from '@/core/model'
import { lines } from '@/core/ingest/util'
import { normalizeWinEvent } from '@/core/ingest/winevent'
import { isWinEventRecord } from '@/core/ingest/winexport'
import { normalizeZeek, parseZeekTsv, zeekPathFromFields, zeekPathFromFilename } from '@/core/ingest/zeek'
import { normalizeKv, parseKvLine } from '@/core/ingest/kv'
import { hostFromFilename, isIisHeader, normalizeAccess, parseAccessLine, parseIisLog } from '@/core/ingest/weblog'
import { normalizeSyslog, parseSyslogLine, syslogHasZone } from '@/core/ingest/syslog'
import { isFirewallLine, parseFirewallLine } from '@/core/ingest/firewall'
import { isAuditLine, parseAuditLog } from '@/core/ingest/auditd'

export type LogFormat = 'winevent-jsonl' | 'zeek-tsv' | 'zeek-json' | 'kv-syslog' | 'firewall-syslog' | 'web-access' | 'iis-w3c' | 'linux-syslog' | 'journald-json' | 'auditd' | 'unknown'

export const FORMAT_LABEL: Record<LogFormat, string> = {
  'winevent-jsonl': 'Windows Event Log',
  'zeek-tsv': 'Zeek (TSV)',
  'zeek-json': 'Zeek (JSON)',
  'kv-syslog': 'Firewall syslog (key=value)',
  'firewall-syslog': 'Firewall/router (MikroTik, pfSense, Cisco)',
  'web-access': 'Access log web (Apache/Nginx/cPanel)',
  'iis-w3c': 'Access log IIS',
  'linux-syslog': 'Log auth/syslog Linux',
  'journald-json': 'Log Linux (journalctl JSON)',
  auditd: 'Linux auditd',
  unknown: 'Tidak dikenali',
}

type JsonRecord = Record<string, unknown>

/** Lines looked at to decide a file's format. */
const SNIFF_LINES = 50
const SNIFF_BYTES = 256 * 1024

/** Format of one JSON record. */
function sniffRecord(json: JsonRecord): LogFormat {
  if (isWinEventRecord(json)) return 'winevent-jsonl'
  if ('__REALTIME_TIMESTAMP' in json) return 'journald-json'
  if ('id.orig_h' in json || ('uid' in json && 'ts' in json) || (typeof json.id === 'object' && 'ts' in json)) return 'zeek-json'
  return 'unknown'
}

/**
 * A file that is one JSON document: an array of records (`ConvertTo-Json` of several events) or a
 * single record (`ConvertTo-Json` of one event). Returns null for JSON-lines and other text.
 */
function wholeJson(text: string): JsonRecord[] | null {
  const head = text.trimStart()
  if (!head.startsWith('[') && !head.startsWith('{')) return null
  try {
    const value: unknown = JSON.parse(head)
    const items = Array.isArray(value) ? value : [value]
    return items.every((x) => x && typeof x === 'object' && !Array.isArray(x)) ? (items as JsonRecord[]) : null
  } catch {
    return null
  }
}

function sniffLine(line: string): LogFormat {
  if (line.trimStart().startsWith('{')) {
    try {
      const value: unknown = JSON.parse(line)
      return value && typeof value === 'object' && !Array.isArray(value) ? sniffRecord(value as JsonRecord) : 'unknown'
    } catch {
      return 'unknown'
    }
  }
  // Before key=value, which an auditd line or a sudo line (`TTY=… ; USER=… ; COMMAND=…`) also resembles.
  if (parseAccessLine(line)) return 'web-access'
  if (isAuditLine(line)) return 'auditd'
  if (isFirewallLine(line)) return 'firewall-syslog'
  if (parseSyslogLine(line)) return 'linux-syslog'
  if (parseKvLine(line)) return 'kv-syslog'
  return 'unknown'
}

/**
 * Decides the format from the first lines of a file, by majority. One line alone is not enough: log
 * rotation or a copy can leave a cut-off first line, and that must not cost the operator the whole file.
 */
export function sniffFormat(text: string): LogFormat {
  const records = wholeJson(text)
  if (records) return records.length ? sniffRecord(records[0]) : 'unknown'
  const head = text.slice(0, SNIFF_BYTES).trimStart()
  if (head.startsWith('#separator') || head.startsWith('#fields')) return 'zeek-tsv'
  if (isIisHeader(head)) return 'iis-w3c'
  const votes = new Map<LogFormat, number>()
  let seen = 0
  for (const [, line] of lines(head)) {
    const format = sniffLine(line)
    if (format !== 'unknown') votes.set(format, (votes.get(format) ?? 0) + 1)
    if (++seen >= SNIFF_LINES) break
  }
  return [...votes].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown'
}

export type IngestError = { line: number; message: string }
export type IngestResult = {
  format: LogFormat
  events: NormalizedEvent[]
  errors: IngestError[]
  errorCount: number
  /** The zone given to timestamps that carry none, when any were found. */
  assumedOffset?: string
}

export type IngestOptions = {
  /** Applies to timestamps without a zone (firewall, classic syslog). */
  defaultTzOffset?: string
  /** Applies to classic syslog, which omits the year. */
  defaultYear?: number
  /** Timestamps without a year are not allowed to fall after this. */
  now?: number
}

const MAX_REPORTED_ERRORS = 50
const WIB = '+07:00'
const UNKNOWN_MESSAGE = 'Format berkas tidak dikenali. Didukung: Windows Event (.evtx, collector SIGAP, Get-WinEvent, Winlogbeat, evtx_dump, EvtxECmd), Zeek TSV/JSON, firewall (FortiGate key=value, MikroTik, pfSense, Cisco ASA), access log web (Apache/Nginx/cPanel/Plesk/IIS), log auth/syslog Linux, journalctl -o json, dan auditd.'

/** `__REALTIME_TIMESTAMP` is microseconds; `MESSAGE` is an array of bytes when it holds non-text. */
function journaldLine(r: JsonRecord) {
  const micros = Number(r.__REALTIME_TIMESTAMP)
  if (!Number.isFinite(micros)) return null
  const message = Array.isArray(r.MESSAGE) ? String.fromCharCode(...(r.MESSAGE as number[])) : String(r.MESSAGE ?? '')
  return { iso: new Date(micros / 1000).toISOString(), hostname: String(r._HOSTNAME ?? '-'), program: String(r.SYSLOG_IDENTIFIER ?? r._COMM ?? '-'), pid: Number(r.SYSLOG_PID ?? r._PID) || undefined, message }
}

/**
 * Parses and normalizes one log file. Event ids are `${importId}:${line}` so re-imports stay stable.
 */
export function ingestText(text: string, filename: string, importId: string, opts: IngestOptions = {}): IngestResult {
  const records = wholeJson(text)
  const format = records ? (records.length ? sniffRecord(records[0]) : 'unknown') : sniffFormat(text)
  const offset = opts.defaultTzOffset ?? WIB
  const now = opts.now ?? Date.now()
  const year = opts.defaultYear ?? new Date(now).getFullYear()
  const events: NormalizedEvent[] = []
  const errors: IngestError[] = []
  let errorCount = 0
  let assumed = false
  const fail = (line: number, message: string) => {
    errorCount++
    if (errors.length < MAX_REPORTED_ERRORS) errors.push({ line, message })
  }
  const push = (event: NormalizedEvent | null, line: number, reason: string) => (event ? events.push(event) : fail(line, reason))
  const eventId = (line: number) => `${importId}:${line}`
  const done = (): IngestResult => ({ format, events, errors, errorCount, ...(assumed ? { assumedOffset: offset } : {}) })

  // One JSON document: entries are numbered from 1 in place of line numbers.
  const jsonRecords: Iterable<[number, JsonRecord | null]> = records
    ? records.map((r, i): [number, JsonRecord] => [i + 1, r])
    : (function* () {
        for (const [lineNo, line] of lines(text)) {
          try {
            yield [lineNo, JSON.parse(line) as JsonRecord]
          } catch {
            yield [lineNo, null]
          }
        }
      })()

  switch (format) {
    case 'winevent-jsonl':
    case 'zeek-json':
    case 'journald-json':
      for (const [lineNo, record] of jsonRecords) {
        if (!record) {
          fail(lineNo, 'JSON tidak valid')
          continue
        }
        if (format === 'winevent-jsonl') {
          push(normalizeWinEvent(record, eventId(lineNo), importId), lineNo, 'EventID atau waktu tidak ditemukan')
        } else if (format === 'journald-json') {
          const entry = journaldLine(record)
          push(entry && normalizeSyslog(entry, eventId(lineNo), importId, year, offset, now), lineNo, 'Waktu tidak valid')
        } else {
          const path = zeekPathFromFields(record) ?? zeekPathFromFilename(filename) ?? 'unknown'
          push(normalizeZeek(record, path, eventId(lineNo), importId), lineNo, 'Kolom ts tidak valid')
        }
      }
      break
    case 'zeek-tsv':
      for (const row of parseZeekTsv(text)) {
        if (row.error || !row.record) {
          fail(row.line, row.error ?? 'Baris tidak terbaca')
          continue
        }
        const path = row.path ?? zeekPathFromFilename(filename) ?? 'unknown'
        push(normalizeZeek(row.record, path, eventId(row.line), importId), row.line, 'Kolom ts tidak valid')
      }
      break
    case 'kv-syslog':
      for (const [lineNo, line] of lines(text)) {
        const kv = parseKvLine(line)
        if (!kv) {
          fail(lineNo, 'Bukan format key=value')
          continue
        }
        if (kv.date && kv.time && !kv.tz) assumed = true
        push(normalizeKv(kv, eventId(lineNo), importId, offset), lineNo, 'Waktu tidak ditemukan (date/time/eventtime)')
      }
      break
    case 'firewall-syslog':
      for (const [lineNo, line] of lines(text)) {
        const kv = parseFirewallLine(line, { year, offset, now })
        if (!kv) {
          fail(lineNo, 'Bukan baris firewall yang dikenali')
          continue
        }
        if (kv.date && !kv.tz) assumed = true
        push(normalizeKv(kv, eventId(lineNo), importId, offset), lineNo, 'Waktu tidak ditemukan pada baris')
      }
      break
    case 'web-access': {
      const host = hostFromFilename(filename)
      for (const [lineNo, line] of lines(text)) {
        if (line.startsWith('#')) continue
        const access = parseAccessLine(line)
        if (!access) {
          fail(lineNo, 'Bukan baris access log (combined/common)')
          continue
        }
        push(normalizeAccess(access, eventId(lineNo), importId, host), lineNo, 'Waktu tidak valid')
      }
      break
    }
    case 'iis-w3c': {
      const parsed = parseIisLog(text, filename, importId)
      events.push(...parsed.events)
      parsed.errors.forEach((e) => fail(e.line, e.message))
      break
    }
    case 'linux-syslog':
      for (const [lineNo, line] of lines(text)) {
        const entry = parseSyslogLine(line)
        if (!entry) {
          fail(lineNo, 'Bukan baris syslog')
          continue
        }
        if (!syslogHasZone(entry)) assumed = true
        push(normalizeSyslog(entry, eventId(lineNo), importId, year, offset, now), lineNo, 'Waktu tidak valid')
      }
      break
    case 'auditd': {
      const parsed = parseAuditLog(text, hostFromFilename(filename), importId)
      events.push(...parsed.events)
      parsed.errors.forEach((e) => fail(e.line, e.message))
      break
    }
    case 'unknown':
      fail(1, UNKNOWN_MESSAGE)
      break
  }
  return done()
}
