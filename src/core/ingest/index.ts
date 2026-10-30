import type { NormalizedEvent } from '@/core/model'
import { lines } from '@/core/ingest/util'
import { normalizeWinEvent } from '@/core/ingest/winevent'
import { normalizeZeek, parseZeekTsv, zeekPathFromFields, zeekPathFromFilename } from '@/core/ingest/zeek'
import { normalizeKv, parseKvLine } from '@/core/ingest/kv'

export type LogFormat = 'winevent-jsonl' | 'zeek-tsv' | 'zeek-json' | 'kv-syslog' | 'unknown'

export const FORMAT_LABEL: Record<LogFormat, string> = {
  'winevent-jsonl': 'Windows Event Log (JSON)',
  'zeek-tsv': 'Zeek (TSV)',
  'zeek-json': 'Zeek (JSON)',
  'kv-syslog': 'Firewall syslog (key=value)',
  unknown: 'Tidak dikenali',
}

function firstJson(text: string): Record<string, unknown> | null {
  for (const [, line] of lines(text)) {
    try {
      const value = JSON.parse(line)
      return value && typeof value === 'object' && !Array.isArray(value) ? value : null
    } catch {
      return null
    }
  }
  return null
}

/** Decides the format from the first meaningful lines of a file. */
export function sniffFormat(text: string): LogFormat {
  const head = text.slice(0, 4096).trimStart()
  if (head.startsWith('#separator') || head.startsWith('#fields')) return 'zeek-tsv'
  const json = firstJson(head)
  if (json) {
    if ('EventData' in json || (('EventID' in json || 'Id' in json) && ('Channel' in json || 'Computer' in json || 'LogName' in json))) return 'winevent-jsonl'
    if ('id.orig_h' in json || ('uid' in json && 'ts' in json) || (typeof json.id === 'object' && 'ts' in json)) return 'zeek-json'
    return 'unknown'
  }
  const firstLine = head.split(/\r?\n/, 1)[0]
  if (parseKvLine(firstLine)) return 'kv-syslog'
  return 'unknown'
}

export type IngestError = { line: number; message: string }
export type IngestResult = { format: LogFormat; events: NormalizedEvent[]; errors: IngestError[]; errorCount: number }

const MAX_REPORTED_ERRORS = 50

/** Parses and normalizes one log file. Event ids are `${importId}:${line}` so re-imports stay stable. */
export function ingestText(text: string, filename: string, importId: string, opts: { defaultTzOffset?: string } = {}): IngestResult {
  const format = sniffFormat(text)
  const events: NormalizedEvent[] = []
  const errors: IngestError[] = []
  let errorCount = 0
  const fail = (line: number, message: string) => {
    errorCount++
    if (errors.length < MAX_REPORTED_ERRORS) errors.push({ line, message })
  }
  const push = (event: NormalizedEvent | null, line: number, reason: string) => (event ? events.push(event) : fail(line, reason))
  const eventId = (line: number) => `${importId}:${line}`

  switch (format) {
    case 'winevent-jsonl':
    case 'zeek-json':
      for (const [lineNo, line] of lines(text)) {
        let record: Record<string, unknown>
        try {
          record = JSON.parse(line)
        } catch {
          fail(lineNo, 'JSON tidak valid')
          continue
        }
        if (format === 'winevent-jsonl') {
          push(normalizeWinEvent(record, eventId(lineNo), importId), lineNo, 'EventID atau waktu tidak ditemukan')
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
        push(normalizeKv(kv, eventId(lineNo), importId, opts.defaultTzOffset), lineNo, 'Waktu tidak ditemukan (date/time/eventtime)')
      }
      break
    case 'unknown':
      fail(1, 'Format berkas tidak dikenali. Didukung: Windows Event JSON, Zeek TSV/JSON, syslog key=value.')
      break
  }
  return { format, events, errors, errorCount }
}
