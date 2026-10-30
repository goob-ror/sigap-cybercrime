import type { FieldValue, NormalizedEvent } from '@/core/model'
import { cleanIp, flatten, parseTimestamp, toNumber, truncate } from '@/core/ingest/util'

/**
 * Zeek logs in TSV (with `#fields` header) or JSON-lines form: conn, dns, http, and Modbus
 * (`modbus` / `modbus_detailed`, the latter in the style of CISA's ICSNPP-Modbus plugin).
 */

/** `conn.log`, `conn.09:00:00-10:00:00.log`, `zeek-dns.log` -> `conn` / `dns`. */
export function zeekPathFromFilename(filename: string): string | undefined {
  const base = filename.split(/[\\/]/).pop()!.toLowerCase().replace(/^zeek[-_]/, '')
  return /^([a-z_]+)/.exec(base)?.[1]
}

/** Guesses the log type from the fields of a JSON record. */
export function zeekPathFromFields(record: Record<string, unknown>): string | undefined {
  if (typeof record._path === 'string') return record._path
  if ('query' in record && 'qtype_name' in record) return 'dns'
  if ('func' in record && ('address' in record || 'values' in record)) return 'modbus_detailed'
  if ('func' in record) return 'modbus'
  if ('method' in record && 'uri' in record) return 'http'
  if ('conn_state' in record || 'proto' in record) return 'conn'
  return undefined
}

type TsvHeader = { fields: string[]; separator: string; setSeparator: string; empty: string; unset: string; path?: string }

/** Parses Zeek TSV into plain records (numbers stay strings; normalization converts them). */
export function* parseZeekTsv(text: string): Generator<{ line: number; record?: Record<string, string>; path?: string; error?: string }> {
  const header: TsvHeader = { fields: [], separator: '\t', setSeparator: ',', empty: '(empty)', unset: '-' }
  let lineNo = 0
  for (const line of text.split(/\r?\n/)) {
    lineNo++
    if (!line.trim()) continue
    if (line.startsWith('#')) {
      const [key, ...rest] = line.slice(1).split(line.startsWith('#separator') ? ' ' : header.separator)
      const value = rest.join(header.separator)
      if (key === 'separator') header.separator = value.replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      else if (key === 'set_separator') header.setSeparator = value
      else if (key === 'empty_field') header.empty = value
      else if (key === 'unset_field') header.unset = value
      else if (key === 'path') header.path = value
      else if (key === 'fields') header.fields = rest
      continue
    }
    if (!header.fields.length) {
      yield { line: lineNo, error: 'Baris data sebelum header #fields' }
      continue
    }
    const values = line.split(header.separator)
    const record: Record<string, string> = {}
    header.fields.forEach((name, i) => {
      const value = values[i]
      if (value === undefined || value === header.unset) return
      record[name] = value === header.empty ? '' : value
    })
    yield { line: lineNo, record, path: header.path }
  }
}

function str(value: unknown): string | undefined {
  return value === null || value === undefined || value === '' ? undefined : String(value)
}

export function normalizeZeek(record: Record<string, unknown>, path: string, id: string, importId: string): NormalizedEvent | null {
  const ts = parseTimestamp(record.ts)
  if (ts === undefined) return null
  // JSON logs may nest `id: {orig_h…}`; flatten gives `id.orig_h` either way, matching Sigma field names.
  const fields: Record<string, FieldValue> = flatten(record)
  const orig = cleanIp(fields['id.orig_h'])
  const resp = cleanIp(fields['id.resp_h'])
  const respPort = toNumber(fields['id.resp_p'])
  const base = { id, ts, srcIp: orig, dstIp: resp, dstPort: respPort, importId, fields, logsource: { product: 'zeek', service: path } }

  switch (path) {
    case 'dns': {
      const query = str(fields.query)
      return { ...base, dataset: 'zeek.dns', sourceKind: 'network', domain: query?.toLowerCase(), message: `DNS ${query ?? '?'} → ${str(fields.answers) ?? '(tanpa jawaban)'}` }
    }
    case 'http': {
      const host = str(fields.host)
      return { ...base, dataset: 'zeek.http', sourceKind: 'network', domain: host?.toLowerCase(), url: host ? `http://${host}${str(fields.uri) ?? ''}` : undefined, message: truncate(`HTTP ${str(fields.method) ?? ''} ${host ?? ''}${str(fields.uri) ?? ''}`) }
    }
    case 'modbus':
    case 'modbus_detailed': {
      const func = str(fields.func)
      const unitId = toNumber(fields.unit ?? fields.unit_id)
      const register = toNumber(fields.address)
      const value = toNumber(str(fields.values)?.split(',')[0])
      const values = str(fields.values)
      const detail = register !== undefined ? ` alamat ${register}${values !== undefined ? ` = ${values}` : ''}` : ''
      return {
        ...base,
        dataset: `zeek.${path}`,
        sourceKind: 'ot',
        ot: { protocol: 'modbus', unitId, func, register, value },
        message: `Modbus ${func ?? '?'} unit ${unitId ?? '?'}${detail} (${orig ?? '?'} → ${resp ?? '?'})`,
      }
    }
    case 'conn': {
      const bytes = toNumber(fields.orig_bytes)
      return {
        ...base,
        dataset: 'zeek.conn',
        sourceKind: respPort === 502 ? 'ot' : 'network',
        message: `${str(fields.proto) ?? '?'} ${orig ?? '?'} → ${resp ?? '?'}:${respPort ?? '?'} ${str(fields.service) ?? ''}${bytes !== undefined ? ` (${bytes} B keluar)` : ''}`.trim(),
      }
    }
    default:
      return { ...base, dataset: `zeek.${path}`, sourceKind: 'network', message: `Zeek ${path}: ${orig ?? '?'} → ${resp ?? '?'}` }
  }
}
