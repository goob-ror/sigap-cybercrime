import { describe, expect, it } from 'vitest'
import { logPredicate, matchesLogTerms, parseLogQuery, wibInputToMs, type LogFilter } from '@/core/logQuery'
import type { NormalizedEvent } from '@/core/model'

const EVENT: NormalizedEvent = {
  id: 'imp:7',
  ts: Date.UTC(2026, 10, 2, 6, 5),
  dataset: 'winevent',
  sourceKind: 'endpoint',
  logsource: { product: 'windows', service: 'security' },
  host: 'WS-MIN-03',
  user: 'sertu.rina',
  srcIp: '10.20.1.44',
  dstIp: '203.0.113.66',
  dstPort: 443,
  process: { name: 'powershell.exe', cmdline: 'powershell.exe -enc SQBFAFgA' },
  message: 'Logon gagal sertu.rina',
  importId: 'imp',
  fields: { EventID: 4688, Image: 'C:\\Windows\\System32\\cmd.exe', 'id.orig_h': '10.20.1.44', Note: null },
}

const matches = (query: string, event = EVENT) => matchesLogTerms(event, parseLogQuery(query))
const FILTER: LogFilter = { terms: [], kind: null, dataset: null, host: null, from: null, to: null, only: null }

describe('parseLogQuery', () => {
  it('splits on spaces and keeps quoted phrases together', () => {
    expect(parseLogQuery('gagal "logon gagal" host:"WS 03"')).toEqual([
      { raw: 'gagal', value: 'gagal' },
      { raw: 'logon gagal', value: 'logon gagal' },
      { raw: 'host:"ws 03"', field: 'host', value: 'ws 03' },
    ])
  })

  it('ignores empty input and empty quotes', () => {
    expect(parseLogQuery('   ')).toEqual([])
    expect(parseLogQuery('"" host:""')).toEqual([])
  })
})

describe('matchesLogTerms', () => {
  it('finds free text across normalized and original fields, ignoring case', () => {
    expect(matches('LOGON')).toBe(true)
    expect(matches('system32')).toBe(true)
    expect(matches('tidak-ada')).toBe(false)
  })

  it('requires every part to match', () => {
    expect(matches('logon rina')).toBe(true)
    expect(matches('logon tidak-ada')).toBe(false)
  })

  it('supports shortcuts and original field names, ignoring case', () => {
    expect(matches('host:ws-min')).toBe(true)
    expect(matches('host:lain')).toBe(false)
    expect(matches('ip:203.0.113.66')).toBe(true)
    expect(matches('ip:10.20.1.44')).toBe(true)
    expect(matches('eventid:4688')).toBe(true)
    expect(matches('id.orig_h:10.20.1.44')).toBe(true)
  })

  it('matches numbers exactly', () => {
    expect(matches('EventID:46')).toBe(false)
    expect(matches('port:443')).toBe(true)
    expect(matches('port:44')).toBe(false)
  })

  it('keeps a value with a colon as free text when the name is not a column', () => {
    expect(matches('C:\\Windows')).toBe(true)
    expect(matches('10.20.1.44:443')).toBe(false)
    expect(matches('http://tidak-ada')).toBe(false)
  })

  it('does not fall back to free text for a known column that is empty', () => {
    expect(matches('domain:logon')).toBe(false)
    expect(matches('Note:apa')).toBe(false)
  })
})

describe('logPredicate', () => {
  it('is null when nothing needs checking event by event', () => {
    expect(logPredicate(FILTER)).toBeNull()
    expect(logPredicate({ ...FILTER, from: 1, to: 2 })).toBeNull()
  })

  it('combines every filter', () => {
    const check = (change: Partial<LogFilter>) => logPredicate({ ...FILTER, ...change })!(EVENT)
    expect(check({ kind: 'endpoint' })).toBe(true)
    expect(check({ kind: 'ot' })).toBe(false)
    expect(check({ dataset: 'winevent' })).toBe(true)
    expect(check({ dataset: 'zeek.conn' })).toBe(false)
    expect(check({ host: 'WS-MIN-03' })).toBe(true)
    expect(check({ host: 'WS-LAIN' })).toBe(false)
    expect(check({ only: new Set(['imp:7']) })).toBe(true)
    expect(check({ only: new Set() })).toBe(false)
    expect(check({ kind: 'endpoint', terms: parseLogQuery('tidak-ada') })).toBe(false)
  })
})

describe('wibInputToMs', () => {
  it('reads the input as WIB', () => {
    expect(wibInputToMs('2026-11-02T13:05')).toBe(Date.UTC(2026, 10, 2, 6, 5))
    expect(wibInputToMs('2026-11-02T13:05:30')).toBe(Date.UTC(2026, 10, 2, 6, 5, 30))
  })

  it('covers the whole minute for an end time', () => {
    expect(wibInputToMs('2026-11-02T13:05', true)).toBe(Date.UTC(2026, 10, 2, 6, 5, 59, 999))
  })

  it('returns null when empty or invalid', () => {
    expect(wibInputToMs('')).toBeNull()
    expect(wibInputToMs('bukan-waktu')).toBeNull()
  })
})
