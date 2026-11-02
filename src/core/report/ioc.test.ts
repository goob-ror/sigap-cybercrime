import { beforeAll, describe, expect, it } from 'vitest'
import type { Detection, EntityType, Incident, IncidentEntity, Level, NormalizedEvent } from '@/core/model'
import { isExternalIp } from '@/core/net'
import { allIocs, blocklistFiles, incidentIocs, isExternalDomain, isIndicator, type BlocklistMeta } from '@/core/report/ioc'
import { ingestText } from '@/core/ingest'
import { runDetections } from '@/core/detect/engine'
import { correlate } from '@/core/correlate/correlate'
import { generateScenario } from '@/data/scenario/generate'
import { loadRulePack } from '@/data/rules'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

// Synthetic, fictional indicators only: RFC 5737 TEST-NET, RFC 3849 IPv6 (2001:db8::/32),
// .example domains, repeated-byte hashes.
const T0 = Date.UTC(2026, 10, 2, 2, 0, 0)
const MIN = 60_000
const HASH_A = 'ab'.repeat(32)
const META: BlocklistMeta = { unit: 'Satuan Uji', scope: 'Kasus KSS-0001', generatedAt: T0, actor: 'operator.satuan' }

function det(id: string, title: string): Detection {
  return { id, ruleId: `rule-${id}`, title, level: 'high' as Level, attack: [], eventIds: [], matched: {}, ts: T0 }
}

function ind(type: EntityType, value: string, detectionIds: string[], opts: Partial<Pick<IncidentEntity, 'firstSeen' | 'common' | 'actor' | 'aliases'>> = {}): IncidentEntity {
  return { type, value, key: `${type}:${value}`, aliases: opts.aliases ?? [], detectionIds, firstSeen: opts.firstSeen ?? T0, actor: opts.actor ?? false, common: opts.common ?? false }
}

function inc(id: string, entities: IncidentEntity[]): Incident {
  return { id, title: `Insiden ${id}`, path: [], level: 'high', detectionIds: entities.flatMap((e) => e.detectionIds), ruleIds: [], entities, relations: [], tactics: [], sourceKinds: [], score: 0.5, scoreBreakdown: [], firstSeen: T0, lastSeen: T0 }
}

describe('isExternalIp', () => {
  it('accepts public IPv4 and rejects private/loopback/link-local', () => {
    expect(isExternalIp('203.0.113.66')).toBe(true)
    expect(isExternalIp('198.51.100.23')).toBe(true)
    expect(isExternalIp('10.20.4.13')).toBe(false)
    expect(isExternalIp('192.168.1.1')).toBe(false)
    expect(isExternalIp('127.0.0.1')).toBe(false)
    expect(isExternalIp('169.254.1.1')).toBe(false)
    expect(isExternalIp('not-an-ip')).toBe(false)
    expect(isExternalIp('')).toBe(false)
  })

  it('accepts only global-unicast IPv6 (2000::/3); rejects internal, mapped and malformed', () => {
    expect(isExternalIp('2001:db8::1')).toBe(true) // RFC 3849 documentation range, global unicast
    expect(isExternalIp('3fff::1')).toBe(true)
    expect(isExternalIp('::1')).toBe(false) // loopback
    expect(isExternalIp('fe80::1')).toBe(false) // link-local
    expect(isExternalIp('fd00::1234')).toBe(false) // unique-local
    expect(isExternalIp('fc00::1')).toBe(false)
    expect(isExternalIp('::ffff:7f00:1')).toBe(false) // IPv4-mapped loopback
    expect(isExternalIp(':')).toBe(false) // malformed
  })
})

describe('isExternalDomain', () => {
  it('accepts public domains and rejects internal / non-routable names', () => {
    expect(isExternalDomain('cdn-tukin.example')).toBe(true)
    expect(isExternalDomain('files-drop.example')).toBe(true)
    expect(isExternalDomain('portal.satuan.local')).toBe(false) // internal AD suffix
    expect(isExternalDomain('srv-satuan-01.internal')).toBe(false)
    expect(isExternalDomain('host.corp')).toBe(false)
    expect(isExternalDomain('wpad')).toBe(false) // single-label hostname
    expect(isExternalDomain('')).toBe(false)
  })
})

describe('isIndicator', () => {
  it('keeps external IPs, domains and hashes; drops internal/common/accounts/files/hosts', () => {
    expect(isIndicator(ind('ip', '203.0.113.66', []))).toBe(true)
    expect(isIndicator(ind('domain', 'cdn-tukin.example', []))).toBe(true)
    expect(isIndicator(ind('hash', HASH_A, []))).toBe(true)
    expect(isIndicator(ind('ip', '10.20.4.13', []))).toBe(false) // internal
    expect(isIndicator(ind('ip', '203.0.113.9', [], { common: true }))).toBe(false) // common infra
    expect(isIndicator(ind('user', 'sertu.rina', []))).toBe(false)
    expect(isIndicator(ind('file', 'tukin.docm', []))).toBe(false)
    expect(isIndicator(ind('host', 'WS-MIN-03', []))).toBe(false)
    expect(isIndicator(ind('device', 'PLC-GENSET-01', []))).toBe(false)
    expect(isIndicator(ind('domain', 'portal.satuan.local', []))).toBe(false) // internal domain
  })
})

describe('incidentIocs', () => {
  const d1 = det('d1', 'Koneksi C2')
  const d2 = det('d2', 'Unduhan berbahaya')
  const detectionsById = new Map([d1, d2].map((d) => [d.id, d]))
  const entities = [
    ind('ip', '203.0.113.66', ['d1']),
    ind('domain', 'CDN-Tukin.Example', ['d1', 'd2']), // mixed case -> normalized lower
    ind('hash', HASH_A, ['d2']),
    ind('ip', '10.20.4.13', ['d1']), // internal, excluded
    ind('user', 'sertu.rina', ['d1']), // account, excluded
    ind('file', 'tukin.docm', ['d2']), // file name, excluded
  ]
  const iocs = incidentIocs(inc('inc-1', entities), detectionsById)

  it('extracts only external indicators, sorted ip -> domain -> hash', () => {
    expect(iocs.map((i) => i.value)).toEqual(['203.0.113.66', 'cdn-tukin.example', HASH_A])
    expect(iocs.map((i) => i.kind)).toEqual(['ip', 'domain', 'sha256'])
  })

  it('computes detection counts and rule context from the entities', () => {
    expect(iocs[0]).toMatchObject({ kind: 'ip', detections: 1, rules: ['Koneksi C2'] })
    expect(iocs[1]).toMatchObject({ kind: 'domain', detections: 2 })
    expect(iocs[1].rules).toEqual(['Koneksi C2', 'Unduhan berbahaya'])
  })

  it('sorts deterministically within a kind by value (stable, feeds the hashed manifest)', () => {
    // Input order is reversed; output must be value-sorted so export bytes and hashes are stable.
    const out = incidentIocs(inc('inc-2', [ind('ip', '203.0.113.66', ['d1']), ind('ip', '198.51.100.23', ['d1']), ind('domain', 'zeta.example', ['d1']), ind('domain', 'alpha.example', ['d1'])]), detectionsById)
    expect(out.map((i) => i.value)).toEqual(['198.51.100.23', '203.0.113.66', 'alpha.example', 'zeta.example'])
  })
})

describe('allIocs', () => {
  it('de-duplicates the same indicator across incidents, keeping the earliest and unioning context', () => {
    const dA = det('a', 'Aturan A')
    const dB = det('b', 'Aturan B')
    const detectionsById = new Map([dA, dB].map((d) => [d.id, d]))
    const i1 = inc('i1', [ind('ip', '203.0.113.66', ['a'], { firstSeen: T0 + 5 * MIN })])
    const i2 = inc('i2', [ind('ip', '203.0.113.66', ['b'], { firstSeen: T0 })])
    const merged = allIocs([i1, i2], detectionsById)
    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ value: '203.0.113.66', detections: 2, firstSeen: T0 })
    expect(merged[0].rules).toEqual(['Aturan A', 'Aturan B'])
  })
})

describe('blocklistFiles', () => {
  const d1 = det('d1', 'Koneksi C2')
  const d2 = det('d2', 'Unduhan berbahaya')
  const detectionsById = new Map([d1, d2].map((d) => [d.id, d]))
  const iocs = incidentIocs(inc('inc-1', [ind('ip', '203.0.113.66', ['d1']), ind('domain', 'cdn-tukin.example', ['d1', 'd2']), ind('hash', HASH_A, ['d2'])]), detectionsById)
  const files = new Map(blocklistFiles(iocs, META).map((f) => [f.name, f.text]))

  it('produces the four content files', () => {
    expect([...files.keys()]).toEqual(['blocklist.txt', 'blocklist.csv', 'dns-sinkhole.hosts', 'README.txt'])
  })

  it('groups the plain-text list and reports computed totals', () => {
    const txt = files.get('blocklist.txt')!
    expect(txt).toContain('# Total indikator: 3 (IP eksternal: 1, Domain: 1, Hash berkas: 1)')
    expect(txt).toContain('203.0.113.66')
    expect(txt).toContain('cdn-tukin.example')
    expect(txt).toContain(HASH_A)
    expect(txt).not.toContain('WIB WIB') // fmtDateTime already appends WIB
  })

  it('writes a CSV with a header row and context', () => {
    const csv = files.get('blocklist.csv')!.split('\n')
    expect(csv[1]).toBe('tipe,nilai,jumlah_temuan,pertama_terlihat,aturan')
    expect(csv.some((l) => l.startsWith('ip,203.0.113.66,1,'))).toBe(true)
    expect(csv.some((l) => l.includes('Koneksi C2; Unduhan berbahaya'))).toBe(true)
  })

  it('puts only domains in the DNS sinkhole file', () => {
    const hosts = files.get('dns-sinkhole.hosts')!
    expect(hosts).toContain('0.0.0.0 cdn-tukin.example')
    expect(hosts).not.toContain('203.0.113.66')
  })

  it('handles an empty indicator set without crashing', () => {
    const empty = new Map(blocklistFiles([], META).map((f) => [f.name, f.text]))
    expect(empty.get('blocklist.txt')).toContain('Tidak ada indikator eksternal')
    expect(empty.get('dns-sinkhole.hosts')).toContain('Tidak ada domain')
  })
})

describe('on the demo scenario (end to end)', () => {
  let iocs: ReturnType<typeof incidentIocs>

  beforeAll(() => {
    const events: NormalizedEvent[] = generateScenario().files.flatMap((f, i) => ingestText(f.text, f.name, `demo-${i}`).events)
    const detections = runDetections(events, loadRulePack())
    const incident = correlate(detections, events, DEFAULT_UNIT_PROFILE).incidents[0]
    iocs = incidentIocs(incident, new Map(detections.map((d) => [d.id, d])))
  })

  it('exports the attacker infrastructure and nothing internal or benign', () => {
    const values = iocs.map((i) => i.value)
    // The C2 addresses and domain from the scenario are present.
    expect(values).toEqual(expect.arrayContaining(['203.0.113.66', '198.51.100.23', 'cdn-tukin.example']))
    // Every exported item is a real external indicator kind.
    expect(iocs.every((i) => i.kind === 'ip' || i.kind === 'domain' || i.kind === 'sha256')).toBe(true)
    expect(iocs.filter((i) => i.kind === 'ip').every((i) => isExternalIp(i.value))).toBe(true)
    // Nothing internal, no accounts, no host names leak in.
    expect(values).not.toContain('10.20.4.13') // WS-MIN-03 internal IP
    expect(values).not.toContain('sertu.rina')
    expect(values).not.toContain('WS-MIN-03')
    // Each indicator carries computed context.
    for (const i of iocs) {
      expect(i.detections).toBeGreaterThan(0)
      expect(i.rules.length).toBeGreaterThan(0)
    }
  })

  it('puts only domains in the DNS sinkhole, never the IPs', () => {
    const hosts = blocklistFiles(iocs, META).find((f) => f.name === 'dns-sinkhole.hosts')!.text
    expect(hosts).toContain('0.0.0.0 cdn-tukin.example')
    expect(hosts).not.toContain('203.0.113.66')
  })
})
