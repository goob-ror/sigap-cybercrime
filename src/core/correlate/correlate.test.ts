import { beforeAll, describe, expect, it } from 'vitest'
import { ingestText } from '@/core/ingest'
import { runDetections } from '@/core/detect/engine'
import { correlate, killChain, scoreOf, scoreTerms } from '@/core/correlate/correlate'
import { reconcileCases } from '@/core/correlate/cases'
import type { Detection, Incident, Level, NormalizedEvent, UnitProfile } from '@/core/model'
import { incidentStory, incidentSummary, priorityActions } from '@/core/report/narrative'
import { bucketSize, computeStats } from '@/core/stats'
import { loadRulePack } from '@/data/rules'
import { RULES } from '@/data/rules/catalog'
import { generateScenario } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const PROFILE: UnitProfile = { name: 'uji', engineeringHosts: [], otSubnets: ['10.40.7.0/24'], uploadThresholdBytes: 1e9, assets: [] }
const T0 = Date.UTC(2026, 10, 2, 2, 0, 0)
const MIN = 60_000

function ev(id: string, minute: number, rest: Partial<NormalizedEvent>): NormalizedEvent {
  return { id, ts: T0 + minute * MIN, dataset: 'winevent', sourceKind: 'endpoint', logsource: { product: 'windows' }, message: id, importId: 'x', fields: {}, ...rest }
}

function det(id: string, eventIds: string[], minute: number, level: Level = 'high', attack: string[] = []): Detection {
  return { id, ruleId: `rule-${id}`, title: `Aturan ${id}`, level, attack, eventIds, matched: {}, ts: T0 + minute * MIN }
}

describe('correlation on the demo scenario', () => {
  let detections: Detection[]
  let events: NormalizedEvent[]
  let incident: Incident

  beforeAll(() => {
    events = generateScenario().files.flatMap((f, i) => ingestText(f.text, f.name, `demo-${i}`).events)
    detections = runDetections(events, loadRulePack())
    const result = correlate(detections, events, DEFAULT_UNIT_PROFILE)
    expect(result.incidents).toHaveLength(1)
    incident = result.incidents[0]
  })

  it('joins the whole attack chain into one incident', () => {
    expect(incident.detectionIds).toHaveLength(detections.length)
    expect(incident.title).toBe('Serangan lintas IT–OT berawal di WS-MIN-03')
    expect(incident.path).toEqual(['asset:WS-MIN-03', 'asset:SRV-SATUAN-01', 'asset:PLC-GENSET-01'])
    expect(incident.level).toBe('critical')
    expect(incident.sourceKinds).toEqual(['endpoint', 'network', 'ot'])
  })

  it('ties IPs to hosts, from the logs and from the unit inventory', () => {
    const ws = incident.entities.find((e) => e.key === 'asset:WS-MIN-03')!
    expect(ws.aliases).toEqual(['10.20.4.13'])
    const plc = incident.entities.find((e) => e.key === 'asset:PLC-GENSET-01')!
    expect(plc.type).toBe('device')
    // The firewall that logged the traffic is not part of the attack.
    expect(incident.entities.some((e) => e.value === 'FW-SATUAN')).toBe(false)
  })

  it('keeps attacker infrastructure and accounts as entities', () => {
    const keys = incident.entities.map((e) => e.key)
    expect(keys).toEqual(expect.arrayContaining(['ip:203.0.113.66', 'domain:cdn-tukin.example', 'ip:198.51.100.23', 'user:sertu.rina', 'user:admin.it', 'user:svc_backup2']))
    const ot = incident.relations.find((r) => r.from === 'asset:SRV-SATUAN-01' && r.to === 'asset:PLC-GENSET-01')!
    expect(ot.level).toBe('critical')
    expect(ot.labels[0]).toMatch(/^Modbus WRITE_/)
  })

  it('explains a high score', () => {
    expect(incident.score).toBeGreaterThan(0.99)
    expect(incident.score).toBeCloseTo(scoreOf(incident.scoreBreakdown), 12)
    expect(incident.scoreBreakdown.filter((t) => t.kind === 'rule')).toHaveLength(incident.ruleIds.length)
    expect(incident.scoreBreakdown.find((t) => t.kind === 'killchain')?.label).toMatch(/^\d+ tahap ATT&CK berurutan: Akses awal → Eksekusi/)
    expect(incident.scoreBreakdown.find((t) => t.kind === 'sources')?.label).toBe('Dikuatkan 3 jenis sumber log: Endpoint, Jaringan, OT')
  })

  it('tells the story in time order with priority actions', () => {
    const detectionsById = new Map(detections.map((d) => [d.id, d]))
    const eventsById = new Map(events.map((e) => [e.id, e]))
    const steps = incidentStory(incident, detectionsById, eventsById)
    expect(steps[0].label).toBe('Akses awal')
    expect(steps[0].places).toEqual(['WS-MIN-03'])
    expect(steps.some((s) => s.places.includes('SRV-SATUAN-01 → PLC-GENSET-01'))).toBe(true)
    expect(steps.flatMap((s) => s.detections)).toHaveLength(detections.length)
    const summary = incidentSummary(incident, steps)
    expect(summary).toContain('Rangkaian dimulai di WS-MIN-03, berlanjut ke SRV-SATUAN-01, hingga PLC-GENSET-01.')
    const actions = priorityActions(incident, detectionsById, RULES)
    expect(actions.length).toBeGreaterThan(0)
    expect(actions[0].level).toBe('critical')
  })
})

describe('linking rules', () => {
  it('links detections that share a host within the window, and not beyond it', () => {
    const events = [ev('a', 0, { host: 'WS-1' }), ev('b', 30, { host: 'WS-1' }), ev('c', 60 * 25 + 30, { host: 'WS-1' })]
    const dets = [det('A', ['a'], 0), det('B', ['b'], 30), det('C', ['c'], 60 * 25 + 30)]
    const { incidents } = correlate(dets, events, PROFILE)
    expect(incidents.map((i) => i.detectionIds.sort())).toEqual(expect.arrayContaining([['A', 'B'], ['C']]))
  })

  it('does not link through a common server unless it is where the activity happened', () => {
    // Six workstations all talk to the DNS server, which makes it common.
    const background = Array.from({ length: 6 }, (_, i) => ev(`bg${i}`, i, { host: `WS-${i}`, dstIp: '10.0.0.53' }))
    const events = [...background, ev('a', 10, { host: 'WS-0', dstIp: '10.0.0.53' }), ev('b', 11, { host: 'WS-1', dstIp: '10.0.0.53' })]
    const { incidents, common } = correlate([det('A', ['a'], 10), det('B', ['b'], 11)], events, PROFILE)
    expect(common.has('ip:10.0.0.53')).toBe(true)
    expect(incidents).toHaveLength(2)
    // With only two hosts in the data the same server is not common, so the detections link.
    const small = correlate([det('A', ['a'], 10), det('B', ['b'], 11)], events.slice(-2), PROFILE)
    expect(small.incidents).toHaveLength(1)
  })

  it('links by file hash but not by file name alone', () => {
    const byName = [ev('a', 0, { host: 'WS-1', file: { name: 'laporan.docx' } }), ev('b', 5, { host: 'WS-2', file: { name: 'laporan.docx' } })]
    expect(correlate([det('A', ['a'], 0), det('B', ['b'], 5)], byName, PROFILE).incidents).toHaveLength(2)
    const byHash = [ev('a', 0, { host: 'WS-1', file: { name: 'x.exe', sha256: 'ab'.repeat(32) } }), ev('b', 5, { host: 'WS-2', file: { name: 'y.exe', sha256: 'ab'.repeat(32) } })]
    expect(correlate([det('A', ['a'], 0), det('B', ['b'], 5)], byHash, PROFILE).incidents).toHaveLength(1)
  })

  it('treats a workstation IP as the workstation once a logon names it', () => {
    const events = [
      ev('logon', 0, { host: 'SRV-1', srcIp: '10.1.1.7', fields: { EventID: 4624, LogonType: 3, IpAddress: '10.1.1.7', WorkstationName: 'WS-7' } }),
      ev('a', 1, { host: 'WS-7' }),
      ev('b', 2, { dataset: 'zeek.conn', sourceKind: 'network', srcIp: '10.1.1.7', dstIp: '203.0.113.9' }),
    ]
    const { incidents, inventory } = correlate([det('A', ['a'], 1), det('B', ['b'], 2)], events, PROFILE)
    expect(inventory.get('10.1.1.7')).toEqual({ name: 'WS-7', source: 'log' })
    expect(incidents).toHaveLength(1)
  })
})

describe('score', () => {
  it('combines weights as 1 − Π(1 − w)', () => {
    const terms = scoreTerms([det('A', [], 0, 'critical'), det('B', [], 1, 'high')], ['endpoint'])
    expect(terms.map((t) => t.weight)).toEqual([0.6, 0.4])
    expect(scoreOf(terms)).toBeCloseTo(1 - 0.4 * 0.6, 12)
  })

  it('counts a rule once however often it fires', () => {
    const repeated = [det('A', [], 0, 'medium'), { ...det('A2', [], 1, 'medium'), ruleId: 'rule-A' }]
    const terms = scoreTerms(repeated, ['endpoint'])
    expect(terms).toEqual([{ kind: 'rule', label: 'Aturan A', weight: 0.2, level: 'medium', count: 2 }])
  })

  it('finds the longest kill-chain ordered run of tactics', () => {
    // Execution, then Initial Access (out of order), then Lateral Movement, then Exfiltration.
    const chain = killChain([det('A', [], 0, 'high', ['T1059']), det('B', [], 1, 'high', ['T1566.003']), det('C', [], 2, 'high', ['T1021.002']), det('D', [], 3, 'high', ['T1048'])])
    expect(chain).toEqual(['Execution', 'Lateral Movement', 'Exfiltration'])
  })
})

describe('cases', () => {
  const inc = (id: string, detectionIds: string[], firstSeen: number, score = 0.5): Incident => ({ id, title: `Insiden ${id}`, path: [], level: 'high', detectionIds, ruleIds: [], entities: [], relations: [], tactics: [], sourceKinds: [], score, scoreBreakdown: [], firstSeen, lastSeen: firstSeen })

  it('creates a case per new incident, numbered by time', () => {
    const { incidents, put } = reconcileCases([inc('i2', ['b'], 2), inc('i1', ['a'], 1)], [], [], 100)
    expect(incidents.map((i) => [i.id, i.caseId])).toEqual([['i2', 'KSS-0002'], ['i1', 'KSS-0001']])
    expect(put.map((c) => [c.id, c.status, c.incidentIds])).toEqual([['KSS-0001', 'Open', ['i1']], ['KSS-0002', 'Open', ['i2']]])
  })

  it('keeps case data when incidents are recomputed, and merges cases whose incidents join', () => {
    const first = reconcileCases([inc('i1', ['a'], 1), inc('i2', ['b'], 2)], [], [], 100)
    const [c1, c2] = first.put
    c1.status = 'Investigating'
    c1.followUps = { a: 'Selesai' }
    c2.notes = 'Periksa server'
    c2.followUps = { b: 'Berjalan' }
    const merged = reconcileCases([inc('i9', ['a', 'b', 'c'], 1)], first.incidents, [c1, c2], 200)
    expect(merged.incidents[0].caseId).toBe('KSS-0001')
    expect(merged.remove).toEqual(['KSS-0002'])
    const kept = merged.put.find((c) => c.id === 'KSS-0001')!
    expect(kept.status).toBe('Investigating')
    expect(kept.followUps).toEqual({ a: 'Selesai', b: 'Berjalan' })
    expect(kept.notes).toContain('Periksa server')
    expect(kept.incidentIds).toEqual(['i9'])
  })
})

describe('stats', () => {
  it('picks a bucket size that keeps the chart readable', () => {
    expect(bucketSize(4 * 60 * MIN)).toBe(10 * MIN)
    expect(bucketSize(24 * 60 * MIN)).toBe(60 * MIN)
  })

  it('counts every event exactly once', () => {
    const events = [ev('a', 0, {}), ev('b', 59, { dataset: 'zeek.conn', sourceKind: 'network' }), ev('c', 600, {})]
    const stats = computeStats(events)!
    expect(stats.buckets.reduce((a, b) => a + b, 0)).toBe(3)
    expect(stats.byDataset).toEqual({ winevent: 2, 'zeek.conn': 1 })
    expect(stats.byKind).toEqual({ endpoint: 2, network: 1 })
  })
})
