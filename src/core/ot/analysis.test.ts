import { describe, expect, it } from 'vitest'
import { correlate } from '@/core/correlate/correlate'
import { runDetections } from '@/core/detect/engine'
import { ingestText } from '@/core/ingest'
import type { NormalizedEvent, UnitProfile } from '@/core/model'
import { analyzeOt, cutOptions, otActions, otSummaryLines, runningAt, segmentationRules, simulateCut, valueAt, type OtAnalysis } from '@/core/ot/analysis'
import { RULE_PACK } from '@/data/rules/catalog'
import { generateScenario } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const WIB = (h: number, m: number, s = 0, ms = 0) => Date.UTC(2026, 10, 2, h - 7, m, s, ms)
const HMI = '10.40.7.10'
const SRV = '10.20.1.5'
const PLC = '10.40.7.22'

function fromScenario(profile: UnitProfile = DEFAULT_UNIT_PROFILE) {
  const events: NormalizedEvent[] = generateScenario().files.flatMap((f, i) => ingestText(f.text, f.name, `i${i}`).events)
  const detections = runDetections(events, RULE_PACK)
  const { incidents } = correlate(detections, events, profile)
  return { events, detections, incidents, ot: analyzeOt(events, detections, incidents, profile)! }
}

const demo = fromScenario()
const setpoint = (a: OtAnalysis) => a.series.find((s) => s.kind === 'setpoint')!

let id = 0
function modbus(ts: number, src: string, func: string, address: number | undefined, values?: string, extra: Record<string, string> = {}): NormalizedEvent {
  return { id: `m${id++}`, ts, dataset: 'zeek.modbus_detailed', sourceKind: 'ot', logsource: { product: 'zeek' }, srcIp: src, dstIp: PLC, dstPort: 502, importId: 'x', message: '', ot: { protocol: 'modbus', func, register: address, value: undefined }, fields: { values: values ?? '', ...extra } }
}
const polls = (from: number, count: number, read: (i: number) => string) => Array.from({ length: count }, (_, i) => modbus(from + i * 60_000, HMI, 'READ_HOLDING_REGISTERS', 0, read(i)))
const quiet: UnitProfile = { ...DEFAULT_UNIT_PROFILE, ot: { setpointRegisters: [1], setpointMin: 200, setpointMax: 240, runStatusRegister: 0, runCoils: [0] } }
const reading = (run: number, volts: number) => `${run},${volts}`

describe('the demo scenario', () => {
  it('still gives the published baseline', () => {
    expect(demo.events).toHaveLength(6296)
    expect(demo.detections).toHaveLength(41)
    expect(demo.incidents).toHaveLength(2)
  })

  it('measures how long there was to respond', () => {
    expect(demo.ot.firstFinding).toBe(WIB(9, 12, 4, 311))
    expect(demo.ot.firstContact).toBe(WIB(9, 31, 2))
    expect(demo.ot.windowMs).toBe(WIB(9, 31, 2) - WIB(9, 12, 4, 311))
    expect(demo.ot.firstWrite).toBe(WIB(9, 36, 20, 150))
  })

  it('tells the intruder from the HMI, by the unit profile', () => {
    const byName = new Map(demo.ot.talkers.map((t) => [t.srcName, t]))
    expect(byName.get('HMI-GENSET-01')).toMatchObject({ status: 'berwenang', reads: 1440, writes: 2, inOtSegment: true })
    expect(byName.get('SRV-SATUAN-01')).toMatchObject({ status: 'tidak-berwenang', reads: 25, writes: 2, inOtSegment: false, addresses: 25 })
    expect(demo.ot.learnedTalkers).toBe(false)
  })

  it('confirms each command against the next reading', () => {
    const [attack, stop, reset, normal] = demo.ot.writes
    expect(attack).toMatchObject({ srcName: 'SRV-SATUAN-01', address: 10, value: 265, trusted: false, outOfBand: true, effect: 'berlaku' })
    expect(attack.checkedAt).toBeGreaterThan(attack.ts)
    expect(stop).toMatchObject({ kind: 'coil', address: 0, value: 0, trusted: false, effect: 'berlaku' })
    expect(reset).toMatchObject({ srcName: 'HMI-GENSET-01', value: 228, trusted: true, outOfBand: false, effect: 'berlaku' })
    expect(normal).toMatchObject({ value: 230, trusted: true, effect: 'berlaku' })
  })

  it('finds how long the setpoint stayed outside its safe range, and the last normal value', () => {
    const s = setpoint(demo.ot)
    expect(s.band).toEqual({ min: 200, max: 240, source: 'profil' })
    expect(s.episodes).toHaveLength(1)
    expect(s.episodes[0]).toMatchObject({ from: WIB(9, 36, 20, 150), to: WIB(13, 5, 12), peak: 265, open: false })
    expect(s.outOfBandMs).toBe(WIB(13, 5, 12) - WIB(9, 36, 20, 150))
    expect(s.lastGood?.value).toBe(230)
    expect(s.last?.value).toBe(230)
  })

  it('shows the stop, and the restart that no command explains', () => {
    const run = demo.ot.runs[0]
    expect(run.stops).toBe(1)
    const [before, stopped, after] = run.spans
    expect(before.running).toBe(true)
    expect(stopped).toMatchObject({ running: false, from: WIB(9, 36, 48, 610), causeName: 'SRV-SATUAN-01', causeTrusted: false })
    expect(after.running).toBe(true)
    expect(after.causeName).toBeUndefined()
    expect(after.from).toBeGreaterThanOrEqual(WIB(9, 52, 30))
    expect(after.from).toBeLessThan(WIB(9, 54))
    expect(run.stoppedMs).toBe(after.from - stopped.from)
  })

  it('leaves the intruder\'s own reads out of the process history', () => {
    const s = setpoint(demo.ot)
    const during = s.points.filter(([t]) => t >= WIB(9, 31) && t < WIB(9, 36))
    expect(during.every(([, v]) => v === 230)).toBe(true)
  })

  it('reads the value and state at any moment', () => {
    const s = setpoint(demo.ot)
    expect(valueAt(s, WIB(9, 0))).toBe(230)
    expect(valueAt(s, WIB(10, 0))).toBe(265)
    expect(valueAt(s, WIB(14, 0))).toBe(230)
    const run = demo.ot.runs[0]
    expect(runningAt(run, WIB(9, 0))).toBe(true)
    expect(runningAt(run, WIB(9, 40))).toBe(false)
    expect(runningAt(run, WIB(10, 0))).toBe(true)
  })

  it('draws the path by zone, with normal control traffic marked as such', () => {
    const zone = new Map(demo.ot.nodes.map((n) => [n.label, n.zone]))
    expect(zone.get('WS-MIN-03')).toBe('it')
    expect(zone.get('SRV-SATUAN-01')).toBe('it')
    expect(zone.get('PLC-GENSET-01')).toBe('plc')
    expect(zone.get('HMI-GENSET-01')).toBe('hmi')
    expect(zone.get('203.0.113.66')).toBe('internet')
    expect(demo.ot.entry).toBe('asset:WS-MIN-03')
    expect(demo.ot.links.find((l) => l.from === 'asset:HMI-GENSET-01')).toMatchObject({ to: 'asset:PLC-GENSET-01', normal: true })
    expect(demo.ot.links.find((l) => l.from === 'asset:SRV-SATUAN-01' && l.to === 'asset:PLC-GENSET-01')?.normal).toBe(false)
  })

  it('tells the story in time order, with process changes among the findings', () => {
    const times = demo.ot.moments.map((m) => m.ts)
    expect(times).toEqual([...times].sort((a, b) => a - b))
    const titles = demo.ot.moments.map((m) => m.title)
    expect(titles).toContain('Setpoint tegangan menjadi 265 V, di luar batas 200–240 V')
    expect(titles).toContain('Setpoint tegangan kembali dalam batas: 228 V')
    expect(titles).toContain('PLC-GENSET-01 berhenti, oleh SRV-SATUAN-01')
    expect(titles).toContain('PLC-GENSET-01 menyala lagi, tanpa perintah Modbus yang terlihat')
    expect(demo.ot.moments.filter((m) => m.kind === 'temuan').length).toBe(demo.incidents.find((i) => i.id === demo.ot.incidentId)!.detectionIds.length)
  })

  it('stays small enough to store, however long the polling', () => {
    expect(JSON.stringify(demo.ot).length).toBeLessThan(200_000)
    for (const s of demo.ot.series) expect(s.points.length).toBeLessThanOrEqual(1000)
  })

  it('sums up in sentences a report can use', () => {
    const lines = otSummaryLines(demo.ot)
    expect(lines.some((l) => l.startsWith('Jendela respons: 19 menit'))).toBe(true)
    expect(lines.some((l) => l.includes('2 perintah tulis') && l.includes('SRV-SATUAN-01') && l.includes('2 di antaranya terlihat berlaku'))).toBe(true)
    expect(lines.some((l) => l.includes('Setpoint tegangan') && l.includes('3 jam 29 menit') && l.includes('Nilai normal terakhir sebelumnya: 230 V'))).toBe(true)
    expect(lines.at(-1)).toContain('bukan pengukuran langsung')
  })
})

describe('what if the path had been cut', () => {
  const cut = (node: string) => simulateCut(demo.ot, { node })

  it('isolating the server keeps the attack out of OT', () => {
    const r = cut('asset:SRV-SATUAN-01')
    expect(r.protectsOt).toBe(true)
    expect(r.otReached).toEqual([])
    expect(r.cutOff).toContain('asset:PLC-GENSET-01')
    expect(r.avoided).toBeGreaterThan(0)
    expect(r.deadline).toBe(WIB(9, 20, 5))
  })

  it('blocking only the path into the PLC protects OT and avoids less', () => {
    const blocked = simulateCut(demo.ot, { link: ['asset:SRV-SATUAN-01', 'asset:PLC-GENSET-01'] })
    expect(blocked.protectsOt).toBe(true)
    expect(blocked.cutOff).toEqual(['asset:PLC-GENSET-01'])
    expect(blocked.deadline).toBe(WIB(9, 31, 2))
    expect(blocked.avoided).toBeLessThan(cut('asset:SRV-SATUAN-01').avoided)
  })

  it('isolating the first host stops what follows, but not what already happened there', () => {
    const r = cut('asset:WS-MIN-03')
    expect(r.protectsOt).toBe(true)
    expect(r.cutOff).not.toContain('asset:WS-MIN-03')
    expect(r.cutOff).toContain('asset:SRV-SATUAN-01')
  })

  it('cutting off a command server alone leaves the logged path into OT in place', () => {
    const r = cut('ip:203.0.113.66')
    expect(r.protectsOt).toBe(false)
    expect(r.otReached).toContain('asset:PLC-GENSET-01')
  })

  it('never counts normal HMI traffic as a path for the attack', () => {
    const noCut = simulateCut(demo.ot, {})
    expect(noCut.otReached).toEqual(['asset:PLC-GENSET-01'])
    expect(noCut.avoided).toBe(0)
  })

  it('offers the IT hosts and the path that crosses into OT', () => {
    const options = cutOptions(demo.ot)
    expect(options.map((o) => o.label)).toEqual(['Isolasi WS-MIN-03', 'Isolasi SRV-SATUAN-01', 'Blokir SRV-SATUAN-01 → PLC-GENSET-01'])
    expect(options.every((o) => o.result.protectsOt)).toBe(true)
    expect(options.every((o) => o.result.total > 0)).toBe(true)
  })
})

describe('segmentation rules', () => {
  it('allows only the HMI, with the allow above the block', () => {
    const rules = segmentationRules(demo.ot)!
    expect(rules.mikrotik).toEqual([
      `/ip firewall filter add chain=forward src-address=${HMI} dst-address=${PLC} protocol=tcp dst-port=502 action=accept`,
      '/ip firewall filter add chain=forward protocol=tcp dst-port=502 action=drop',
    ])
    expect(rules.iptables).toEqual(['iptables -I FORWARD 1 -p tcp --dport 502 -j DROP', `iptables -I FORWARD 1 -s ${HMI} -d ${PLC} -p tcp --dport 502 -j ACCEPT`])
    expect(JSON.stringify(rules)).not.toContain(SRV)
  })

  it('never puts a forged address into a command someone may paste', () => {
    const forged = '10.40.7.10; rm -rf /'
    const profile = { ...DEFAULT_UNIT_PROFILE, engineeringHosts: [forged] }
    const events = [...polls(WIB(8, 0), 20, () => reading(1, 230)).map((e) => ({ ...e, srcIp: forged }))]
    const a = analyzeOt(events, [], [], profile)!
    expect(a.talkers[0].status).toBe('berwenang')
    expect(segmentationRules(a)).toBeNull()
  })

  it('gives nothing when no talker is known to be good', () => {
    const a = analyzeOt([modbus(WIB(9, 0), SRV, 'WRITE_SINGLE_COIL', 0, 'F')], [], [], quiet)!
    expect(segmentationRules(a)).toBeNull()
  })
})

describe('otActions', () => {
  it('says who to cut off and what to check, from the demo', () => {
    const actions = otActions(demo.ot).map((a) => a.title)
    expect(actions[0]).toBe('Putuskan SRV-SATUAN-01 dari perangkat OT')
    expect(actions).toContain('Alihkan pengendali ke mode lokal atau manual, bila tersedia')
    expect(actions).toContain('Periksa peralatan yang dicatu PLC-GENSET-01')
  })

  it('gives the value to restore while it is still wrong', () => {
    const events = [...polls(WIB(8, 0), 20, () => reading(1, 230)), modbus(WIB(8, 30), SRV, 'WRITE_SINGLE_REGISTER', 1, '300'), ...polls(WIB(8, 31), 3, () => reading(1, 300))]
    const a = analyzeOt(events, [], [], quiet)!
    const restore = otActions(a).find((x) => x.title.startsWith('Kembalikan'))!
    expect(restore.title).toBe('Kembalikan Setpoint tegangan pada PLC-GENSET-01 ke 230 V')
    expect(restore.detail).toContain('300 V')
  })

  it('says when equipment was last seen stopped', () => {
    const events = [...polls(WIB(8, 0), 5, () => reading(1, 230)), ...polls(WIB(8, 5), 5, () => reading(0, 230))]
    expect(otActions(analyzeOt(events, [], [], quiet)!).map((a) => a.title)).toContain('Periksa PLC-GENSET-01: terakhir terlihat berhenti')
  })

  it('asks for nothing when only normal traffic is seen', () => {
    expect(otActions(analyzeOt(polls(WIB(8, 0), 20, () => reading(1, 230)), [], [], quiet)!)).toEqual([])
  })
})

describe('other logs', () => {
  it('returns nothing when the logs hold no Modbus', () => {
    const other = { id: 'w', ts: 1, dataset: 'winevent', sourceKind: 'endpoint', logsource: {}, message: '', importId: 'x', fields: {} } as NormalizedEvent
    expect(analyzeOt([other], [], [], DEFAULT_UNIT_PROFILE)).toBeNull()
    expect(analyzeOt([], [], [], DEFAULT_UNIT_PROFILE)).toBeNull()
  })

  it('still reports a connection to the Modbus port when there is no Modbus detail', () => {
    const conn = { id: 'c', ts: WIB(9, 0), dataset: 'zeek.conn', sourceKind: 'ot', logsource: {}, message: '', importId: 'x', fields: {}, srcIp: SRV, dstIp: PLC, dstPort: 502 } as NormalizedEvent
    const a = analyzeOt([conn], [], [], DEFAULT_UNIT_PROFILE)!
    expect(a.hasValues).toBe(false)
    expect(a.talkers[0]).toMatchObject({ srcName: 'SRV-SATUAN-01', connections: 1, reads: 0, status: 'tidak-berwenang' })
    expect(a.series).toEqual([])
  })

  it('says so when plain Zeek Modbus logs hold no addresses or values', () => {
    const a = analyzeOt([modbus(WIB(9, 0), HMI, 'READ_HOLDING_REGISTERS', undefined), modbus(WIB(9, 1), SRV, 'WRITE_SINGLE_COIL', undefined)], [], [], DEFAULT_UNIT_PROFILE)!
    expect(a.hasValues).toBe(false)
    expect(a.writes).toEqual([])
    expect(a.talkers.find((t) => t.src === SRV)?.writes).toBe(1)
  })

  it('learns who is normal when the unit listed no HMI', () => {
    const profile = { ...quiet, engineeringHosts: [] }
    const events = [...polls(WIB(8, 0), 30, () => reading(1, 230)), modbus(WIB(9, 0), SRV, 'WRITE_SINGLE_REGISTER', 1, '300')]
    const a = analyzeOt(events, [], [], profile)!
    expect(a.learnedTalkers).toBe(true)
    expect(a.talkers.find((t) => t.src === HMI)?.status).toBe('pola-utama')
    expect(a.talkers.find((t) => t.src === SRV)?.status).toBe('menyimpang')
    expect(a.writes[0].trusted).toBe(false)
    expect(segmentationRules(a)?.iptables.join()).toContain(HMI)
  })

  it('learns the normal range when the unit gave none, from before the first intrusion', () => {
    const profile = { ...DEFAULT_UNIT_PROFILE, ot: { measuredRegisters: [{ address: 1, label: 'Tegangan', unit: 'V' }] } }
    const events = [...polls(WIB(8, 0), 30, () => reading(1, 230)), modbus(WIB(8, 40), SRV, 'WRITE_SINGLE_REGISTER', 1, '300'), ...polls(WIB(8, 41), 5, () => reading(1, 300))]
    const a = analyzeOt(events, [], [], profile)!
    const s = a.series.find((x) => x.address === 1)!
    expect(s.band?.source).toBe('dipelajari')
    expect(s.band!.min).toBeLessThan(230)
    expect(s.band!.max).toBeLessThan(300)
    expect(s.episodes[0]).toMatchObject({ from: WIB(8, 40), open: true, peak: 300 })
    expect(s.lastGood?.value).toBe(230)
  })

  it('makes no range from too few readings', () => {
    const profile = { ...DEFAULT_UNIT_PROFILE, ot: {} }
    const a = analyzeOt([...polls(WIB(8, 0), 3, () => reading(1, 230)), modbus(WIB(8, 5), SRV, 'WRITE_SINGLE_REGISTER', 1, '300')], [], [], profile)!
    expect(a.series.find((s) => s.address === 1)?.band).toBeUndefined()
  })

  it('reports a command the readings do not bear out', () => {
    const events = [...polls(WIB(8, 0), 20, () => reading(1, 230)), modbus(WIB(8, 19, 30), SRV, 'WRITE_SINGLE_REGISTER', 1, '300'), ...polls(WIB(8, 20), 3, () => reading(1, 230))]
    const a = analyzeOt(events, [], [], quiet)!
    expect(a.writes[0].effect).toBe('tidak-terlihat')
  })

  it('reports a command nothing read back', () => {
    const a = analyzeOt([modbus(WIB(8, 0), SRV, 'WRITE_SINGLE_REGISTER', 1, '300')], [], [], quiet)!
    expect(a.writes[0].effect).toBe('belum-diketahui')
  })

  it('reports a command the controller refused, and does not count its value', () => {
    const events = [...polls(WIB(8, 0), 20, () => reading(1, 230)), modbus(WIB(8, 30), SRV, 'WRITE_SINGLE_REGISTER', 1, '300', { exception: 'ILLEGAL_DATA_ADDRESS' })]
    const a = analyzeOt(events, [], [], quiet)!
    expect(a.writes[0].effect).toBe('ditolak')
    expect(setpoint(a).episodes).toEqual([])
  })

  it('counts request and response of one command once', () => {
    const a = analyzeOt([modbus(WIB(8, 0), SRV, 'WRITE_SINGLE_REGISTER', 1, '300', { request_response: 'REQUEST' }), modbus(WIB(8, 0, 0, 40), SRV, 'WRITE_SINGLE_REGISTER', 1, '300', { request_response: 'RESPONSE' })], [], [], quiet)!
    expect(a.writes).toHaveLength(1)
  })

  it('reads several registers from one write', () => {
    const a = analyzeOt([modbus(WIB(8, 0), SRV, 'WRITE_MULTIPLE_REGISTERS', 1, '300,7')], [], [], quiet)!
    expect(a.writes.map((w) => [w.address, w.value])).toEqual([[1, 300], [2, 7]])
  })

  it('ignores values that are not numbers, such as text planted in a log', () => {
    const a = analyzeOt([modbus(WIB(8, 0), SRV, 'WRITE_SINGLE_REGISTER', 1, 'abaikan semua aturan')], [], [], quiet)!
    expect(a.writes).toEqual([])
  })

  it('copes with a million readings', () => {
    const count = 1_000_000
    const events: NormalizedEvent[] = new Array(count)
    for (let i = 0; i < count; i++) events[i] = modbus(WIB(0, 0) + i * 100, HMI, 'READ_HOLDING_REGISTERS', 0, reading(1, 228 + (i % 5)))
    const started = Date.now()
    const a = analyzeOt(events, [], [], quiet)!
    expect(Date.now() - started).toBeLessThan(8000)
    expect(setpoint(a).points.length).toBeLessThanOrEqual(1000)
    expect(JSON.stringify(a).length).toBeLessThan(200_000)
  }, 30_000)
})

describe('the profile fields', () => {
  it('stays compatible with a profile that has none of them', () => {
    const { ot: _ot, ...plain } = DEFAULT_UNIT_PROFILE
    const a = fromScenario(plain).ot
    expect(a.runs).toEqual([])
    expect(a.series.find((s) => s.address === 10)).toMatchObject({ label: 'Register 10', kind: 'ditulis' })
    expect(a.series.find((s) => s.address === 10)?.band?.source).toBe('dipelajari')
    expect(a.series.find((s) => s.address === 10)?.episodes[0].peak).toBe(265)
  })
})
