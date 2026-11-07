import { buildInventory } from '@/core/correlate/correlate'
import type { Detection, Incident, Level, NormalizedEvent, UnitProfile } from '@/core/model'
import { ipInCidr, ipv4ToInt, isExternalIp } from '@/core/net'
import { fmtSpan, fmtTime } from '@/lib/format'

/**
 * What an IT-to-OT attack did to the physical process, read from Modbus traffic.
 *
 * An IT log tool stops at "host A sent a command to host B". OT polling goes further: the HMI reads the
 * controller every few seconds, so the log also holds what the controller reported before and after each
 * command. That is enough to say whether a command took effect, how long a value stayed outside its safe
 * range, and which value was last normal.
 *
 * Everything here is arithmetic on the log, so each number can be traced to its lines. It is what the
 * network saw the controller report, not a measurement from the equipment itself.
 */

const MODBUS_PORT = 502
const MAX_POINTS = 480
const MAX_RUN_SPANS = 50
const MAX_MOMENTS = 80
/** A reading this long after a command still says whether the command took effect. */
const EFFECT_WINDOW_MS = 15 * 60_000
/** A run or stop this soon after a command counts as caused by it. */
const CAUSE_WINDOW_MS = 2 * 60_000
/** Request and response of one transaction are logged apart, moments away from each other. */
const SAME_WRITE_MS = 2_000
/** A learned range needs this many readings, or it says nothing. */
const MIN_READINGS_FOR_BAND = 10
/** The main talker sends most of a device's traffic, on polling that never stops. */
const MAIN_TALKER_SHARE = 0.6
const MAIN_TALKER_MIN = 10

export type OtEffect = 'berlaku' | 'tidak-terlihat' | 'belum-diketahui' | 'ditolak'
export type TalkerStatus = 'berwenang' | 'pola-utama' | 'tidak-berwenang' | 'menyimpang'

export type OtWrite = {
  ts: number
  eventId: string
  src: string
  srcName: string
  dst: string
  dstName: string
  func: string
  address: number
  kind: 'register' | 'coil'
  value: number
  trusted: boolean
  outOfBand: boolean
  effect: OtEffect
  /** When a later reading confirmed or contradicted it. */
  checkedAt?: number
}

export type OtTalker = {
  src: string
  srcName: string
  dst: string
  dstName: string
  reads: number
  writes: number
  /** Connections seen in `conn` or firewall logs, with or without Modbus detail. */
  connections: number
  addresses: number
  functions: string[]
  firstSeen: number
  lastSeen: number
  status: TalkerStatus
  inOtSegment: boolean
}

export type OtBand = { min: number; max: number; source: 'profil' | 'dipelajari' }
export type OtEpisode = { from: number; to: number; open: boolean; peak: number }

export type OtSeries = {
  device: string
  deviceName: string
  address: number
  label: string
  unit?: string
  kind: 'setpoint' | 'terukur' | 'ditulis'
  band?: OtBand
  points: [number, number][]
  episodes: OtEpisode[]
  outOfBandMs: number
  lastGood?: { value: number; ts: number }
  last?: { value: number; ts: number }
}

export type OtRunSpan = { from: number; to: number; running: boolean; causeName?: string; causeTrusted?: boolean }
export type OtRun = { device: string; deviceName: string; spans: OtRunSpan[]; stoppedMs: number; stops: number }

export type OtZone = 'internet' | 'it' | 'hmi' | 'plc'
export type OtNode = { key: string; label: string; zone: OtZone; firstSeen: number; detectionIds: string[]; inAttack: boolean }
export type OtLink = { from: string; to: string; firstSeen: number; label: string; normal: boolean }
export type OtMoment = { ts: number; kind: 'temuan' | 'proses'; title: string; level?: Level; detectionId?: string; nodes: string[] }

export type OtAnalysis = {
  incidentId?: string
  /** False for plain Zeek `modbus.log`, which holds no addresses or values. */
  hasValues: boolean
  /** The unit listed no HMI, so who is normal was learned from the traffic. */
  learnedTalkers: boolean
  transactions: number
  talkers: OtTalker[]
  writes: OtWrite[]
  series: OtSeries[]
  runs: OtRun[]
  firstFinding?: number
  firstContact?: number
  firstWrite?: number
  /** First finding to first touch of OT by anything untrusted: the time there was to stop it. */
  windowMs?: number
  windowToWriteMs?: number
  span: { from: number; to: number }
  nodes: OtNode[]
  links: OtLink[]
  entry?: string
  moments: OtMoment[]
}

const isWriteFunc = (func: string) => /^(WRITE_|MASK_WRITE|READ_WRITE)/.test(func)
const isCoilFunc = (func: string) => func.includes('COIL')

function parseValue(raw: string): number | undefined {
  const text = raw.trim().toLowerCase()
  if (text === 't' || text === 'true') return 1
  if (text === 'f' || text === 'false') return 0
  if (!/^-?\d+(\.\d+)?$/.test(text)) return undefined
  return Number(text)
}

function valuesOf(e: NormalizedEvent): number[] {
  const raw = e.fields.values
  if (raw === null || raw === undefined || raw === '' || raw === '-') return []
  return String(raw).split(',').map(parseValue).filter((v): v is number => v !== undefined)
}

const refused = (e: NormalizedEvent) => {
  const value = e.fields.exception
  return value !== undefined && value !== null && value !== '' && value !== '-'
}

/** Keeps every change, then trims a long series to what a chart of ordinary width can show. */
function thin(points: [number, number][]): [number, number][] {
  const changes: [number, number][] = []
  points.forEach((p, i) => {
    const before = points[i - 1]
    const after = points[i + 1]
    if (!before || !after || before[1] !== p[1] || after[1] !== p[1]) changes.push(p)
  })
  if (changes.length <= MAX_POINTS) return changes
  const size = Math.ceil(changes.length / (MAX_POINTS / 2))
  const out: [number, number][] = []
  for (let i = 0; i < changes.length; i += size) {
    const chunk = changes.slice(i, i + size)
    const low = chunk.reduce((a, b) => (b[1] < a[1] ? b : a))
    const high = chunk.reduce((a, b) => (b[1] > a[1] ? b : a))
    if (low === high) out.push(low)
    else out.push(...(low[0] <= high[0] ? [low, high] : [high, low]))
  }
  return out
}

/** The first reading after a moment. Readings are in time order, and a log can hold millions of them. */
function firstAfter(list: [number, number][] | undefined, after: number): [number, number] | undefined {
  if (!list) return undefined
  let low = 0
  let high = list.length
  while (low < high) {
    const mid = (low + high) >> 1
    if (list[mid][0] > after) high = mid
    else low = mid + 1
  }
  return list[low]
}

function learnBand(readings: [number, number][], before: number): OtBand | undefined {
  let count = 0
  let min = Infinity
  let max = -Infinity
  for (const [ts, value] of readings) {
    if (ts >= before) break
    count++
    if (value < min) min = value
    if (value > max) max = value
  }
  if (count < MIN_READINGS_FOR_BAND) return undefined
  const pad = Math.max(1, Math.round(Math.abs((min + max) / 2) * 0.05))
  return { min: min - pad, max: max + pad, source: 'dipelajari' }
}

function episodesOf(points: [number, number][], band: OtBand | undefined) {
  const episodes: OtEpisode[] = []
  let lastGood: { value: number; ts: number } | undefined
  let goodBeforeFirst: { value: number; ts: number } | undefined
  if (!band) return { episodes, lastGood }
  const outside = (v: number) => v < band.min || v > band.max
  let open: OtEpisode | undefined
  for (const [ts, value] of points) {
    if (outside(value)) {
      if (open) open.peak = Math.abs(value - (band.min + band.max) / 2) > Math.abs(open.peak - (band.min + band.max) / 2) ? value : open.peak
      else {
        open = { from: ts, to: ts, open: true, peak: value }
        goodBeforeFirst ??= lastGood
      }
      open.to = ts
    } else {
      if (open) {
        open.to = ts
        open.open = false
        episodes.push(open)
        open = undefined
      }
      lastGood = { value, ts }
    }
  }
  if (open) episodes.push(open)
  return { episodes, lastGood: goodBeforeFirst ?? lastGood }
}

/** Analysis of all Modbus traffic in the logs, or null when there is none to read. */
export function analyzeOt(events: readonly NormalizedEvent[], detections: readonly Detection[], incidents: readonly Incident[], profile: UnitProfile): OtAnalysis | null {
  const modbus = events.filter((e) => e.ot?.protocol === 'modbus' && e.srcIp && e.dstIp).sort((a, b) => a.ts - b.ts)
  const contacts = events.filter((e) => !e.ot && e.dstPort === MODBUS_PORT && e.srcIp && e.dstIp)
  if (!modbus.length && !contacts.length) return null

  const inventory = buildInventory(events, profile)
  const nameOf = (ip: string) => inventory.get(ip)?.name ?? ip
  const keyOf = (ip: string) => `asset:${nameOf(ip)}`
  const inSegment = (ip: string) => profile.otSubnets.some((cidr) => ipInCidr(ip, cidr))
  const engineering = new Set(profile.engineeringHosts)
  const learnedTalkers = engineering.size === 0
  const ot = profile.ot ?? {}
  const runCoils = new Set(ot.runCoils ?? [])
  const setpoints = new Set(ot.setpointRegisters ?? [])
  const measured = new Map((ot.measuredRegisters ?? []).map((m) => [m.address, m]))

  // Who talks to whom.
  const pairs = new Map<string, OtTalker & { seen: Set<number>; funcs: Set<string> }>()
  const pair = (src: string, dst: string, ts: number) => {
    const key = `${src}>${dst}`
    let t = pairs.get(key)
    if (!t) {
      t = { src, srcName: nameOf(src), dst, dstName: nameOf(dst), reads: 0, writes: 0, connections: 0, addresses: 0, functions: [], firstSeen: ts, lastSeen: ts, status: 'menyimpang', inOtSegment: inSegment(src), seen: new Set(), funcs: new Set() }
      pairs.set(key, t)
    }
    t.firstSeen = Math.min(t.firstSeen, ts)
    t.lastSeen = Math.max(t.lastSeen, ts)
    return t
  }
  for (const e of contacts) pair(e.srcIp!, e.dstIp!, e.ts).connections++
  for (const e of modbus) {
    const t = pair(e.srcIp!, e.dstIp!, e.ts)
    const func = e.ot!.func ?? '?'
    t.funcs.add(func)
    if (isWriteFunc(func)) t.writes++
    else t.reads++
    if (e.ot!.register !== undefined) t.seen.add(e.ot!.register)
  }
  const perDevice = new Map<string, number>()
  for (const t of pairs.values()) perDevice.set(t.dst, (perDevice.get(t.dst) ?? 0) + t.reads + t.writes)
  for (const t of pairs.values()) {
    const share = t.reads + t.writes
    if (!learnedTalkers) t.status = engineering.has(t.src) ? 'berwenang' : 'tidak-berwenang'
    else t.status = share >= MAIN_TALKER_MIN && share / (perDevice.get(t.dst) || 1) >= MAIN_TALKER_SHARE ? 'pola-utama' : 'menyimpang'
    t.addresses = t.seen.size
    t.functions = [...t.funcs].sort()
  }
  const talkers: OtTalker[] = [...pairs.values()].map(({ seen: _seen, funcs: _funcs, ...t }) => t).sort((a, b) => a.firstSeen - b.firstSeen)
  const trusted = (src: string, dst: string) => { const s = pairs.get(`${src}>${dst}`)?.status; return s === 'berwenang' || s === 'pola-utama' }

  // The trusted talker that reads most is the reference for what the controller reported. An intruder's
  // own reads are left out: only the fact of them matters, and they may be partial.
  const reference = new Map<string, string>()
  for (const t of talkers) {
    if (!trusted(t.src, t.dst) || !t.reads) continue
    const current = reference.get(t.dst)
    if (!current || t.reads > (pairs.get(`${current}>${t.dst}`)?.reads ?? 0)) reference.set(t.dst, t.src)
  }

  // What the reference read, per device and address.
  const readings = new Map<string, [number, number][]>()
  const coilReadings = new Map<string, [number, number][]>()
  const addReading = (target: Map<string, [number, number][]>, device: string, address: number, ts: number, value: number) => {
    const key = `${device}#${address}`
    const list = target.get(key)
    if (list) list.push([ts, value])
    else target.set(key, [[ts, value]])
  }

  // Commands, one per transaction.
  const raw: OtWrite[] = []
  let hasValues = false
  for (const e of modbus) {
    const func = e.ot!.func ?? '?'
    const start = e.ot!.register
    const values = valuesOf(e)
    if (start !== undefined && values.length) hasValues = true
    if (isWriteFunc(func)) {
      if (start === undefined || !values.length) continue
      values.forEach((value, i) => {
        const src = e.srcIp!
        const dst = e.dstIp!
        const address = start + i
        for (let n = raw.length - 1; n >= 0 && e.ts - raw[n].ts <= SAME_WRITE_MS; n--) {
          const w = raw[n]
          if (w.src === src && w.dst === dst && w.address === address && w.value === value && w.func === func) return
        }
        raw.push({ ts: e.ts, eventId: e.id, src, srcName: nameOf(src), dst, dstName: nameOf(dst), func, address, kind: isCoilFunc(func) ? 'coil' : 'register', value, trusted: trusted(src, dst), outOfBand: false, effect: refused(e) ? 'ditolak' : 'belum-diketahui' })
      })
    } else if (start !== undefined && values.length && e.srcIp === reference.get(e.dstIp!)) {
      values.forEach((value, i) => addReading(isCoilFunc(func) ? coilReadings : readings, e.dstIp!, start + i, e.ts, value))
    }
  }
  const writes = raw.sort((a, b) => a.ts - b.ts)
  const firstUntrustedWrite = writes.find((w) => !w.trusted)?.ts
  const firstUntrustedOf = (device: string) => writes.find((w) => !w.trusted && w.dst === device)?.ts ?? Infinity

  // Did each command take effect? Only a later reading can say.
  const nextReading = (list: [number, number][] | undefined, after: number) => {
    const found = firstAfter(list, after)
    return found && found[0] - after <= EFFECT_WINDOW_MS ? found : undefined
  }
  for (const w of writes) {
    if (w.effect === 'ditolak') continue
    const isRunCoil = w.kind === 'coil' && runCoils.has(w.address)
    const list = w.kind === 'coil' ? coilReadings.get(`${w.dst}#${w.address}`) ?? (isRunCoil && ot.runStatusRegister !== undefined ? readings.get(`${w.dst}#${ot.runStatusRegister}`) : undefined) : readings.get(`${w.dst}#${w.address}`)
    const reading = nextReading(list, w.ts)
    if (!reading) continue
    w.checkedAt = reading[0]
    w.effect = reading[1] === w.value ? 'berlaku' : 'tidak-terlihat'
  }

  // Value over time, for each point the unit named or anyone wrote to.
  const series: OtSeries[] = []
  const devices = [...new Set(modbus.map((e) => e.dstIp!))]
  for (const device of devices) {
    const addresses = new Set<number>([...setpoints, ...measured.keys()])
    for (const w of writes) if (w.dst === device && w.kind === 'register') addresses.add(w.address)
    for (const address of [...addresses].sort((a, b) => a - b)) {
      const read = readings.get(`${device}#${address}`) ?? []
      const written = writes.filter((w) => w.dst === device && w.address === address && w.kind === 'register' && w.effect !== 'ditolak')
      if (!read.length && !written.length) continue
      const merged = [...read, ...written.map((w): [number, number] => [w.ts, w.value])].sort((a, b) => a[0] - b[0])
      const isSetpoint = setpoints.has(address)
      const named = measured.get(address)
      const band: OtBand | undefined = isSetpoint && ot.setpointMin !== undefined && ot.setpointMax !== undefined ? { min: ot.setpointMin, max: ot.setpointMax, source: 'profil' } : learnBand(read, firstUntrustedOf(device))
      const { episodes, lastGood } = episodesOf(merged, band)
      const end = merged.at(-1)
      series.push({
        device,
        deviceName: nameOf(device),
        address,
        label: isSetpoint ? 'Setpoint tegangan' : named?.label ?? `Register ${address}`,
        unit: isSetpoint ? 'V' : named?.unit,
        kind: isSetpoint ? 'setpoint' : named ? 'terukur' : 'ditulis',
        band,
        points: thin(merged),
        episodes,
        outOfBandMs: episodes.reduce((sum, ep) => sum + (ep.to - ep.from), 0),
        lastGood,
        last: end ? { value: end[1], ts: end[0] } : undefined,
      })
      if (band) for (const w of written) w.outOfBand = w.value < band.min || w.value > band.max
    }
  }
  series.sort((a, b) => Number(b.kind === 'setpoint') - Number(a.kind === 'setpoint') || a.address - b.address)

  // Was the equipment running?
  const runs: OtRun[] = []
  for (const device of devices) {
    const statusReads = ot.runStatusRegister !== undefined ? readings.get(`${device}#${ot.runStatusRegister}`) : undefined
    const coilReads = [...runCoils].flatMap((coil) => coilReadings.get(`${device}#${coil}`) ?? [])
    const commands = writes.filter((w) => w.dst === device && w.kind === 'coil' && runCoils.has(w.address) && w.effect !== 'ditolak')
    const observed = (statusReads?.length ? statusReads : coilReads).map(([ts, v]): [number, boolean] => [ts, v !== 0])
    if (!observed.length) continue
    const spans: OtRunSpan[] = []
    for (const [ts, running] of observed) {
      const last = spans.at(-1)
      if (last && last.running === running) { last.to = ts; continue }
      const cause = [...commands].reverse().find((w) => w.ts <= ts && ts - w.ts <= CAUSE_WINDOW_MS && (w.value !== 0) === running)
      // A stop begins at the command that caused it, not at the next poll that noticed.
      const from = cause?.ts ?? ts
      if (last) last.to = from
      spans.push({ from, to: ts, running, causeName: cause?.srcName, causeTrusted: cause?.trusted })
    }
    const stopped = spans.filter((s) => !s.running)
    runs.push({ device, deviceName: nameOf(device), spans: spans.slice(0, MAX_RUN_SPANS), stoppedMs: stopped.reduce((sum, s) => sum + (s.to - s.from), 0), stops: stopped.length })
  }

  // The incident that reached OT, and how much warning there was.
  const incident = [...incidents].filter((i) => i.entities.some((e) => e.type === 'device')).sort((a, b) => b.score - a.score)[0]
  const untrustedTalkers = talkers.filter((t) => !trusted(t.src, t.dst))
  const firstContact = untrustedTalkers.length ? Math.min(...untrustedTalkers.map((t) => t.firstSeen)) : undefined
  const firstFinding = incident?.firstSeen
  const windowOf = (later: number | undefined) => (firstFinding !== undefined && later !== undefined && later >= firstFinding ? later - firstFinding : undefined)

  // The path, by zone.
  const engineeringKeys = new Set([...engineering].map(keyOf))
  const otAssetKeys = new Set(profile.assets.filter((a) => a.kind === 'ot').map((a) => `asset:${a.name.toUpperCase()}`))
  const zoneOf = (key: string, type: string, value: string): OtZone | null => {
    if (type === 'domain') return 'internet'
    if (type === 'ip') return isExternalIp(value) ? 'internet' : 'it'
    if (type !== 'host' && type !== 'device') return null
    if (engineeringKeys.has(key)) return 'hmi'
    return type === 'device' || otAssetKeys.has(key) ? 'plc' : 'it'
  }
  const nodes: OtNode[] = []
  const links: OtLink[] = []
  for (const e of incident?.entities ?? []) {
    const zone = zoneOf(e.key, e.type, e.value)
    if (zone) nodes.push({ key: e.key, label: e.value, zone, firstSeen: e.firstSeen, detectionIds: e.detectionIds, inAttack: true })
  }
  const known = new Set(nodes.map((n) => n.key))
  for (const r of incident?.relations ?? []) {
    // A domain's address is a fact about the domain, not a step taken by the attacker.
    if (!known.has(r.from) || !known.has(r.to) || r.labels.includes('resolusi DNS')) continue
    links.push({ from: r.from, to: r.to, firstSeen: r.firstSeen, label: r.labels[0] ?? '', normal: false })
  }
  // Normal control traffic is drawn too, since that is what the attack has to be told apart from.
  for (const t of talkers) {
    if (!trusted(t.src, t.dst)) continue
    const from = keyOf(t.src)
    const to = keyOf(t.dst)
    if (!known.has(from)) { nodes.push({ key: from, label: t.srcName, zone: 'hmi', firstSeen: t.firstSeen, detectionIds: [], inAttack: false }); known.add(from) }
    if (!known.has(to)) { nodes.push({ key: to, label: t.dstName, zone: 'plc', firstSeen: t.firstSeen, detectionIds: [], inAttack: false }); known.add(to) }
    links.push({ from, to, firstSeen: t.firstSeen, label: t.functions[0] ?? 'Modbus', normal: true })
  }
  const entry = incident?.path[0] ?? nodes.filter((n) => n.inAttack && n.zone === 'it').sort((a, b) => a.firstSeen - b.firstSeen)[0]?.key

  // What happened, in order: findings from the rules, and what the process did.
  const moments: OtMoment[] = []
  const byId = new Map(detections.map((d) => [d.id, d]))
  for (const id of incident?.detectionIds ?? []) {
    const d = byId.get(id)
    if (d) moments.push({ ts: d.ts, kind: 'temuan', title: d.title, level: d.level, detectionId: d.id, nodes: nodes.filter((n) => n.detectionIds.includes(id)).map((n) => n.key) })
  }
  for (const s of series) {
    if (s.kind === 'terukur') continue
    const unit = s.unit ? ` ${s.unit}` : ''
    const change = (ts: number, title: string) => moments.push({ ts, kind: 'proses', title, nodes: [keyOf(s.device)] })
    const valueOf = (ts: number) => s.points.find(([at]) => at >= ts)?.[1]
    for (const ep of s.episodes) {
      change(ep.from, `${s.label} menjadi ${valueOf(ep.from) ?? ep.peak}${unit}, di luar batas ${s.band!.min}–${s.band!.max}${unit}`)
      if (!ep.open) change(ep.to, `${s.label} kembali dalam batas: ${valueOf(ep.to) ?? ''}${unit}`)
    }
  }
  for (const run of runs) {
    run.spans.slice(1).forEach((span) => {
      const by = span.causeName ? `oleh ${span.causeName}` : 'tanpa perintah Modbus yang terlihat'
      moments.push({ ts: span.from, kind: 'proses', title: `${run.deviceName} ${span.running ? 'menyala lagi' : 'berhenti'}, ${by}`, nodes: [keyOf(run.device)] })
    })
  }
  moments.sort((a, b) => a.ts - b.ts)

  let spanFrom = Infinity
  let spanTo = -Infinity
  for (const e of modbus) { if (e.ts < spanFrom) spanFrom = e.ts; if (e.ts > spanTo) spanTo = e.ts }
  for (const e of contacts) { if (e.ts < spanFrom) spanFrom = e.ts; if (e.ts > spanTo) spanTo = e.ts }
  return {
    incidentId: incident?.id,
    hasValues,
    learnedTalkers,
    transactions: modbus.length,
    talkers,
    writes,
    series,
    runs,
    firstFinding,
    firstContact,
    firstWrite: firstUntrustedWrite,
    windowMs: windowOf(firstContact),
    windowToWriteMs: windowOf(firstUntrustedWrite),
    span: { from: spanFrom, to: spanTo },
    nodes,
    links,
    entry,
    moments: moments.slice(0, MAX_MOMENTS),
  }
}

export type OtCut = { node?: string; link?: [string, string] }
export type CutResult = { protectsOt: boolean; cutOff: string[]; otReached: string[]; avoided: number; total: number; deadline?: number; leadMs?: number }

function reach(a: OtAnalysis, cut: OtCut): Set<string> {
  const seen = new Set<string>()
  if (!a.entry) return seen
  const queue = [a.entry]
  seen.add(a.entry)
  while (queue.length) {
    const at = queue.shift()!
    // The entry host is already compromised when anyone can act, so isolating it stops what comes next, not it.
    if (at === cut.node) continue
    for (const l of a.links) {
      if (l.normal || l.from !== at || seen.has(l.to) || l.to === cut.node) continue
      if (cut.link && l.from === cut.link[0] && l.to === cut.link[1]) continue
      seen.add(l.to)
      queue.push(l.to)
    }
  }
  return seen
}

/** What the attack could still have reached with one host isolated or one path blocked. Only the paths in the logs count. */
export function simulateCut(a: OtAnalysis, cut: OtCut): CutResult {
  const before = reach(a, {})
  const after = reach(a, cut)
  const cutOff = [...before].filter((k) => !after.has(k))
  const zones = new Map(a.nodes.map((n) => [n.key, n]))
  const otReached = [...after].filter((k) => { const z = zones.get(k)?.zone; return z === 'hmi' || z === 'plc' })
  const nodesOf = new Map<string, string[]>()
  for (const n of a.nodes) for (const id of n.detectionIds) nodesOf.set(id, [...(nodesOf.get(id) ?? []), n.key])
  let avoided = 0
  for (const keys of nodesOf.values()) if (keys.every((k) => !after.has(k))) avoided++
  const incoming = a.links.filter((l) => !l.normal && (cut.link ? l.from === cut.link[0] && l.to === cut.link[1] : l.to === cut.node)).map((l) => l.firstSeen)
  const deadline = incoming.length ? Math.min(...incoming) : cut.node ? zones.get(cut.node)?.firstSeen : undefined
  return { protectsOt: otReached.length === 0, cutOff, otReached, avoided, total: nodesOf.size, deadline, leadMs: deadline !== undefined && a.firstFinding !== undefined ? Math.max(0, deadline - a.firstFinding) : undefined }
}

export type CutOption = { id: string; label: string; kind: 'host' | 'jalur'; cut: OtCut; result: CutResult }

/** The hosts and paths worth testing: IT hosts on the path, and every path that crosses into OT. */
export function cutOptions(a: OtAnalysis): CutOption[] {
  const byKey = new Map(a.nodes.map((n) => [n.key, n]))
  const options: CutOption[] = []
  for (const n of a.nodes) {
    if (n.zone !== 'it' || !n.inAttack) continue
    const cut = { node: n.key }
    options.push({ id: n.key, label: `Isolasi ${n.label}`, kind: 'host', cut, result: simulateCut(a, cut) })
  }
  for (const l of a.links) {
    const from = byKey.get(l.from)
    const to = byKey.get(l.to)
    if (l.normal || !from || !to || (to.zone !== 'hmi' && to.zone !== 'plc') || from.zone === 'hmi' || from.zone === 'plc') continue
    const cut = { link: [l.from, l.to] as [string, string] }
    options.push({ id: `${l.from}>${l.to}`, label: `Blokir ${from.label} → ${to.label}`, kind: 'jalur', cut, result: simulateCut(a, cut) })
  }
  return options
}

/**
 * Firewall lines that allow only the known-good Modbus talkers. These are commands an operator may paste
 * into a real device, and addresses here can come from a log anyone could forge, so only well-formed
 * IPv4 addresses ever reach them.
 */
export function segmentationRules(a: OtAnalysis): { mikrotik: string[]; iptables: string[] } | null {
  const good = a.talkers.filter((t) => (t.status === 'berwenang' || t.status === 'pola-utama') && ipv4ToInt(t.src) !== null && ipv4ToInt(t.dst) !== null)
  if (!good.length) return null
  const allow = [...new Map(good.map((t) => [`${t.src}>${t.dst}`, t])).values()]
  const mikrotik = allow.map((t) => `/ip firewall filter add chain=forward src-address=${t.src} dst-address=${t.dst} protocol=tcp dst-port=${MODBUS_PORT} action=accept`)
  mikrotik.push(`/ip firewall filter add chain=forward protocol=tcp dst-port=${MODBUS_PORT} action=drop`)
  // -I puts each line on top, so the block goes in first and the allows end up above it.
  const iptables = [`iptables -I FORWARD 1 -p tcp --dport ${MODBUS_PORT} -j DROP`, ...allow.map((t) => `iptables -I FORWARD 1 -s ${t.src} -d ${t.dst} -p tcp --dport ${MODBUS_PORT} -j ACCEPT`)]
  return { mikrotik, iptables }
}

/** The value of a series at a moment: the last point at or before it. */
export function valueAt(series: OtSeries, t: number): number | undefined {
  let found: number | undefined
  for (const [ts, value] of series.points) {
    if (ts > t) break
    found = value
  }
  return found
}

export function runningAt(run: OtRun, t: number): boolean | undefined {
  for (let i = run.spans.length - 1; i >= 0; i--) if (run.spans[i].from <= t) return run.spans[i].running
  return run.spans[0]?.running
}

/** What to do next, worked out from the analysis. Everything here touches operational systems, so the page states who must authorize it. */
export function otActions(a: OtAnalysis): { title: string; detail: string }[] {
  const actions: { title: string; detail: string }[] = []
  const intruders = [...new Set(a.talkers.filter((t) => t.status === 'tidak-berwenang' || t.status === 'menyimpang').map((t) => t.srcName))]
  if (intruders.length) actions.push({ title: `Putuskan ${intruders.join(', ')} dari perangkat OT`, detail: 'Blokir di firewall dengan aturan di bawah ini. Isolasi host itu dari jaringan, jangan dimatikan, agar bukti di memori tetap ada.' })
  if (a.writes.some((w) => !w.trusted)) actions.push({ title: 'Alihkan pengendali ke mode lokal atau manual, bila tersedia', detail: 'Jangan memutus daya pengendali secara mendadak. Ikuti prosedur operator peralatan.' })
  for (const s of a.series) {
    if (s.kind === 'terukur' || !s.episodes.length) continue
    const unit = s.unit ? ` ${s.unit}` : ''
    const latest = s.episodes.at(-1)!
    if (latest.open) {
      actions.push({
        title: s.lastGood ? `Kembalikan ${s.label} pada ${s.deviceName} ke ${s.lastGood.value}${unit}` : `Tentukan nilai yang benar untuk ${s.label} pada ${s.deviceName}`,
        detail: s.lastGood ? `Itu nilai normal terakhir, terbaca pukul ${fmtTime(s.lastGood.ts, false)} WIB. Nilai terakhir di log: ${s.last?.value ?? '?'}${unit}.` : 'Log tidak memuat nilai normal sebelum perubahan. Lihat dokumen pengendali.',
      })
    } else {
      actions.push({ title: `Periksa peralatan yang dicatu ${s.deviceName}`, detail: `${s.label} berada di luar batas selama ${fmtSpan(s.outOfBandMs)}, mencapai ${latest.peak}${unit}. Nilainya sudah kembali, tetapi kerusakannya tidak akan terlihat di log.` })
    }
  }
  for (const r of a.runs) {
    const latest = r.spans.at(-1)
    if (latest && !latest.running) actions.push({ title: `Periksa ${r.deviceName}: terakhir terlihat berhenti`, detail: `Sejak pukul ${fmtTime(latest.from, false)} WIB. Nyalakan kembali secara manual sesuai prosedur setelah penyebabnya ditangani.` })
  }
  return actions
}

/** The analysis in sentences, for reports. */
export function otSummaryLines(a: OtAnalysis): string[] {
  const lines: string[] = []
  const range = (s: OtSeries) => (s.band ? `${s.band.min}–${s.band.max}${s.unit ? ` ${s.unit}` : ''}` : '')
  if (a.windowMs !== undefined && a.firstFinding !== undefined && a.firstContact !== undefined) lines.push(`Jendela respons: ${fmtSpan(a.windowMs)} dari temuan pertama (${fmtTime(a.firstFinding, false)} WIB) sampai perangkat OT tersentuh host tidak berwenang (${fmtTime(a.firstContact, false)} WIB).`)
  const intruders = a.writes.filter((w) => !w.trusted)
  if (intruders.length) lines.push(`${intruders.length} perintah tulis Modbus dari host tidak berwenang: ${[...new Set(intruders.map((w) => w.srcName))].join(', ')}. ${intruders.filter((w) => w.effect === 'berlaku').length} di antaranya terlihat berlaku pada pembacaan berikutnya.`)
  for (const s of a.series) {
    if (s.kind === 'terukur' || !s.episodes.length) continue
    const worst = s.episodes.reduce((x, y) => (y.to - y.from > x.to - x.from ? y : x))
    lines.push(`${s.label} pada ${s.deviceName} di luar batas ${range(s)} selama ${fmtSpan(s.outOfBandMs)}, mencapai ${worst.peak}${s.unit ? ` ${s.unit}` : ''}.${s.lastGood ? ` Nilai normal terakhir sebelumnya: ${s.lastGood.value}${s.unit ? ` ${s.unit}` : ''}.` : ''}`)
  }
  for (const r of a.runs) if (r.stops) lines.push(`${r.deviceName} berhenti ${r.stops} kali, total ${fmtSpan(r.stoppedMs)}.`)
  if (lines.length) lines.push('Nilai di atas berasal dari lalu lintas Modbus yang terekam, bukan pengukuran langsung pada peralatan. Periksa kondisi fisik peralatan.')
  return lines
}
