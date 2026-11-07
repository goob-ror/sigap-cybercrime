import type { Assessment, Detection, EntityType, Incident, IncidentEntity, Level, NormalizedEvent, Relation, ScoreTerm, Signal, SourceKind, UnitProfile } from '@/core/model'
import { KIND_LABEL, LEVEL_RANK } from '@/core/labels'
import { cleanIp } from '@/core/ingest/util'
import { ipInCidr, isExternalIp, isPrivateIp } from '@/core/net'
import { TACTIC_LABEL, TACTIC_ORDER, tacticOf } from '@/data/attack'

/**
 * Correlation: detections that share an entity (asset, account, IP, domain, file hash) within
 * a time window become one incident, and each incident gets an explainable score.
 *
 * Linking rules, in plain terms:
 * - IP addresses are tied to host names using the unit's asset inventory and what the logs show
 *   (Sysmon network events, remote logons), so `10.20.4.13` and `WS-MIN-03` are one asset.
 * - An entity seen with at least half of the hosts (DNS server, file server, shared account) is
 *   "common". It links two detections only where it is the host the detection was logged on or
 *   the source of the activity; otherwise every detection would merge through the DNS server.
 * - File names alone never link (many files share a name); hashes do.
 */

export const LINK_WINDOW_MS = 24 * 60 * 60_000
export const LEVEL_WEIGHT: Record<Level, number> = { critical: 0.6, high: 0.4, medium: 0.2, low: 0.1, informational: 0.05 }
/** What a finding adds depends on how much it proves: most attempts fail, and admins run the same tools. */
export const SIGNAL_FACTOR: Record<Signal, number> = { kuat: 1, ambigu: 0.5, percobaan: 0.25 }
export const KILLCHAIN_WEIGHT = 0.3
export const MULTI_SOURCE_WEIGHT = 0.2
/** A common entity is seen with at least this many hosts (and at least half of them). */
export const COMMON_MIN_HOSTS = 4

export type InventoryEntry = { name: string; source: 'profil' | 'log' }

type Context = {
  /** IP -> asset name. */
  inventory: Map<string, InventoryEntry>
  otAssets: Set<string>
  otSubnets: string[]
}

type EntityRef = { key: string; type: EntityType; value: string }
type Occurrence = EntityRef & { actor: boolean }

function hostName(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const name = value.trim().replace(/^\\+/, '')
  if (!name || name === '-') return undefined
  return name.split('.')[0].toUpperCase()
}

/** Learns IP -> host from the logs, then applies the unit's asset inventory on top. */
export function buildInventory(events: readonly NormalizedEvent[], profile: UnitProfile): Map<string, InventoryEntry> {
  const votes = new Map<string, Map<string, number>>()
  const vote = (ip: string | undefined, host: string | undefined) => {
    if (!ip || !host || !isPrivateIp(ip)) return
    const forIp = votes.get(ip) ?? new Map<string, number>()
    forIp.set(host, (forIp.get(host) ?? 0) + 1)
    votes.set(ip, forIp)
  }
  for (const e of events) {
    if (e.dataset !== 'winevent') continue
    const f = e.fields
    // Sysmon 3: an outbound connection's source address belongs to the host that logged it.
    if (e.logsource.category === 'network_connection' && String(f.Initiated).toLowerCase() === 'true') vote(cleanIp(f.SourceIp), e.host)
    // Network and RDP logons name the client workstation and its address.
    if ((f.EventID === 4624 || f.EventID === 4625) && (Number(f.LogonType) === 3 || Number(f.LogonType) === 10)) vote(cleanIp(f.IpAddress), hostName(f.WorkstationName))
  }
  const inventory = new Map<string, InventoryEntry>()
  for (const [ip, hosts] of votes) {
    const [name] = [...hosts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]
    inventory.set(ip, { name, source: 'log' })
  }
  for (const a of profile.assets) inventory.set(a.ip, { name: a.name.toUpperCase(), source: 'profil' })
  return inventory
}

function asset(ctx: Context, name: string): EntityRef {
  return { key: `asset:${name}`, type: ctx.otAssets.has(name) ? 'device' : 'host', value: name }
}

function canonIp(ctx: Context, ip: string): EntityRef {
  const known = ctx.inventory.get(ip)
  if (known) return asset(ctx, known.name)
  if (ctx.otSubnets.some((cidr) => ipInCidr(ip, cidr))) return { key: `asset:${ip}`, type: 'device', value: ip }
  return { key: `ip:${ip}`, type: 'ip', value: ip }
}

/** IPv4 answers of a DNS event (Sysmon 22 `QueryResults`, Zeek `answers`). */
function answerIps(e: NormalizedEvent): string[] {
  if (!e.domain) return []
  const text = `${e.fields.QueryResults ?? ''} ${e.fields.answers ?? ''}`
  return [...new Set(text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [])]
}

/**
 * Host the event happened on. Endpoint and server logs are written by the host itself; firewall
 * and sensor logs name the device that logged the traffic, which is not a party to it.
 */
function recordHost(e: NormalizedEvent): string | undefined {
  return e.sourceKind === 'endpoint' || e.sourceKind === 'server' ? e.host : undefined
}

function eventEntities(e: NormalizedEvent, ctx: Context): Occurrence[] {
  const out: Occurrence[] = []
  const host = recordHost(e)
  if (host) out.push({ ...asset(ctx, host), actor: true })
  if (e.srcIp) out.push({ ...canonIp(ctx, e.srcIp), actor: true })
  if (e.dstIp) out.push({ ...canonIp(ctx, e.dstIp), actor: false })
  if (e.user) out.push({ key: `user:${e.user}`, type: 'user', value: e.user, actor: false })
  if (e.domain) out.push({ key: `domain:${e.domain}`, type: 'domain', value: e.domain, actor: false })
  for (const ip of answerIps(e)) out.push({ ...canonIp(ctx, ip), actor: false })
  if (e.file?.sha256) out.push({ key: `hash:${e.file.sha256}`, type: 'hash', value: e.file.sha256, actor: false })
  if (e.file?.name) out.push({ key: `file:${e.file.name.toLowerCase()}`, type: 'file', value: e.file.name, actor: false })
  return out
}

/** Entities seen with at least half of all hosts (and at least `COMMON_MIN_HOSTS`). */
function commonEntities(events: readonly NormalizedEvent[], ctx: Context): Set<string> {
  const hostsByKey = new Map<string, Set<string>>()
  const hosts = new Set<string>()
  for (const e of events) {
    const host = recordHost(e)
    const anchor = host ? asset(ctx, host).key : e.srcIp ? canonIp(ctx, e.srcIp).key : undefined
    if (!anchor) continue
    hosts.add(anchor)
    for (const o of eventEntities(e, ctx)) {
      if (o.key === anchor) continue
      const set = hostsByKey.get(o.key) ?? new Set<string>()
      set.add(anchor)
      hostsByKey.set(o.key, set)
    }
  }
  const threshold = Math.max(COMMON_MIN_HOSTS, Math.ceil(hosts.size / 2))
  return new Set([...hostsByKey].filter(([, set]) => set.size >= threshold).map(([key]) => key))
}

const str = (v: unknown) => (v === null || v === undefined || v === '' ? undefined : String(v))

function netLabel(e: NormalizedEvent): string {
  if (e.ot?.func) return `Modbus ${e.ot.func}`
  const service = str(e.fields.service)?.toUpperCase()
  if (e.dstPort === undefined) return service ?? 'koneksi'
  return `${service ? `${service} ` : ''}:${e.dstPort}`
}

function remoteLabel(e: NormalizedEvent): string {
  if (e.dataset === 'web.access') return `HTTP ${str(e.fields['cs-method']) ?? ''}`.trim()
  if (e.dataset === 'linux.auth') return e.fields.outcome === 'failure' ? 'SSH gagal' : e.fields.outcome === 'success' ? 'SSH login' : 'akses'
  switch (e.fields.EventID) {
    case 4624: return 'logon'
    case 4625: return 'logon gagal'
    case 4648: return 'logon eksplisit'
    case 5140: return `share ${str(e.fields.ShareName)?.split('\\').pop() ?? ''}`.trim()
    default: return 'akses'
  }
}

function userLabel(e: NormalizedEvent): string {
  if (e.dataset === 'linux.auth') {
    if (e.fields.new_user) return 'akun dibuat'
    if (e.fields.group) return 'ditambah ke grup'
    if (e.fields.command) return 'sudo'
    return e.fields.outcome === 'failure' ? 'login gagal' : e.fields.outcome === 'success' ? 'login' : 'akun'
  }
  switch (e.fields.EventID) {
    case 4720: return 'akun dibuat'
    case 4625: return 'logon gagal'
    case 4624: return 'logon'
    default: return 'akun'
  }
}

function eventRelations(e: NormalizedEvent, ctx: Context): [EntityRef, EntityRef, string][] {
  const out: [EntityRef, EntityRef, string][] = []
  const recorded = recordHost(e)
  const host = recorded ? asset(ctx, recorded) : undefined
  const src = e.srcIp ? canonIp(ctx, e.srcIp) : undefined
  const dst = e.dstIp ? canonIp(ctx, e.dstIp) : undefined
  const actor = host ?? src
  if (src && dst && src.key !== dst.key) out.push([src, dst, netLabel(e)])
  else if (host && src && src.key !== host.key) out.push([src, host, remoteLabel(e)])
  else if (host && dst && dst.key !== host.key) out.push([host, dst, netLabel(e)])
  if (e.user && actor) out.push([{ key: `user:${e.user}`, type: 'user', value: e.user }, actor, userLabel(e)])
  if (e.domain && actor) {
    const domain: EntityRef = { key: `domain:${e.domain}`, type: 'domain', value: e.domain }
    out.push([actor, domain, e.dataset === 'zeek.http' ? 'HTTP' : 'DNS'])
    for (const ip of answerIps(e)) out.push([domain, canonIp(ctx, ip), 'resolusi DNS'])
  }
  if (e.file?.name && host) out.push([host, { key: `file:${e.file.name.toLowerCase()}`, type: 'file', value: e.file.name }, 'berkas'])
  else if (e.file?.sha256 && host) out.push([host, { key: `hash:${e.file.sha256}`, type: 'hash', value: e.file.sha256 }, 'berkas'])
  return out
}

/** FNV-1a, for short stable ids. */
function hash32(text: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 0x01000193)
  return (h >>> 0).toString(16).padStart(8, '0')
}

const maxLevel = (levels: Level[]) => levels.reduce((a, b) => (LEVEL_RANK[b] > LEVEL_RANK[a] ? b : a), 'informational' as Level)

/** Longest run of tactics whose first appearances follow the kill-chain order. */
export function killChain(detections: readonly Detection[]): string[] {
  const first = new Map<string, number>()
  for (const d of [...detections].sort((a, b) => a.ts - b.ts)) for (const id of d.attack) {
    const tactic = tacticOf(id)
    if (tactic && !first.has(tactic)) first.set(tactic, d.ts)
  }
  const seq = [...first].sort((a, b) => a[1] - b[1]).map(([t]) => t).filter((t) => TACTIC_ORDER.includes(t))
  const rank = seq.map((t) => TACTIC_ORDER.indexOf(t))
  // O(n²) longest increasing subsequence; n is at most the number of tactics.
  const len = rank.map(() => 1)
  const prev = rank.map(() => -1)
  for (let i = 0; i < rank.length; i++) for (let j = 0; j < i; j++) {
    if (rank[j] < rank[i] && len[j] + 1 > len[i]) {
      len[i] = len[j] + 1
      prev[i] = j
    }
  }
  let end = len.indexOf(Math.max(...len))
  const out: string[] = []
  while (end !== -1) {
    out.unshift(seq[end])
    end = prev[end]
  }
  return out
}

/** Findings written before signals existed, and ones built by hand, count in full. */
const signalOf = (d: Detection): Signal => d.signal ?? 'kuat'

/** The strongest thing the findings support. */
export function assessIncident(detections: readonly Detection[]): Assessment {
  if (detections.some((d) => signalOf(d) === 'kuat')) return 'indikasi-kuat'
  return detections.some((d) => signalOf(d) === 'ambigu') ? 'perlu-konfirmasi' : 'hanya-percobaan'
}

/**
 * One term per distinct rule (repeat hits of the same rule are not independent evidence), plus
 * bonuses. A sequence or several log sources support a conclusion only when something in them is hard
 * to explain away: a scanner runs through recon and exploit patterns whether or not it gets anywhere,
 * and an admin's day looks like a kill chain too.
 */
export function scoreTerms(detections: readonly Detection[], sourceKinds: readonly SourceKind[]): ScoreTerm[] {
  const byRule = new Map<string, Detection[]>()
  for (const d of detections) {
    const list = byRule.get(d.ruleId)
    if (list) list.push(d)
    else byRule.set(d.ruleId, [d])
  }
  const weightOf = (d: Detection) => LEVEL_WEIGHT[d.level] * SIGNAL_FACTOR[signalOf(d)]
  const terms: ScoreTerm[] = [...byRule.values()]
    .sort((a, b) => weightOf(b[0]) - weightOf(a[0]) || a[0].ts - b[0].ts)
    .map((list) => ({ kind: 'rule', label: list[0].title, weight: weightOf(list[0]), level: list[0].level, ...(list[0].signal ? { signal: list[0].signal } : {}), count: list.length }))
  if (assessIncident(detections) !== 'indikasi-kuat') return terms
  const chain = killChain(detections)
  if (chain.length >= 3) terms.push({ kind: 'killchain', label: `${chain.length} tahap ATT&CK berurutan: ${chain.map((t) => TACTIC_LABEL[t] ?? t).join(' → ')}`, weight: KILLCHAIN_WEIGHT })
  if (sourceKinds.length >= 2) terms.push({ kind: 'sources', label: `Dikuatkan ${sourceKinds.length} jenis sumber log: ${sourceKinds.map((k) => KIND_LABEL[k]).join(', ')}`, weight: MULTI_SOURCE_WEIGHT })
  return terms
}

/** `1 − Π(1 − wᵢ)`: orders the queue, most pressing first. It is not the probability of an attack. */
export function scoreOf(terms: readonly ScoreTerm[]): number {
  return 1 - terms.reduce((rest, t) => rest * (1 - t.weight), 1)
}

type TitleInput = {
  assessment: Assessment
  tactics: string[]
  path: IncidentEntity[]
  hasOt: boolean
  server: boolean
  /** External sources, in order of first appearance. */
  attackers: string[]
  /** External source of the first finding that is hard to explain away. */
  provenAttacker: string | undefined
  top: Detection
}

/** The title says only what the evidence supports, because it is what a commander reads first. */
function incidentTitle({ assessment, tactics, path, hasOt, server, attackers, provenAttacker, top }: TitleInput): string {
  const start = path[0]?.value
  const at = start ? ` di ${start}` : ''
  if (assessment === 'hanya-percobaan') {
    const who = attackers.length > 1 ? `dari ${attackers.length} alamat luar` : attackers[0] ? `dari ${attackers[0]}` : ''
    if (start) return `Percobaan serangan terhadap ${start} ${who}, belum ada tanda berhasil`.replace(/\s+,/, ',')
    return `${top.title}, belum ada tanda berhasil`
  }
  if (assessment === 'perlu-konfirmasi') {
    // "Antara", not "dari": the path is in order of first appearance, which is not always the direction.
    if (path.length >= 2) return `Perlu konfirmasi: aktivitas jarak jauh antara ${path[0].value} dan ${path.at(-1)!.value}, bisa pekerjaan admin`
    return `Perlu konfirmasi: ${top.title}${at}`
  }
  if (path.length >= 2 && hasOt) return `Serangan lintas IT–OT berawal di ${start}`
  if (path.length >= 2) return tactics.includes('Lateral Movement') ? `Pergerakan lateral berawal di ${start}` : `Rangkaian serangan di ${path.length} aset, berawal di ${start}`
  const attacker = provenAttacker ?? attackers[0]
  if (server && attacker && start) return `Peretasan server ${start} dari ${attacker}`
  return `${top.title}${at}`
}

/** No incident reads as more severe than its evidence: only findings that are hard to explain away rank above Sedang. */
function incidentLevel(detections: readonly Detection[], assessment: Assessment): Level {
  const level = maxLevel(detections.map((d) => d.level))
  return assessment !== 'indikasi-kuat' && LEVEL_RANK[level] > LEVEL_RANK.medium ? 'medium' : level
}

export type CorrelationResult = { incidents: Incident[]; inventory: Map<string, InventoryEntry>; common: Set<string> }

export function correlate(detections: readonly Detection[], events: readonly NormalizedEvent[], profile: UnitProfile, windowMs = LINK_WINDOW_MS): CorrelationResult {
  const inventory = buildInventory(events, profile)
  const ctx: Context = { inventory, otAssets: new Set(profile.assets.filter((a) => a.kind === 'ot').map((a) => a.name.toUpperCase())), otSubnets: profile.otSubnets }
  const common = commonEntities(events, ctx)
  const eventsById = new Map(events.map((e) => [e.id, e]))
  const sorted = [...detections].sort((a, b) => a.ts - b.ts)
  const detEvents = sorted.map((d) => d.eventIds.map((id) => eventsById.get(id)).filter((e): e is NormalizedEvent => !!e))

  // Union-find: link each detection to the previous one that shares a linking entity within the window.
  const parent = sorted.map((_, i) => i)
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])))
  const lastByKey = new Map<string, { i: number; ts: number }>()
  sorted.forEach((d, i) => {
    const keys = new Set<string>()
    for (const e of detEvents[i]) for (const o of eventEntities(e, ctx)) {
      if (o.type !== 'file' && (o.actor || !common.has(o.key))) keys.add(o.key)
    }
    for (const key of keys) {
      const last = lastByKey.get(key)
      if (last && d.ts - last.ts <= windowMs) parent[find(i)] = find(last.i)
      lastByKey.set(key, { i, ts: d.ts })
    }
  })

  const groups = new Map<number, number[]>()
  sorted.forEach((_, i) => {
    const root = find(i)
    const members = groups.get(root)
    if (members) members.push(i)
    else groups.set(root, [i])
  })

  const ipsByName = new Map<string, string[]>()
  for (const [ip, entry] of inventory) ipsByName.set(entry.name, [...(ipsByName.get(entry.name) ?? []), ip])

  const incidents = [...groups.values()].map((members): Incident => {
    const dets = members.map((i) => sorted[i])
    const entities = new Map<string, IncidentEntity>()
    // Labels keep the most severe level that produced them, so the worst action is listed first.
    const relations = new Map<string, Relation & { labelLevel: Map<string, Level>; detSet: Set<string> }>()
    const kinds = new Set<SourceKind>()
    // An entity can appear in every finding of a big incident, so membership is not checked by scanning a list.
    const seenFindings = new Map<string, Set<string>>()
    const addEntity = (ref: EntityRef, actor: boolean, detectionId: string, ts: number) => {
      const entity = entities.get(ref.key)
      if (entity) {
        entity.actor ||= actor
        const seen = seenFindings.get(ref.key)!
        if (!seen.has(detectionId)) {
          seen.add(detectionId)
          entity.detectionIds.push(detectionId)
        }
        return
      }
      const aliases = ref.key.startsWith('asset:') ? (ipsByName.get(ref.value) ?? []) : []
      seenFindings.set(ref.key, new Set([detectionId]))
      entities.set(ref.key, { ...ref, aliases, detectionIds: [detectionId], firstSeen: ts, actor, common: common.has(ref.key) })
    }
    for (const i of members) {
      const d = sorted[i]
      for (const e of detEvents[i]) {
        kinds.add(e.sourceKind)
        for (const o of eventEntities(e, ctx)) addEntity(o, o.actor, d.id, e.ts)
        for (const [from, to, label] of eventRelations(e, ctx)) {
          addEntity(from, false, d.id, e.ts)
          addEntity(to, false, d.id, e.ts)
          const id = `${from.key}>${to.key}`
          const rel = relations.get(id) ?? { from: from.key, to: to.key, labels: [], count: 0, level: 'informational' as Level, detectionIds: [], firstSeen: e.ts, labelLevel: new Map<string, Level>(), detSet: new Set<string>() }
          rel.count++
          const prevLevel = rel.labelLevel.get(label)
          if (!prevLevel || LEVEL_RANK[d.level] > LEVEL_RANK[prevLevel]) rel.labelLevel.set(label, d.level)
          rel.detSet.add(d.id)
          if (LEVEL_RANK[d.level] > LEVEL_RANK[rel.level]) rel.level = d.level
          relations.set(id, rel)
        }
      }
    }

    const sourceKinds = (['endpoint', 'server', 'network', 'ot', 'mobile'] as SourceKind[]).filter((k) => kinds.has(k))
    const terms = scoreTerms(dets, sourceKinds)
    const entityList = [...entities.values()].sort((a, b) => a.firstSeen - b.firstSeen)
    const path = entityList.filter((e) => (e.type === 'host' && e.actor) || e.type === 'device').map((e) => e.key).slice(0, 6)
    const top = [...dets].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts)[0]
    const hasOt = sourceKinds.includes('ot') || path.some((k) => entities.get(k)!.type === 'device')
    // Outside addresses acting on a server we have logs from: an attack on a public-facing service.
    const attackers = sourceKinds.includes('server') ? entityList.filter((e) => e.type === 'ip' && e.actor && !e.common && isExternalIp(e.value)).map((e) => e.value) : []
    // The one to name is whoever did the part that worked, not the first scanner in the log.
    const provenIndex = members.find((i) => signalOf(sorted[i]) === 'kuat' && detEvents[i].some((e) => e.srcIp && attackers.includes(e.srcIp)))
    const provenAttacker = provenIndex === undefined ? undefined : detEvents[provenIndex].find((e) => e.srcIp && attackers.includes(e.srcIp))?.srcIp
    const assessment = assessIncident(dets)
    const tactics = TACTIC_ORDER.filter((t) => dets.some((d) => d.attack.some((id) => tacticOf(id) === t)))
    const title = incidentTitle({ assessment, tactics, path: path.map((k) => entities.get(k)!), hasOt, server: sourceKinds.includes('server'), attackers, provenAttacker, top })

    return {
      id: `inc-${hash32(dets[0].id)}`,
      title,
      assessment,
      path,
      level: incidentLevel(dets, assessment),
      detectionIds: dets.map((d) => d.id),
      ruleIds: [...new Set(dets.map((d) => d.ruleId))],
      entities: entityList,
      relations: [...relations.values()].map(({ labelLevel, detSet, ...r }) => ({
        ...r,
        labels: [...labelLevel].sort((a, b) => LEVEL_RANK[b[1]] - LEVEL_RANK[a[1]]).map(([label]) => label),
        detectionIds: [...detSet],
      })),
      tactics,
      sourceKinds,
      score: scoreOf(terms),
      scoreBreakdown: terms,
      firstSeen: dets[0].ts,
      lastSeen: dets.at(-1)!.ts,
    }
  })

  incidents.sort((a, b) => b.score - a.score || a.firstSeen - b.firstSeen)
  return { incidents, inventory, common }
}
