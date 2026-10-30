import type { Detection, Incident, Level, NormalizedEvent } from '@/core/model'
import type { RuleMeta } from '@/core/detect/sigma'
import { LEVEL_RANK } from '@/core/labels'
import { TACTIC_LABEL, tacticOf } from '@/data/attack'
import { fmtDate, fmtNumber, fmtSpan, fmtTime } from '@/lib/format'

/**
 * Deterministic, plain-language descriptions of an incident, built only from its data. Used by
 * Ringkasan, Kasus and Laporan so all three tell the same story.
 */

export type StoryStep = {
  tactic: string
  label: string
  first: number
  last: number
  detections: Detection[]
  /** Where it happened, e.g. `WS-MIN-03` or `SRV-SATUAN-01 → PLC-GENSET-01`. */
  places: string[]
}

export function primaryTactic(d: Detection): string | undefined {
  for (const id of d.attack) {
    const tactic = tacticOf(id)
    if (tactic) return tactic
  }
  return undefined
}

/** IP -> asset name, from the incident's entities. */
function nameIndex(incident: Incident): Map<string, string> {
  const names = new Map<string, string>()
  for (const e of incident.entities) {
    if (e.type !== 'host' && e.type !== 'device') continue
    names.set(e.value, e.value)
    for (const ip of e.aliases) names.set(ip, e.value)
  }
  return names
}

function placeOf(d: Detection, eventsById: Map<string, NormalizedEvent>, names: Map<string, string>): string | undefined {
  const e = eventsById.get(d.eventIds[0])
  if (!e) return undefined
  const host = e.sourceKind === 'endpoint' ? e.host : undefined
  const src = e.srcIp ? names.get(e.srcIp) ?? e.srcIp : undefined
  const dst = e.dstIp ? names.get(e.dstIp) : undefined
  // Remote activity logged on the target, e.g. a logon on the server from a workstation.
  if (host && src && src !== host) return `${src} → ${host}`
  const from = host ?? src
  if (from && dst && dst !== from) return `${from} → ${dst}`
  return from ?? dst
}

/** Detections in time order, grouped into runs of the same ATT&CK tactic. */
export function incidentStory(incident: Incident, detectionsById: Map<string, Detection>, eventsById: Map<string, NormalizedEvent>): StoryStep[] {
  const names = nameIndex(incident)
  const dets = incident.detectionIds.map((id) => detectionsById.get(id)).filter((d): d is Detection => !!d).sort((a, b) => a.ts - b.ts)
  const steps: StoryStep[] = []
  for (const d of dets) {
    const tactic = primaryTactic(d) ?? 'Other'
    const place = placeOf(d, eventsById, names)
    const last = steps.at(-1)
    if (last && last.tactic === tactic) {
      last.detections.push(d)
      last.last = d.ts
      if (place && !last.places.includes(place)) last.places.push(place)
    } else {
      steps.push({ tactic, label: TACTIC_LABEL[tactic] ?? 'Aktivitas lain', first: d.ts, last: d.ts, detections: [d], places: place ? [place] : [] })
    }
  }
  return steps
}

export type PriorityAction = { text: string; ruleTitle: string; level: Level; detectionId: string }

/** Physical effects come first: a stopped generator matters before a password reset. */
const PHYSICAL_TACTICS = new Set(['Impact', 'Impair Process Control'])

/**
 * First response step of each critical/high rule in the incident: most severe first, then
 * physical (OT) effects, then earliest.
 */
export function priorityActions(incident: Incident, detectionsById: Map<string, Detection>, rules: Map<string, RuleMeta>, limit = 5): PriorityAction[] {
  const dets = incident.detectionIds.map((id) => detectionsById.get(id)).filter((d): d is Detection => !!d)
  const physical = (d: Detection) => (PHYSICAL_TACTICS.has(primaryTactic(d) ?? '') ? 1 : 0)
  const ordered = dets.filter((d) => LEVEL_RANK[d.level] >= LEVEL_RANK.high).sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || physical(b) - physical(a) || a.ts - b.ts)
  const out: PriorityAction[] = []
  const seenRules = new Set<string>()
  for (const d of ordered) {
    if (seenRules.has(d.ruleId)) continue
    seenRules.add(d.ruleId)
    const step = rules.get(d.ruleId)?.respons[0]
    if (step && !out.some((a) => a.text === step)) out.push({ text: step, ruleTitle: d.title, level: d.level, detectionId: d.id })
    if (out.length >= limit) break
  }
  return out
}

export function scorePercent(score: number): number {
  // Floor, so a score is never rounded up to a certainty it does not have.
  return Math.floor(score * 100)
}

/** Hosts and OT devices the incident touched. A common server counts only where activity happened on it. */
export function affectedAssets(incident: Incident) {
  return incident.entities.filter((e) => (e.type === 'host' || e.type === 'device') && (e.actor || !e.common))
}

/** Counts used in summaries. */
export function incidentFacts(incident: Incident) {
  const assets = affectedAssets(incident).length
  const accounts = incident.entities.filter((e) => e.type === 'user').length
  const external = incident.entities.filter((e) => e.type === 'ip' || e.type === 'domain').length
  return { detections: incident.detectionIds.length, rules: incident.ruleIds.length, assets, accounts, external, span: incident.lastSeen - incident.firstSeen }
}

/** Executive summary paragraph in Bahasa Indonesia. */
export function incidentSummary(incident: Incident, steps: StoryStep[]): string {
  const f = incidentFacts(incident)
  const path = incident.path.map((key) => incident.entities.find((e) => e.key === key)?.value ?? key)
  const window = f.span > 0
    ? `Antara ${fmtTime(incident.firstSeen, false)} dan ${fmtTime(incident.lastSeen, false)} WIB tanggal ${fmtDate(incident.firstSeen)} (${fmtSpan(f.span)})`
    : `Pada ${fmtTime(incident.firstSeen, false)} WIB tanggal ${fmtDate(incident.firstSeen)}`
  const parts = [
    `${window}, SIGAP mencatat ${fmtNumber(f.detections)} temuan dari ${fmtNumber(f.rules)} aturan deteksi yang saling terkait melalui ${f.assets} aset dan ${f.accounts} akun.`,
  ]
  if (path.length >= 2) parts.push(`Rangkaian dimulai di ${path[0]}, berlanjut ke ${path.slice(1, -1).length ? `${path.slice(1, -1).join(', ')}, hingga ` : ''}${path.at(-1)}.`)
  else if (path.length === 1) parts.push(`Aktivitas terpusat di ${path[0]}.`)
  if (steps.length) parts.push(`Tahap yang teramati: ${[...new Set(steps.map((s) => s.label))].join(', ')}.`)
  parts.push(`Tingkat keyakinan ${scorePercent(incident.score)}% dihitung dari ${incident.scoreBreakdown.length} unsur bukti. Keterkaitan antar-temuan disimpulkan dari entitas yang sama; sebab-akibatnya tetap perlu diverifikasi.`)
  return parts.join(' ')
}
