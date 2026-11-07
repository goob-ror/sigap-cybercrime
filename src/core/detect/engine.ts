import type { Detection, NormalizedEvent } from '@/core/model'
import type { CompiledRule, RuleMeta } from '@/core/detect/sigma'
import type { NativeRule } from '@/core/detect/native'

export type RulePack = {
  sigma: CompiledRule[]
  native: NativeRule[]
  skipped: { source: string; reason: string }[]
}

/** `attack.t1059.001` -> `T1059.001`; tactic tags are ignored. */
export function techniquesFromTags(tags: string[]): string[] {
  return tags.flatMap((tag) => {
    const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(tag)
    return m ? [m[1].toUpperCase()] : []
  })
}

export function ruleCatalog(pack: RulePack): Map<string, RuleMeta> {
  return new Map([...pack.sigma, ...pack.native].map((r) => [r.meta.id, r.meta]))
}

/** Attempts from one source are one finding until it pauses this long. */
const FOLD_GAP_MS = 10 * 60_000
/** Events listed on a folded finding; the true count stays in `matched`. A sqlmap run is tens of thousands. */
const FOLD_MAX_EVENTS = 2000
const COUNT_FIELD = 'Jumlah kejadian'

/**
 * Folds repeated attempts by one source against one host into one finding. An attacker's noisy scanner
 * otherwise writes a finding per request, which buries the rest and stalls the browser doing the analysis.
 */
export function foldAttempts(detections: readonly Detection[], eventOf: (id: string) => NormalizedEvent | undefined): Detection[] {
  const out: Detection[] = []
  const open = new Map<string, { detection: Detection; last: number; count: number }>()
  for (const d of [...detections].sort((a, b) => a.ts - b.ts)) {
    if (d.signal !== 'percobaan' || d.eventIds.length !== 1 || d.ruleId.startsWith('sigap-native-')) {
      out.push(d)
      continue
    }
    const event = eventOf(d.eventIds[0])
    const key = `${d.ruleId}|${event?.host ?? ''}|${event?.srcIp ?? ''}`
    const current = open.get(key)
    if (current && d.ts - current.last <= FOLD_GAP_MS) {
      current.last = d.ts
      current.count++
      if (current.detection.eventIds.length < FOLD_MAX_EVENTS) current.detection.eventIds.push(d.eventIds[0])
      current.detection.matched[COUNT_FIELD] = String(current.count)
      continue
    }
    const detection: Detection = { ...d, eventIds: [...d.eventIds], matched: { ...d.matched } }
    open.set(key, { detection, last: d.ts, count: 1 })
    out.push(detection)
  }
  return out
}

/** Every rule over the events, one finding per match. Detection ids are deterministic, so re-runs are idempotent. */
export function matchRules(events: readonly NormalizedEvent[], pack: RulePack): Detection[] {
  const detections: Detection[] = []
  for (const rule of pack.sigma) {
    const attack = techniquesFromTags(rule.meta.tags)
    for (const event of events) {
      const matched = rule.match(event)
      if (!matched) continue
      detections.push({ id: `${rule.meta.id}:${event.id}`, ruleId: rule.meta.id, title: rule.meta.title, level: rule.meta.level, signal: rule.meta.signal, attack, eventIds: [event.id], matched, ts: event.ts })
    }
  }
  for (const rule of pack.native) {
    const attack = techniquesFromTags(rule.meta.tags)
    for (const hit of rule.run(events)) {
      detections.push({ id: `${rule.meta.id}:${hit.eventIds[0]}`, ruleId: rule.meta.id, title: rule.meta.title, level: rule.meta.level, signal: rule.meta.signal, attack, eventIds: hit.eventIds, matched: hit.matched, ts: hit.ts })
    }
  }
  return detections.sort((a, b) => a.ts - b.ts)
}

/** Findings for a set of events, with repeated attempts folded. */
export function runDetections(events: readonly NormalizedEvent[], pack: RulePack): Detection[] {
  const detections = matchRules(events, pack)
  if (!detections.some((d) => d.signal === 'percobaan')) return detections
  const byId = new Map(events.map((e) => [e.id, e]))
  return foldAttempts(detections, (id) => byId.get(id))
}
