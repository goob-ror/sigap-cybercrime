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

/** Runs every rule over the events. Detection ids are deterministic, so re-runs are idempotent. */
export function runDetections(events: readonly NormalizedEvent[], pack: RulePack): Detection[] {
  const detections: Detection[] = []
  for (const rule of pack.sigma) {
    const attack = techniquesFromTags(rule.meta.tags)
    for (const event of events) {
      const matched = rule.match(event)
      if (!matched) continue
      detections.push({ id: `${rule.meta.id}:${event.id}`, ruleId: rule.meta.id, title: rule.meta.title, level: rule.meta.level, attack, eventIds: [event.id], matched, ts: event.ts })
    }
  }
  for (const rule of pack.native) {
    const attack = techniquesFromTags(rule.meta.tags)
    for (const hit of rule.run(events)) {
      detections.push({ id: `${rule.meta.id}:${hit.eventIds[0]}`, ruleId: rule.meta.id, title: rule.meta.title, level: rule.meta.level, attack, eventIds: hit.eventIds, matched: hit.matched, ts: hit.ts })
    }
  }
  return detections.sort((a, b) => a.ts - b.ts)
}
