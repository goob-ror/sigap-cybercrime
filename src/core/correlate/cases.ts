import type { Case, Incident } from '@/core/model'

/**
 * Keeps cases attached to incidents when incidents are recomputed after an import. A new incident
 * inherits the case of any earlier incident it shares a detection with, so status, notes and
 * follow-ups survive. If one incident now covers several cases, the oldest case absorbs the rest.
 */

export const SYSTEM_ACTOR = 'SIGAP'

export function caseNumber(id: string): number {
  return Number(/(\d+)$/.exec(id)?.[1] ?? 0)
}

export function formatCaseId(n: number): string {
  return `KSS-${String(n).padStart(4, '0')}`
}

function newCase(id: string, incident: Incident, now: number): Case {
  return {
    id,
    title: incident.title,
    status: 'Open',
    assignee: '',
    notes: '',
    createdAt: now,
    updatedAt: now,
    incidentIds: [],
    playbookProgress: {},
    followUps: {},
    history: [{ ts: now, actor: SYSTEM_ACTOR, text: `Kasus dibuat otomatis dari ${incident.detectionIds.length} temuan terkorelasi` }],
  }
}

function absorb(into: Case, other: Case, now: number) {
  into.followUps = { ...other.followUps, ...into.followUps }
  into.playbookProgress = { ...other.playbookProgress, ...into.playbookProgress }
  if (other.notes.trim()) into.notes = into.notes.trim() ? `${into.notes}\n\n[${other.id}] ${other.notes}` : other.notes
  if (!into.assignee) into.assignee = other.assignee
  into.history = [...into.history, ...other.history, { ts: now, actor: SYSTEM_ACTOR, text: `${other.id} digabung ke kasus ini karena insidennya kini terhubung` }].sort((a, b) => a.ts - b.ts)
}

export type Reconciled = { incidents: Incident[]; put: Case[]; remove: string[] }

export function reconcileCases(incidents: readonly Incident[], previous: readonly Incident[], existing: readonly Case[], now: number): Reconciled {
  const caseByDetection = new Map<string, string>()
  for (const inc of previous) if (inc.caseId) for (const id of inc.detectionIds) caseByDetection.set(id, inc.caseId)
  const cases = new Map(existing.map((c) => [c.id, structuredClone(c)]))
  const remove: string[] = []
  let next = Math.max(0, ...existing.map((c) => caseNumber(c.id))) + 1

  const out = incidents.map((inc) => ({ ...inc }))
  // Oldest incident first, so case numbers follow the order things happened.
  for (const inc of [...out].sort((a, b) => a.firstSeen - b.firstSeen)) {
    const ids = [...new Set(inc.detectionIds.map((id) => caseByDetection.get(id)))]
      .filter((id): id is string => !!id && cases.has(id))
      .sort((a, b) => cases.get(a)!.createdAt - cases.get(b)!.createdAt || caseNumber(a) - caseNumber(b))
    let target: Case
    if (ids.length === 0) {
      target = newCase(formatCaseId(next++), inc, now)
      cases.set(target.id, target)
    } else {
      target = cases.get(ids[0])!
      for (const otherId of ids.slice(1)) {
        absorb(target, cases.get(otherId)!, now)
        cases.delete(otherId)
        remove.push(otherId)
      }
    }
    inc.caseId = target.id
  }

  for (const c of cases.values()) {
    const own = out.filter((i) => i.caseId === c.id).sort((a, b) => b.score - a.score)
    c.incidentIds = own.map((i) => i.id)
    if (own.length) c.title = own[0].title
  }
  return { incidents: out, put: [...cases.values()], remove }
}
