import { useMemo } from 'react'
import { useLiveQuery } from 'dexie-react-hooks'
import { db } from '@/db/db'
import type { Artifact, Case, Detection, Incident, NormalizedEvent } from '@/core/model'
import type { EventStats } from '@/core/stats'
import type { ScenarioCheck } from '@/workers/protocol'

export type Investigation = {
  loaded: boolean
  eventCount: number
  detections: Detection[]
  detectionsById: Map<string, Detection>
  /** Only the events referenced by detections (the full set can be very large). */
  eventsById: Map<string, NormalizedEvent>
  imports: Artifact[]
  /** Highest score first. */
  incidents: Incident[]
  incidentOf: Map<string, Incident>
  cases: Case[]
  caseById: Map<string, Case>
  stats: EventStats | null
  check: ScenarioCheck | null
  /** Engine version that produced the stored results, if any. */
  engine: string | null
}

/** Live view of the local investigation data; re-renders whenever the worker or a case edit writes. */
export function useInvestigation(): Investigation {
  const data = useLiveQuery(async () => {
    const [eventCount, detections, imports, incidents, cases, meta] = await Promise.all([
      db.events.count(),
      db.detections.orderBy('ts').toArray(),
      db.artifacts.where('kind').equals('log').reverse().sortBy('addedAt'),
      db.incidents.toArray(),
      db.cases.toArray(),
      db.meta.toArray(),
    ])
    const ids = [...new Set(detections.flatMap((d) => d.eventIds))]
    const events = await db.events.bulkGet(ids)
    return { eventCount, detections, imports, incidents, cases, meta, events: events.filter((e): e is NormalizedEvent => !!e) }
  })
  return useMemo(() => {
    const incidents = [...(data?.incidents ?? [])].sort((a, b) => b.score - a.score || a.firstSeen - b.firstSeen)
    const incidentOf = new Map<string, Incident>()
    for (const inc of incidents) for (const id of inc.detectionIds) incidentOf.set(id, inc)
    const cases = data?.cases ?? []
    const meta = data?.meta ?? []
    return {
      loaded: data !== undefined,
      eventCount: data?.eventCount ?? 0,
      detections: data?.detections ?? [],
      detectionsById: new Map((data?.detections ?? []).map((d) => [d.id, d])),
      eventsById: new Map((data?.events ?? []).map((e) => [e.id, e])),
      imports: data?.imports ?? [],
      incidents,
      incidentOf,
      cases,
      caseById: new Map(cases.map((c) => [c.id, c])),
      stats: (meta.find((m) => m.key === 'stats')?.value as EventStats | undefined) ?? null,
      check: (meta.find((m) => m.key === 'check')?.value as ScenarioCheck | undefined) ?? null,
      engine: (meta.find((m) => m.key === 'engine')?.value as string | undefined) ?? null,
    }
  }, [data])
}

/** Cases in working order: unresolved first, then highest incident score. */
export function orderedCases(data: Investigation): { c: Case; incident: Incident | undefined }[] {
  return data.cases
    .map((c) => ({ c, incident: data.incidents.find((i) => i.caseId === c.id) }))
    .sort((a, b) => Number(a.c.status === 'Resolved') - Number(b.c.status === 'Resolved') || (b.incident?.score ?? 0) - (a.incident?.score ?? 0))
}
