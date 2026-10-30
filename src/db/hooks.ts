import { useMemo } from 'react'
import { useLiveQuery } from 'dexie-react-hooks'
import { db } from '@/db/db'
import type { Artifact, Detection, NormalizedEvent } from '@/core/model'

export type Investigation = {
  loaded: boolean
  eventCount: number
  detections: Detection[]
  /** Only the events referenced by detections (the full set can be very large). */
  eventsById: Map<string, NormalizedEvent>
  imports: Artifact[]
}

/** Live view of the local investigation data; re-renders whenever the worker writes. */
export function useInvestigation(): Investigation {
  const data = useLiveQuery(async () => {
    const [eventCount, detections, imports] = await Promise.all([
      db.events.count(),
      db.detections.orderBy('ts').toArray(),
      db.artifacts.where('kind').equals('log').reverse().sortBy('addedAt'),
    ])
    const ids = [...new Set(detections.flatMap((d) => d.eventIds))]
    const events = await db.events.bulkGet(ids)
    return { eventCount, detections, imports, events: events.filter((e): e is NormalizedEvent => !!e) }
  })
  return useMemo(
    () => ({
      loaded: data !== undefined,
      eventCount: data?.eventCount ?? 0,
      detections: data?.detections ?? [],
      eventsById: new Map((data?.events ?? []).map((e) => [e.id, e])),
      imports: data?.imports ?? [],
    }),
    [data],
  )
}
