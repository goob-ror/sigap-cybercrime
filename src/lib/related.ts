import type { Detection, NormalizedEvent } from '@/core/model'

function entityKeys(event: NormalizedEvent | undefined): string[] {
  if (!event) return []
  return [event.host && `host:${event.host}`, event.user && `user:${event.user}`, event.srcIp && `ip:${event.srcIp}`, event.dstIp && `ip:${event.dstIp}`].filter((k): k is string => !!k)
}

/**
 * Detections that share a host, user or IP with `det` within ±60 minutes, nearest first.
 * A simple stand-in until the correlation engine (Phase 2) groups detections into incidents.
 */
export function relatedDetections(det: Detection, all: readonly Detection[], eventsById: Map<string, NormalizedEvent>, windowMs = 60 * 60_000, limit = 8): Detection[] {
  const keys = new Set(entityKeys(eventsById.get(det.eventIds[0])))
  if (!keys.size) return []
  return all
    .filter((d) => d.id !== det.id && Math.abs(d.ts - det.ts) <= windowMs && entityKeys(eventsById.get(d.eventIds[0])).some((k) => keys.has(k)))
    .sort((a, b) => Math.abs(a.ts - det.ts) - Math.abs(b.ts - det.ts))
    .slice(0, limit)
}
