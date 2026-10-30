import type { Detection, Incident } from '@/core/model'

/** Other detections of the same incident, nearest in time first. */
export function incidentNeighbors(det: Detection, incident: Incident | undefined, byId: Map<string, Detection>, limit = 8): Detection[] {
  if (!incident) return []
  return incident.detectionIds
    .filter((id) => id !== det.id)
    .map((id) => byId.get(id))
    .filter((d): d is Detection => !!d)
    .sort((a, b) => Math.abs(a.ts - det.ts) - Math.abs(b.ts - det.ts))
    .slice(0, limit)
}
