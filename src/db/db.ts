import { Dexie, type EntityTable } from 'dexie'
import type { Artifact, Case, CustodyEntry, Detection, Incident, NormalizedEvent } from '@/core/model'

/** Local IndexedDB store. Everything stays in the operator's browser; nothing is sent anywhere. */
export class SigapDb extends Dexie {
  events!: EntityTable<NormalizedEvent, 'id'>
  detections!: EntityTable<Detection, 'id'>
  incidents!: EntityTable<Incident, 'id'>
  cases!: EntityTable<Case, 'id'>
  artifacts!: EntityTable<Artifact, 'id'>
  custody!: EntityTable<CustodyEntry, 'seq'>

  constructor() {
    super('sigap')
    // Only indexed fields are listed; other fields are stored as-is.
    this.version(1).stores({
      events: 'id, ts, importId, dataset, sourceKind, host, user, srcIp, dstIp',
      detections: 'id, ts, ruleId, level, *eventIds',
      incidents: 'id, caseId, score, firstSeen',
      cases: 'id, status, updatedAt',
      artifacts: 'id, caseId, sha256, kind, addedAt',
      custody: 'seq, artifactId, ts',
    })
  }
}

export const db = new SigapDb()
