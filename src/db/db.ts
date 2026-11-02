import { Dexie, type EntityTable } from 'dexie'
import type { Artifact, Case, CustodyEntry, Detection, Incident, NormalizedEvent } from '@/core/model'
import type { EventStats } from '@/core/stats'
import type { ScenarioCheck } from '@/workers/protocol'

/** Derived values the worker computes after each import. */
export type MetaRow = { key: 'stats'; value: EventStats } | { key: 'check'; value: ScenarioCheck } | { key: 'engine'; value: string }

/** Original bytes of an imported log file, kept so the evidence package can bundle it and the
 *  engine can re-parse it when the parser changes. Keyed by `importId`. */
export type BlobRow = { id: string; name: string; bytes: Uint8Array }

/** Local IndexedDB store. Everything stays in the operator's browser; nothing is sent anywhere. */
export class SigapDb extends Dexie {
  events!: EntityTable<NormalizedEvent, 'id'>
  detections!: EntityTable<Detection, 'id'>
  incidents!: EntityTable<Incident, 'id'>
  cases!: EntityTable<Case, 'id'>
  artifacts!: EntityTable<Artifact, 'id'>
  custody!: EntityTable<CustodyEntry, 'seq'>
  meta!: EntityTable<MetaRow, 'key'>
  blobs!: EntityTable<BlobRow, 'id'>

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
    this.version(2).stores({ meta: 'key' })
    this.version(3).stores({ blobs: 'id' })
  }
}

export const db = new SigapDb()
