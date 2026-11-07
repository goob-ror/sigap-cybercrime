import { Dexie, type EntityTable } from 'dexie'
import type { Coverage } from '@/core/coverage'
import type { DrillResult } from '@/core/drill'
import type { IndicatorList } from '@/core/indicators'
import type { Artifact, Case, CustodyEntry, Detection, Incident, NormalizedEvent, UnitProfile } from '@/core/model'
import type { OtAnalysis } from '@/core/ot/analysis'
import type { EventStats } from '@/core/stats'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import type { ScenarioCheck } from '@/workers/protocol'

/** Derived values the worker computes after each import. */
export type MetaRow = { key: 'stats'; value: EventStats } | { key: 'check'; value: ScenarioCheck } | { key: 'engine'; value: string } | { key: 'coverage'; value: Coverage } | { key: 'ot'; value: OtAnalysis }

/** Original bytes of an imported log file, kept so the evidence package can bundle it and the
 *  engine can re-parse it when the parser changes. Keyed by `importId`. */
export type BlobRow = { id: string; name: string; bytes: Uint8Array; tzOffset?: string }

/** This browser's configuration. Kept apart from `meta` because it must survive re-analysis and "Hapus data lokal". */
export type SettingRow =
  | { key: 'profile'; value: UnitProfile }
  | { key: 'operator'; value: string }
  /** Zone last chosen for logs whose timestamps carry none. */
  | { key: 'importTz'; value: string }
  /** Signs evidence packages. The private half cannot be read back out of the browser. */
  | { key: 'signingKey'; value: CryptoKeyPair }
  /** Whether the operator has allowed online features. Off until they say otherwise. */
  | { key: 'onlineConsent'; value: boolean }
  /** Past drills, newest first, so readiness can be seen over time. */
  | { key: 'drillResults'; value: DrillResult[] }

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
  settings!: EntityTable<SettingRow, 'key'>
  indicatorLists!: EntityTable<IndicatorList, 'id'>

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
    this.version(4).stores({ settings: 'key' })
    this.version(5).stores({ indicatorLists: 'id' })
  }
}

export const db = new SigapDb()

/** The profile detection runs with: the one saved in this browser, else the fictional demo unit. */
export async function activeProfile(): Promise<UnitProfile> {
  const row = await db.settings.get('profile')
  return row?.key === 'profile' ? row.value : DEFAULT_UNIT_PROFILE
}
