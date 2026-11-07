import type { CollectionInfo } from '@/core/coverage'
import type { IngestError, LogFormat } from '@/core/ingest'
import type { UnitProfile } from '@/core/model'

/**
 * Bump when rules, parsing or correlation change: stored results from an older engine are then
 * recomputed from the stored events when the app opens.
 */
export const ENGINE_VERSION = '2026.11-fase6-ot'

export type IngestRequest =
  /** `tzOffset`: the zone of timestamps that carry none, e.g. `+09:00`. */
  | { type: 'import'; files: File[]; actor: string; tzOffset?: string }
  | { type: 'scenario'; actor: string }
  | { type: 'reanalyze' }
  | { type: 'clear' }
  /** Saves the unit profile (null returns to the demo unit), then re-analyzes the stored events with it. */
  | { type: 'profile'; profile: UnitProfile | null; actor: string }
  /** The local indicator lists changed: re-analyzes the stored events against them. */
  | { type: 'indicators' }

export type ImportSummary = {
  files: { name: string; format: string; events: number; errors: number }[]
  /** Events added by this request. */
  events: number
  totalEvents: number
  detections: number
  incidents: number
  rules: number
}

export type IngestResponse =
  | { type: 'progress'; message: string; done: number; total: number }
  | { type: 'done'; summary: ImportSummary }
  | { type: 'error'; message: string }

/** Stored in `Artifact.analysis` for imported log files. */
export type LogAnalysis = {
  format: LogFormat
  formatLabel: string
  eventCount: number
  errorCount: number
  errors: IngestError[]
  /** The zone given to timestamps that carried none. */
  assumedOffset?: string
  collection?: CollectionInfo
}

/**
 * How well detection did on the built-in demo scenario, whose attack events are known. Computed
 * whenever the scenario's files are among the imports (loaded from the button or the sample ZIP).
 */
export type ScenarioCheck = {
  files: number
  totalFiles: number
  attackEvents: number
  attackFlagged: number
  benignEvents: number
  benignFlagged: number
}
