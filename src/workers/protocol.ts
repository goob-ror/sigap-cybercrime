import type { IngestError, LogFormat } from '@/core/ingest'

/**
 * Bump when rules, parsing or correlation change: stored results from an older engine are then
 * recomputed from the stored events when the app opens.
 */
export const ENGINE_VERSION = '2026.11-fase2'

export type IngestRequest = { type: 'import'; files: File[]; actor: string } | { type: 'scenario'; actor: string } | { type: 'reanalyze' } | { type: 'clear' }

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
export type LogAnalysis = { format: LogFormat; formatLabel: string; eventCount: number; errorCount: number; errors: IngestError[] }

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
