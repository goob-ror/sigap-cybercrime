import type { IngestError, LogFormat } from '@/core/ingest'

export type IngestRequest = { type: 'import'; files: File[]; actor: string } | { type: 'scenario'; actor: string } | { type: 'clear' }

export type ImportSummary = {
  files: { name: string; format: string; events: number; errors: number }[]
  /** Events added by this request. */
  events: number
  totalEvents: number
  detections: number
  rules: number
}

export type IngestResponse =
  | { type: 'progress'; message: string; done: number; total: number }
  | { type: 'done'; summary: ImportSummary }
  | { type: 'error'; message: string }

/** Stored in `Artifact.analysis` for imported log files. */
export type LogAnalysis = { format: LogFormat; formatLabel: string; eventCount: number; errorCount: number; errors: IngestError[] }
