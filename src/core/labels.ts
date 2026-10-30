import type { CaseStatus, Level, SourceKind } from '@/core/model'

// Bahasa Indonesia labels shared by the engine (incident titles, score terms) and the UI.

export const LEVEL_LABEL: Record<Level, string> = {
  critical: 'Kritis', high: 'Tinggi', medium: 'Sedang', low: 'Rendah', informational: 'Info',
}

/** Highest first, for sorting. */
export const LEVEL_RANK: Record<Level, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 }

export const KIND_LABEL: Record<SourceKind, string> = {
  endpoint: 'Endpoint', network: 'Jaringan', ot: 'OT', mobile: 'Seluler',
}

export const CASE_STATUS_LABEL: Record<CaseStatus, string> = {
  Open: 'Terbuka', Investigating: 'Investigasi', Resolved: 'Selesai',
}
