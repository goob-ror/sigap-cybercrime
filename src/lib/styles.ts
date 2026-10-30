import type { CaseStatus, Level } from '@/core/model'

export { CASE_STATUS_LABEL, KIND_LABEL, LEVEL_LABEL, LEVEL_RANK } from '@/core/labels'

export const levelStyle: Record<Level, string> = {
  critical: 'text-[#FCA5A5] bg-[#EF4444]/10 border-[#EF4444]/25',
  high: 'text-[#FBBF24] bg-[#F59E0B]/10 border-[#F59E0B]/25',
  medium: 'text-[#7DD3FC] bg-[#38BDF8]/10 border-[#38BDF8]/25',
  low: 'text-[#86EFAC] bg-[#22C55E]/10 border-[#22C55E]/25',
  informational: 'text-[#AEB6C1] bg-[#272E3A]/40 border-[#374151]',
}

/** Solid colour per level, for chart marks and graph edges. */
export const LEVEL_COLOR: Record<Level, string> = {
  critical: '#EF4444', high: '#F59E0B', medium: '#38BDF8', low: '#22C55E', informational: '#64748B',
}

export const caseStatusStyle: Record<CaseStatus, string> = {
  Open: 'border-[#EF4444]/25 bg-[#EF4444]/10 text-[#FCA5A5]',
  Investigating: 'border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]',
  Resolved: 'border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]',
}
