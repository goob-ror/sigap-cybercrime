import { type Severity } from '@/data/demoCase'
import type { Level, SourceKind } from '@/core/model'

export const severityStyle: Record<Severity, string> = {
  Kritis: 'text-[#FCA5A5] bg-[#EF4444]/10 border-[#EF4444]/25',
  Tinggi: 'text-[#FBBF24] bg-[#F59E0B]/10 border-[#F59E0B]/25',
  Sedang: 'text-[#7DD3FC] bg-[#38BDF8]/10 border-[#38BDF8]/25',
  Rendah: 'text-[#86EFAC] bg-[#22C55E]/10 border-[#22C55E]/25',
}

export const LEVEL_LABEL: Record<Level, string> = {
  critical: 'Kritis', high: 'Tinggi', medium: 'Sedang', low: 'Rendah', informational: 'Info',
}

export const levelStyle: Record<Level, string> = {
  critical: severityStyle.Kritis,
  high: severityStyle.Tinggi,
  medium: severityStyle.Sedang,
  low: severityStyle.Rendah,
  informational: 'text-[#AEB6C1] bg-[#272E3A]/40 border-[#374151]',
}

/** Highest first, for sorting. */
export const LEVEL_RANK: Record<Level, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 }

export const KIND_LABEL: Record<SourceKind, string> = {
  endpoint: 'Endpoint', network: 'Jaringan', ot: 'OT', mobile: 'Seluler',
}
