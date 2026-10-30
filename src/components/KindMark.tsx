import { Cpu, Monitor, Router, Smartphone } from 'lucide-react'
import type { SourceKind } from '@/core/model'

const ICONS = { endpoint: Monitor, network: Router, ot: Cpu, mobile: Smartphone } as const

/** Icon for where an event came from. OT gets the amber treatment used across the app. */
export function KindMark({ kind, size = 13 }: { kind: SourceKind; size?: number }) {
  const Icon = ICONS[kind]
  return <span title={kind.toUpperCase()} className={`grid size-7 shrink-0 place-items-center rounded-md border ${kind === 'ot' ? 'border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FBBF24]' : 'border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]'}`}><Icon size={size} /></span>
}
