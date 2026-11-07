import { CircleCheck, CircleDashed, CircleMinus, Eye, TriangleAlert } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import type { Coverage, CoverageSource } from '@/core/coverage'

const ICON = {
  ada: <CircleCheck size={14} className="mt-0.5 shrink-0 text-[#22C55E]" />,
  sebagian: <CircleDashed size={14} className="mt-0.5 shrink-0 text-[#F59E0B]" />,
  'tidak-ada': <CircleMinus size={14} className="mt-0.5 shrink-0 text-[#657080]" />,
} as const

function SourceRow({ source, gap }: { source: CoverageSource; gap: boolean }) {
  return <li className="flex items-start gap-2 text-xs leading-5">{ICON[source.status]}<span className="min-w-0 flex-1"><span className={source.status === 'ada' ? 'text-[#C3CAD3]' : gap ? 'text-[#FCD34D]' : 'text-[#7E8998]'}>{source.label}</span> <span className="font-mono text-[10px] text-[#657080]">{source.rulesWithData}/{source.rules} aturan</span>{gap && <span className="block text-[11px] leading-4 text-[#8D97A6]">{source.fix}</span>}</span></li>
}

/** What the imported logs let the rules see, and how to see more next time. */
export function CoverageCard({ coverage }: { coverage: Coverage }) {
  const gapIds = new Set(coverage.gaps.map((g) => g.id))
  const present = coverage.sources.filter((s) => s.status === 'ada')
  const notImported = coverage.sources.filter((s) => s.status === 'tidak-ada' && !gapIds.has(s.id))
  const pct = coverage.rulesTotal ? (coverage.rulesWithData / coverage.rulesTotal) * 100 : 0
  return <Card title="Cakupan Analisis" icon={<Eye size={16} className={coverage.complete ? 'text-[#22C55E]' : 'text-[#F59E0B]'} />}>
    <div className="flex items-baseline gap-2"><span className="font-mono text-2xl font-semibold">{coverage.rulesWithData}</span><span className="text-xs text-[#8D97A6]">dari {coverage.rulesTotal} aturan memiliki data untuk diperiksa</span></div>
    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[#0D1016]"><div className={`h-full rounded-full ${coverage.complete ? 'bg-[#22C55E]' : 'bg-[#F59E0B]'}`} style={{ width: `${pct}%` }} /></div>
    <p className="mt-2 text-[11px] leading-4 text-[#8D97A6]">Aturan tanpa data tidak dapat menemukan apa pun. Apa yang tidak tercatat di log tidak akan terlihat di SIGAP, seberapa pun seriusnya.</p>
    {coverage.warnings.length > 0 && <ul className="mt-3 space-y-1.5">{coverage.warnings.map((w) => <li key={w} className="flex gap-2 rounded-lg border border-[#F59E0B]/30 bg-[#F59E0B]/10 p-2.5 text-[11px] leading-4 text-[#FCD34D]"><TriangleAlert size={13} className="mt-0.5 shrink-0" />{w}</li>)}</ul>}
    {coverage.gaps.length > 0 && <div className="mt-3"><div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[#FBBF24]">Kurang dari log yang diimpor</div><ul className="space-y-1.5">{coverage.gaps.map((s) => <SourceRow key={s.id} source={s} gap />)}</ul></div>}
    {present.length > 0 && <div className="mt-3"><div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[#657080]">Terbaca</div><ul className="space-y-1">{present.map((s) => <SourceRow key={s.id} source={s} gap={false} />)}</ul></div>}
    {notImported.length > 0 && <div className="mt-3"><div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[#657080]">Belum diimpor</div><ul className="space-y-1">{notImported.map((s) => <SourceRow key={s.id} source={s} gap={false} />)}</ul></div>}
  </Card>
}
