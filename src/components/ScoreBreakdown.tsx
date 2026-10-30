import { useState } from 'react'
import { Badge } from '@/components/ui/Badge'
import type { Incident } from '@/core/model'
import { scorePercent } from '@/core/report/narrative'
import { LEVEL_LABEL, levelStyle } from '@/lib/styles'

const decimal = (n: number, digits = 2) => n.toFixed(digits).replace('.', ',')

/** The incident score with every term that produced it: "Mengapa skor ini?". */
export function ScoreBreakdown({ incident, limit = 6 }: { incident: Incident; limit?: number }) {
  const [all, setAll] = useState(false)
  const terms = all ? incident.scoreBreakdown : incident.scoreBreakdown.slice(0, limit)
  const doubt = 1 - incident.score
  const pct = scorePercent(incident.score)
  return <div>
    <div className="flex items-end gap-3"><div className="font-mono text-3xl font-semibold">{pct}%</div><div className="pb-1 text-[11px] text-[#7E8998]">keyakinan bahwa ini insiden nyata</div></div>
    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[#0D1016]"><div className="h-full rounded-full bg-gradient-to-r from-[#F59E0B] to-[#EF4444]" style={{ width: `${pct}%` }} /></div>
    <p className="mt-3 text-[11px] leading-5 text-[#8D97A6]">Skor = 1 − Π(1 − bobot). Setiap unsur bukti mengurangi sisa keraguan; satu aturan dihitung sekali walau terpicu berulang. Bobot: Kritis 0,60 · Tinggi 0,40 · Sedang 0,20 · Rendah 0,10.</p>
    <ol className="mt-3 space-y-1.5">{terms.map((t, i) => <li key={i} className="flex items-center gap-2 text-xs"><span className="w-9 shrink-0 font-mono text-[#7DD3FC]">{decimal(t.weight)}</span><span className="min-w-0 flex-1 truncate text-[#C3CAD3]" title={t.label}>{t.label}{t.count && t.count > 1 ? <span className="text-[#657080]"> ×{t.count}</span> : null}</span>{t.level ? <Badge className={levelStyle[t.level]}>{LEVEL_LABEL[t.level]}</Badge> : <Badge className="border-[#A78BFA]/25 bg-[#A78BFA]/10 text-[#C4B5FD]">{t.kind === 'killchain' ? 'POLA' : 'SUMBER'}</Badge>}</li>)}</ol>
    {incident.scoreBreakdown.length > limit && <button onClick={() => setAll((v) => !v)} className="mt-2 text-[11px] text-[#7DD3FC] hover:underline">{all ? 'Ringkas' : `Tampilkan semua ${incident.scoreBreakdown.length} unsur`}</button>}
    <div className="mt-3 rounded-lg bg-[#0D1016] px-3 py-2 font-mono text-[10px] text-[#8D97A6]">Π(1 − bobot) = {doubt < 0.0001 ? '< 0,0001' : decimal(doubt, 4)} → skor {pct}%</div>
  </div>
}
