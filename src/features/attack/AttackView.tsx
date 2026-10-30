import { Link2 } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { PageTitle } from '@/components/ui/PageTitle'
import type { Detection } from '@/core/model'
import { TACTIC_ORDER, TECHNIQUES } from '@/data/attack'
import { fmtTime } from '@/lib/format'
import { LEVEL_RANK } from '@/lib/styles'

export function AttackView({ detections, select }: { detections: Detection[]; select: (id: string) => void }) {
  const byTechnique = new Map<string, Detection[]>()
  for (const d of detections) for (const id of d.attack) {
    if (!byTechnique.has(id)) byTechnique.set(id, [])
    byTechnique.get(id)!.push(d)
  }
  const rank = (id: string) => {
    const i = TACTIC_ORDER.indexOf(TECHNIQUES.get(id)?.tactic ?? '')
    return i === -1 ? TACTIC_ORDER.length : i
  }
  const techniques = [...byTechnique.keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))

  return <div className="mx-auto max-w-6xl">
    <div className="mb-6"><PageTitle eyebrow="Pemetaan Pengetahuan" title="MITRE ATT&CK & ATT&CK for ICS" text="Teknik yang muncul pada temuan, diurutkan menurut tahap serangan. Pilih kartu untuk membuka temuan paling berat." /></div>
    {techniques.length === 0 ? <p className="rounded-xl border border-[#272E3A] bg-[#131720] p-8 text-center text-sm text-[#657080]">Belum ada temuan yang dipetakan.</p> :
      <div className="grid gap-4 md:grid-cols-2">{techniques.map((id) => {
        const t = TECHNIQUES.get(id)
        const list = byTechnique.get(id)!
        const top = [...list].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts)[0]
        const ics = t?.domain === 'ics'
        return <button key={id} onClick={() => select(top.id)} className="rounded-xl border border-[#272E3A] bg-[#131720] p-4 text-left hover:border-[#38BDF8]/40">
          <div className="flex items-center justify-between"><Badge className={ics ? 'border-[#F59E0B]/25 text-[#FBBF24]' : 'border-[#38BDF8]/25 text-[#7DD3FC]'}>{ics ? 'ATT&CK FOR ICS' : 'ENTERPRISE ATT&CK'} · {t?.tactic ?? '—'}</Badge><span className="font-mono text-xs text-[#7DD3FC]">{id}</span></div>
          <h2 className="mt-3 text-sm font-semibold">{t?.name ?? id}</h2>
          <p className="mt-2 text-xs leading-5 text-[#8D97A6]">{[...new Set(list.map((d) => d.title))].slice(0, 3).join(' · ')}</p>
          <div className="mt-3 flex items-center gap-2 border-t border-[#272E3A] pt-3 text-[10px] text-[#657080]"><Link2 size={11} />{list.length} temuan · pertama {fmtTime(list[0].ts, false)} WIB</div>
        </button>
      })}</div>}
    <p className="mt-6 text-[10px] text-[#596474]">MITRE ATT&CK® adalah merek dagang terdaftar milik The MITRE Corporation.</p>
  </div>
}
