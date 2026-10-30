import { CircleCheck, Link2, X } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Label } from '@/components/ui/Label'
import type { Detection, Incident, NormalizedEvent } from '@/core/model'
import { scorePercent } from '@/core/report/narrative'
import { TECHNIQUES } from '@/data/attack'
import { RULES } from '@/data/rules/catalog'
import { fmtTime } from '@/lib/format'
import { LEVEL_LABEL, levelStyle } from '@/lib/styles'

type Props = {
  detection: Detection
  event: NormalizedEvent | undefined
  incident: Incident | undefined
  /** Nearest other detections of the same incident. */
  related: Detection[]
  close: () => void
  openDetail: () => void
  openCase: (caseId: string) => void
  select: (id: string) => void
}

export function EvidencePanel({ detection, event, incident, related, close, openDetail, openCase, select }: Props) {
  const rule = RULES.get(detection.ruleId)
  const technique = detection.attack[0]
  return <aside className="rounded-xl border border-[#272E3A] bg-[#131720] xl:sticky xl:top-20 xl:h-[calc(100vh-104px)] xl:overflow-y-auto">
    <div className="sticky top-0 flex items-start justify-between border-b border-[#272E3A] bg-[#131720] p-4"><div><div className="mb-2 flex items-center gap-2"><Badge className={levelStyle[detection.level]}>{LEVEL_LABEL[detection.level]}</Badge><span className="font-mono text-[10px] text-[#7E8998]">{fmtTime(detection.ts)} WIB</span></div><h2 className="text-sm font-semibold">{detection.title}</h2></div><button onClick={close} aria-label="Tutup panel" className="text-[#657080] hover:text-white"><X size={17} /></button></div>
    <div className="space-y-5 p-4">
      <div><Label>Event</Label><p className="break-words text-sm leading-5">{event?.message ?? '—'}</p></div>
      <div className="grid grid-cols-2 gap-2">{[['Pengguna', event?.user], ['Host', event?.host], ['IP sumber', event?.srcIp], ['ATT&CK', technique ? `${technique}${TECHNIQUES.get(technique) ? ` · ${TECHNIQUES.get(technique)!.name}` : ''}` : undefined]].map(([a, b]) => <div key={a} className="min-w-0 rounded-lg border border-[#272E3A] bg-[#0D1016] p-2.5"><div className="text-[9px] uppercase tracking-wider text-[#657080]">{a}</div><div title={b} className="mt-1 truncate font-mono text-[11px]">{b || '—'}</div></div>)}</div>
      <div><Label>Mengapa ditandai?</Label><div className="rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3"><div className="mb-1 text-[10px] font-semibold text-[#FBBF24]">{rule?.kind === 'native' ? 'ATURAN AGREGASI' : 'ATURAN SIGMA'} · {detection.ruleId}</div><p className="text-xs leading-5 text-[#CBD1D8]">{rule?.description}</p></div></div>
      <div><Label>Bukti yang memenuhi aturan</Label><div className="space-y-2">{Object.entries(detection.matched).map(([field, value], i) => <div key={field} className="flex gap-2 text-xs leading-5 text-[#AEB6C1]"><CircleCheck size={14} className="mt-0.5 shrink-0 text-[#22C55E]" /><span className="min-w-0 break-words"><b className="mr-1 font-mono text-[10px] text-[#657080]">B{i + 1}</b><span className="font-mono text-[#7DD3FC]">{field}</span> = {value}</span></div>)}</div></div>
      {rule?.falsepositives.length ? <div><Label>Kemungkinan positif palsu</Label><ul className="list-disc space-y-1 pl-4 text-xs leading-5 text-[#8D97A6]">{rule.falsepositives.map((f) => <li key={f}>{f}</li>)}</ul></div> : null}
       {incident && incident.detectionIds.length > 1 && incident.caseId && <div><Label>Insiden</Label><button onClick={() => openCase(incident.caseId!)} className="w-full rounded-lg border border-[#38BDF8]/25 bg-[#38BDF8]/5 p-3 text-left hover:border-[#38BDF8]/50"><div className="flex items-center justify-between font-mono text-[11px]"><span className="text-[#7DD3FC]">{incident.caseId}</span><span>{scorePercent(incident.score)}%</span></div><div className="mt-1 text-xs">{incident.title}</div><div className="mt-1 text-[10px] text-[#7E8998]">{incident.detectionIds.length} temuan terkorelasi</div></button></div>}
      <div><Label>Temuan terdekat di insiden ini</Label>{related.length ? <div className="flex flex-col gap-1.5">{related.map((d) => <button key={d.id} onClick={() => select(d.id)} className="flex items-center gap-2 rounded-md border border-[#272E3A] bg-[#191F2A] px-2 py-1.5 text-left text-[11px] text-[#CBD1D8] hover:border-[#38BDF8]/50"><Link2 size={11} className="shrink-0 text-[#7DD3FC]" /><span className="font-mono text-[10px] text-[#7E8998]">{fmtTime(d.ts, false)}</span><span className="truncate">{d.title}</span></button>)}</div> : <p className="text-xs text-[#657080]">Temuan ini berdiri sendiri: tidak ada temuan lain dengan aset, akun, IP, atau domain yang sama dalam 24 jam.</p>}</div>
      <button onClick={openDetail} className="w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]">Buka analisis lengkap</button>
    </div>
  </aside>
}
