import type { Dispatch, SetStateAction } from 'react'
import { CheckSquare, ChevronRight, CircleCheck, ExternalLink, FileSearch, Link2, Network, ShieldAlert, TriangleAlert } from 'lucide-react'
import { KindMark } from '@/components/KindMark'
import { Badge } from '@/components/ui/Badge'
import { Card, Info } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import type { Detection, NormalizedEvent } from '@/core/model'
import { TECHNIQUES } from '@/data/attack'
import { RULES } from '@/data/rules/catalog'
import { fmtDateTime, fmtTime } from '@/lib/format'
import { relatedDetections } from '@/lib/related'
import { LEVEL_LABEL, levelStyle } from '@/lib/styles'

type Props = {
  detection: Detection | undefined
  detections: Detection[]
  eventsById: Map<string, NormalizedEvent>
  followup: string
  changeStatus: (id: string, status: string) => void
  select: (id: string) => void
  checks: Record<string, boolean>
  setChecks: Dispatch<SetStateAction<Record<string, boolean>>>
  openLogs: (eventId: string) => void
  openTimeline: () => void
}

export function DetailView({ detection, detections, eventsById, followup, changeStatus, select, checks, setChecks, openLogs, openTimeline }: Props) {
  if (!detection) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><FileSearch className="mx-auto mb-3 text-[#536071]" /><h1 className="text-lg font-semibold">Belum ada temuan dipilih</h1><p className="mt-2 text-sm text-[#7E8998]">Pilih temuan dari Timeline untuk melihat analisis lengkapnya.</p><button onClick={openTimeline} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Timeline</button></div></div>
  }
  const rule = RULES.get(detection.ruleId)
  const event = eventsById.get(detection.eventIds[0])
  const related = relatedDetections(detection, detections, eventsById)
  const steps = rule?.respons ?? []

  return <div className="mx-auto max-w-6xl">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow={`Temuan / ${detection.ruleId}`} title={detection.title} text={event?.message ?? ''} /><div className="flex flex-wrap gap-2"><Badge className={levelStyle[detection.level]}>{LEVEL_LABEL[detection.level].toUpperCase()}</Badge><Badge className="border-[#38BDF8]/25 bg-[#38BDF8]/10 text-[#7DD3FC]">{followup.toUpperCase()}</Badge></div></div>
    <div className="grid gap-4 lg:grid-cols-[1.4fr_.8fr]">
      <div className="space-y-4">
        <Card title="Mengapa Ditandai?" icon={<ShieldAlert size={16} className="text-[#F59E0B]" />}>
          <Info title={rule?.kind === 'native' ? 'Aturan agregasi SIGAP' : 'Aturan Sigma'} text={rule?.description ?? ''} />
          <div className="mt-4"><Label>Bukti yang memenuhi aturan</Label><div className="space-y-2">{Object.entries(detection.matched).map(([field, value], i) => <div key={field} className="flex items-start gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-xs"><span className="font-mono text-[#38BDF8]">B{i + 1}</span><span className="min-w-0 flex-1 break-words text-[#C3CAD3]"><span className="font-mono text-[#7DD3FC]">{field}</span> = {value}</span><CircleCheck size={15} className="shrink-0 text-[#22C55E]" /></div>)}</div></div>
          {rule?.falsepositives.length ? <div className="mt-4 rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3"><div className="mb-1 text-[10px] font-semibold text-[#FBBF24]">PERLU DIVERIFIKASI — KEMUNGKINAN POSITIF PALSU</div><ul className="list-disc pl-4 text-xs leading-5 text-[#AEB6C1]">{rule.falsepositives.map((f) => <li key={f}>{f}</li>)}</ul></div> : null}
        </Card>
        <Card title="Langkah Respons Awal" icon={<CircleCheck size={16} className="text-[#22C55E]" />}>
          <div className="mb-3 flex gap-2 rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3 text-[11px] leading-5 text-[#D4A64B]"><TriangleAlert size={15} className="mt-0.5 shrink-0" />Tindakan pada sistem operasional wajib diverifikasi, mendapat otorisasi komandan, dan dicatat.</div>
          {steps.length === 0 ? <p className="text-xs text-[#657080]">Aturan ini belum memiliki langkah respons.</p> :
            <div className="space-y-2">{steps.map((step, i) => { const key = `${detection.id}#${i}`; return <div key={key} className="flex items-start gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><button title="Tandai selesai" onClick={() => setChecks((v) => ({ ...v, [key]: !v[key] }))} className={`mt-0.5 ${checks[key] ? 'text-[#22C55E]' : 'text-[#56606E]'}`}><CheckSquare size={17} /></button><span className={`flex-1 text-sm leading-5 ${checks[key] ? 'text-[#7E8998] line-through' : ''}`}>{step}</span></div> })}</div>}
          <div className="mt-4 flex items-center justify-between border-t border-[#272E3A] pt-3 text-xs"><span className="text-[#8D97A6]">Status tindak lanjut temuan</span><select value={followup} onChange={(x) => changeStatus(detection.id, x.target.value)} className="rounded-md border border-[#272E3A] bg-[#191F2A] px-2 py-1 text-[11px]"><option>Baru</option><option>Berjalan</option><option>Selesai</option></select></div>
        </Card>
        {event && <Card title="Data Asli Event" icon={<FileSearch size={16} className="text-[#38BDF8]" />}><pre className="max-h-80 overflow-auto rounded-lg bg-[#0D1016] p-3 font-mono text-[11px] leading-5 text-[#AEB6C1]">{JSON.stringify(event.fields, null, 2)}</pre></Card>}
      </div>
      <div className="space-y-4">
        <Card title="Entitas & Teknik" icon={<Network size={16} className="text-[#38BDF8]" />}>
          <div className="space-y-2">{[['Waktu', fmtDateTime(detection.ts)], ['Sumber log', event?.dataset], ['Host', event?.host], ['Pengguna', event?.user], ['IP sumber', event?.srcIp], ['IP tujuan', event?.dstIp && `${event.dstIp}${event.dstPort ? `:${event.dstPort}` : ''}`], ['Domain', event?.domain], ['Event terlibat', String(detection.eventIds.length)]].filter(([, b]) => b).map(([a, b]) => <div key={a} className="flex items-center justify-between gap-3 border-b border-[#272E3A] py-2 text-xs last:border-0"><span className="text-[#707B8A]">{a}</span><span className="truncate font-mono text-[#D1D6DD]" title={b}>{b}</span></div>)}</div>
          <div className="mt-3"><Label>MITRE ATT&CK</Label><div className="space-y-1.5">{detection.attack.map((id) => { const t = TECHNIQUES.get(id); return <div key={id} className="rounded-lg border border-[#272E3A] bg-[#0D1016] px-3 py-2 text-xs"><span className="font-mono text-[#7DD3FC]">{id}</span> <span className="text-[#C3CAD3]">{t?.name ?? ''}</span>{t && <div className="mt-0.5 text-[10px] text-[#657080]">{t.domain === 'ics' ? 'ICS · ' : ''}{t.tactic}</div>}</div> })}</div></div>
        </Card>
        <button onClick={() => openLogs(detection.eventIds[0])} className="flex w-full items-center justify-center gap-2 rounded-xl border border-[#38BDF8]/30 bg-[#38BDF8]/10 py-3 text-xs font-semibold text-[#7DD3FC] transition hover:bg-[#38BDF8]/15"><ExternalLink size={14} />Buka di Log Explorer</button>
        <Card title="Temuan Terkait" icon={<Link2 size={16} className="text-[#38BDF8]" />}>
          {related.length === 0 ? <p className="text-xs text-[#657080]">Tidak ada temuan lain dengan host, pengguna, atau IP yang sama dalam ±60 menit.</p> :
            <div className="space-y-2">{related.map((d) => { const e = eventsById.get(d.eventIds[0]); return <button onClick={() => select(d.id)} key={d.id} className="flex w-full items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-left hover:border-[#38BDF8]/40">{e && <KindMark kind={e.sourceKind} />}<span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium">{d.title}</span><span className="mt-1 block font-mono text-[10px] text-[#657080]">{fmtTime(d.ts)} · {LEVEL_LABEL[d.level]}</span></span><ChevronRight size={14} className="text-[#657080]" /></button> })}</div>}
        </Card>
      </div>
    </div>
  </div>
}
