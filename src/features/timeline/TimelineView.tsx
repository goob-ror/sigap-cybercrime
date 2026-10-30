import { useMemo, useState } from 'react'
import { Filter, Link2, PanelLeftClose, Search, Upload, Zap } from 'lucide-react'
import { KindMark } from '@/components/KindMark'
import { Badge } from '@/components/ui/Badge'
import { Info } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import { Select } from '@/components/ui/Select'
import type { Detection, Level, NormalizedEvent, SourceKind } from '@/core/model'
import { RULES } from '@/data/rules/catalog'
import { EvidencePanel } from '@/features/timeline/EvidencePanel'
import { fmtDate, fmtDuration, fmtNumber, fmtTime } from '@/lib/format'
import { relatedDetections } from '@/lib/related'
import { KIND_LABEL, LEVEL_LABEL, levelStyle } from '@/lib/styles'

type Props = {
  detections: Detection[]
  eventsById: Map<string, NormalizedEvent>
  eventCount: number
  selectedId: string | null
  onSelect: (id: string) => void
  openDetail: (id: string) => void
  openImport: () => void
}

const LEVEL_OPTIONS = ['Semua tingkat', ...(['critical', 'high', 'medium', 'low'] as Level[]).map((l) => LEVEL_LABEL[l])]
const KIND_OPTIONS = ['Semua sumber', ...(['endpoint', 'network', 'ot'] as SourceKind[]).map((k) => KIND_LABEL[k])]

export function TimelineView({ detections, eventsById, eventCount, selectedId, onSelect, openDetail, openImport }: Props) {
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState(LEVEL_OPTIONS[0])
  const [kind, setKind] = useState(KIND_OPTIONS[0])
  const [panel, setPanel] = useState(true)

  const filtered = useMemo(() => detections.filter((d) => {
    const e = eventsById.get(d.eventIds[0])
    const haystack = `${d.title} ${d.ruleId} ${e?.message ?? ''} ${e?.host ?? ''} ${e?.user ?? ''} ${e?.srcIp ?? ''} ${e?.dstIp ?? ''} ${d.attack.join(' ')}`.toLowerCase()
    return haystack.includes(query.toLowerCase()) && (level === LEVEL_OPTIONS[0] || LEVEL_LABEL[d.level] === level) && (kind === KIND_OPTIONS[0] || (e && KIND_LABEL[e.sourceKind] === kind))
  }), [detections, eventsById, query, level, kind])

  const selected = detections.find((d) => d.id === selectedId) ?? filtered[0]
  const related = useMemo(() => new Set(selected ? relatedDetections(selected, detections, eventsById).map((d) => d.id) : []), [selected, detections, eventsById])

  if (detections.length === 0) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]"><Upload size={22} /></div><h1 className="text-lg font-semibold">{eventCount ? 'Tidak ada temuan' : 'Belum ada data'}</h1><p className="mt-2 text-sm text-[#7E8998]">{eventCount ? `${fmtNumber(eventCount)} event diperiksa dan tidak ada yang memicu aturan deteksi.` : 'Impor log satuan atau muat skenario contoh untuk mulai menganalisis.'}</p><button onClick={openImport} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Impor Data</button></div></div>
  }

  const critical = detections.filter((d) => d.level === 'critical' || d.level === 'high').length
  const span = detections.at(-1)!.ts - detections[0].ts
  const rulesFired = new Set(detections.map((d) => d.ruleId)).size

  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Investigasi / Kronologi" title="Timeline Temuan" text="Event yang memicu aturan deteksi, diurutkan menurut waktu. Pilih temuan untuk melihat bukti dan alasan penandaannya." /><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]"><Zap size={11} className="mr-1" />{rulesFired} ATURAN TERPICU</Badge></div>
    <div className="mb-5 grid grid-cols-2 gap-3 xl:grid-cols-4">
      {[['Event diperiksa', fmtNumber(eventCount), 'dari semua berkas impor', 'bg-[#38BDF8]'], ['Temuan', fmtNumber(detections.length), `${fmtNumber(filtered.length)} sesuai filter`, 'bg-[#38BDF8]'], ['Kritis & tinggi', fmtNumber(critical), 'Prioritaskan ini', 'bg-[#EF4444]'], ['Rentang temuan', fmtDuration(span), `${fmtTime(detections[0].ts, false)} — ${fmtTime(detections.at(-1)!.ts, false)} WIB`, 'bg-[#22C55E]']].map(([a, b, c, dot]) => <div key={a} className="rounded-xl border border-[#272E3A] bg-[#131720] p-4"><div className="flex items-center justify-between text-xs text-[#7E8998]">{a}<span className={`size-2 rounded-full ${dot}`} /></div><div className="mt-2 font-mono text-xl font-semibold">{b}</div><div className="mt-1 text-[11px] text-[#657080]">{c}</div></div>)}
    </div>
    <div className="mb-3 flex flex-col gap-2 rounded-xl border border-[#272E3A] bg-[#131720] p-3 md:flex-row">
      <div className="relative min-w-0 flex-1"><Search size={15} className="absolute left-3 top-2.5 text-[#687384]" /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Cari temuan, host, pengguna, IP, teknik…" className="h-9 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] pl-9 pr-3 text-xs outline-none placeholder:text-[#56606E] focus:border-[#38BDF8]/60" /></div>
      <Select value={level} setValue={setLevel} options={LEVEL_OPTIONS} />
      <Select value={kind} setValue={setKind} options={KIND_OPTIONS} />
      <button onClick={() => { setQuery(''); setLevel(LEVEL_OPTIONS[0]); setKind(KIND_OPTIONS[0]) }} className="flex h-9 items-center justify-center gap-2 rounded-lg border border-[#272E3A] px-3 text-xs text-[#9BA5B4] hover:text-white"><Filter size={14} />Reset</button>
    </div>
    <div className={`grid gap-4 ${panel ? 'xl:grid-cols-[minmax(0,1fr)_380px]' : ''}`}>
      <section className="overflow-hidden rounded-xl border border-[#272E3A] bg-[#0D1016]">
        <div className="hidden grid-cols-[112px_40px_minmax(260px,1fr)_140px_100px] gap-3 border-b border-[#272E3A] px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-[#657080] md:grid"><span>Waktu (WIB)</span><span></span><span>Temuan</span><span>Entitas</span><span>Tingkat</span></div>
        {filtered.length === 0 ? <div className="grid min-h-64 place-items-center text-center"><div><Search className="mx-auto mb-3 text-[#536071]" /><div className="text-sm font-medium">Tidak ada temuan yang cocok</div><div className="mt-1 text-xs text-[#687384]">Ubah kata kunci atau filter pencarian.</div></div></div> :
          filtered.map((d) => {
            const e = eventsById.get(d.eventIds[0])
            const isSelected = selected?.id === d.id
            const rule = RULES.get(d.ruleId)
            const evidence = Object.entries(d.matched)[0]
            return <div key={d.id} className={`border-b border-[#1D232D] last:border-0 ${related.has(d.id) ? 'bg-[#38BDF8]/[0.035]' : ''}`}>
              <button onClick={() => { onSelect(d.id); setPanel(true) }} className={`grid w-full grid-cols-[74px_32px_minmax(0,1fr)] gap-3 px-4 py-4 text-left transition hover:bg-[#131720] md:grid-cols-[112px_40px_minmax(260px,1fr)_140px_100px] ${isSelected ? 'bg-[#131720] shadow-[inset_2px_0_0_#38BDF8]' : ''}`}>
                <div><div className="font-mono text-xs text-[#D8DCE2]">{fmtTime(d.ts)}</div><div className="mt-1 text-[10px] text-[#657080]">{fmtDate(d.ts)}</div></div>
                <div>{e && <KindMark kind={e.sourceKind} />}</div>
                <div className="min-w-0"><div className="mb-1 flex items-center gap-2"><span className="truncate text-sm font-medium">{d.title}</span>{e?.sourceKind === 'ot' && <Badge className="border-[#F59E0B]/20 text-[#FBBF24]">OT</Badge>}{related.has(d.id) && <Badge className="border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]"><Link2 size={9} className="mr-1" />TERKAIT</Badge>}{d.eventIds.length > 1 && <Badge className="border-[#374151] text-[#AEB6C1]">{d.eventIds.length} EVENT</Badge>}</div><p className="truncate text-xs text-[#7E8998]">{e?.message}</p><div className="mt-2 flex gap-3 font-mono text-[10px] text-[#667180]"><span>{d.attack.join(' · ') || d.ruleId}</span><span className="hidden sm:inline">{e?.srcIp}</span></div></div>
                <div className="hidden min-w-0 md:block"><div className="truncate font-mono text-[11px]">{e?.host ?? e?.srcIp ?? '—'}</div><div className="mt-1 truncate text-[10px] text-[#7E8998]">{e?.user ?? e?.dstIp ?? ''}</div></div>
                <div className="hidden md:block"><Badge className={levelStyle[d.level]}>{LEVEL_LABEL[d.level]}</Badge></div>
              </button>
              {isSelected && <div className="grid gap-3 border-t border-[#272E3A]/70 bg-[#0B0E13] px-4 py-3 md:ml-[152px] md:grid-cols-3"><Info title="Aturan terpicu" text={rule?.id ?? d.ruleId} /><Info title="Bukti utama" text={evidence ? `${evidence[0]}: ${evidence[1]}` : '—'} /><div><Label>Korelasi sementara</Label><div className="text-xs text-[#B4BCC7]">{related.size} temuan terkait (host/pengguna/IP sama, ±60 menit)</div></div></div>}
            </div>
          })}
      </section>
      {panel && selected && <EvidencePanel detection={selected} event={eventsById.get(selected.eventIds[0])} related={detections.filter((d) => related.has(d.id))} close={() => setPanel(false)} openDetail={() => openDetail(selected.id)} select={onSelect} />}
      {!panel && <button onClick={() => setPanel(true)} className="fixed bottom-5 right-5 flex items-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-semibold text-[#071018]"><PanelLeftClose size={15} />Buka detail</button>}
    </div>
  </div>
}
