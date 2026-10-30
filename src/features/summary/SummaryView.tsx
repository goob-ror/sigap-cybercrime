import { Activity, ArrowRight, ChevronRight, ClipboardList, Database, GitBranch, ListChecks, Route, ShieldAlert, Upload } from 'lucide-react'
import { KindMark } from '@/components/KindMark'
import { ScoreBreakdown } from '@/components/ScoreBreakdown'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { PageTitle } from '@/components/ui/PageTitle'
import type { Detection, Level, SourceKind } from '@/core/model'
import { affectedAssets, incidentFacts, incidentStory, incidentSummary, priorityActions, scorePercent } from '@/core/report/narrative'
import type { Investigation } from '@/db/hooks'
import { RULES } from '@/data/rules/catalog'
import { fmtDate, fmtNumber, fmtSpan, fmtTime } from '@/lib/format'
import { CASE_STATUS_LABEL, KIND_LABEL, LEVEL_COLOR, LEVEL_LABEL, LEVEL_RANK, caseStatusStyle, levelStyle } from '@/lib/styles'

type Props = {
  data: Investigation
  openImport: () => void
  openCase: (caseId: string) => void
  openGraph: (incidentId: string) => void
  openTimeline: () => void
  openDetail: (detectionId: string) => void
}

const LEVELS: Level[] = ['critical', 'high', 'medium', 'low', 'informational']

export function SummaryView({ data, openImport, openCase, openGraph, openTimeline, openDetail }: Props) {
  const { detections, incidents, stats } = data

  if (!data.eventCount) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]"><Upload size={22} /></div><h1 className="text-lg font-semibold">Belum ada data</h1><p className="mt-2 text-sm text-[#7E8998]">Impor log satuan atau muat skenario contoh. Ringkasan ini lalu disusun otomatis dari data tersebut.</p><button onClick={openImport} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Impor Data</button></div></div>
  }

  const top = incidents[0]
  const topCase = top?.caseId ? data.caseById.get(top.caseId) : undefined
  const steps = top ? incidentStory(top, data.detectionsById, data.eventsById) : []
  const actions = top ? priorityActions(top, data.detectionsById, RULES) : []
  const facts = top ? incidentFacts(top) : undefined
  const urgent = detections.filter((d) => LEVEL_RANK[d.level] >= LEVEL_RANK.high).length
  const affected = new Set(incidents.flatMap((i) => affectedAssets(i).map((e) => e.key)))
  const accounts = new Set(incidents.flatMap((i) => i.entities.filter((e) => e.type === 'user').map((e) => e.key)))
  const datasets = Object.keys(stats?.byDataset ?? {}).length

  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Pusat Investigasi" title="Ringkasan" text="Gambaran insiden yang ditemukan pada log yang diimpor. Semua angka dan kalimat di halaman ini disusun dari data di browser ini." /><Badge className={incidents.length ? 'border-[#EF4444]/25 bg-[#EF4444]/10 text-[#FCA5A5]' : 'border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]'}>{incidents.length} INSIDEN</Badge></div>

    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{([
      ['Event diperiksa', fmtNumber(data.eventCount), `${datasets} jenis log · ${stats?.hosts ?? 0} host`, Database, '#38BDF8'],
      ['Temuan', fmtNumber(detections.length), `${fmtNumber(urgent)} kritis/tinggi · ${new Set(detections.map((d) => d.ruleId)).size} aturan`, ShieldAlert, '#EF4444'],
      ['Insiden terkorelasi', fmtNumber(incidents.length), top ? `skor tertinggi ${scorePercent(top.score)}%` : 'tidak ada', GitBranch, '#F59E0B'],
      ['Aset terdampak', fmtNumber(affected.size), `${accounts.size} akun terlibat`, Route, '#22C55E'],
    ] as const).map(([label, value, sub, Icon, color]) => <div key={label} className="rounded-xl border border-[#272E3A] bg-[#131720] p-4"><div className="flex items-center justify-between text-xs text-[#7E8998]">{label}<span className="grid size-8 place-items-center rounded-lg bg-[#0D1016]" style={{ color }}><Icon size={15} /></span></div><div className="mt-3 font-mono text-2xl font-semibold">{value}</div><div className="mt-1 text-[10px] text-[#657080]">{sub}</div></div>)}</div>

    {!top ? <div className="mt-4 rounded-xl border border-[#22C55E]/25 bg-[#22C55E]/5 p-6"><h2 className="font-semibold">Tidak ada temuan</h2><p className="mt-1 text-sm text-[#8D97A6]">{fmtNumber(data.eventCount)} event diperiksa dengan {RULES.size} aturan dan tidak ada yang terpicu.</p></div> : <>
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[1.35fr_.65fr]">
        <section className="relative overflow-hidden rounded-xl border border-[#EF4444]/25 bg-gradient-to-br from-[#1A1D25] to-[#11151C] p-6">
          <div className="absolute -right-16 -top-20 size-64 rounded-full bg-[#EF4444]/5 blur-3xl" />
          <div className="relative">
            <div className="flex flex-wrap items-center gap-2"><Badge className={levelStyle[top.level]}>{LEVEL_LABEL[top.level].toUpperCase()}</Badge>{topCase && <><span className="font-mono text-[11px] text-[#AEB6C1]">{topCase.id}</span><Badge className={caseStatusStyle[topCase.status]}>{CASE_STATUS_LABEL[topCase.status].toUpperCase()}</Badge></>}<span className="font-mono text-[10px] text-[#657080]">{fmtDate(top.firstSeen)} · {fmtTime(top.firstSeen, false)}–{fmtTime(top.lastSeen, false)} WIB</span></div>
            <h2 className="mt-4 text-xl font-semibold">{top.title}</h2>
            {top.path.length > 1 && <div className="mt-3 flex flex-wrap items-center gap-1.5">{top.path.map((key, i) => { const e = top.entities.find((x) => x.key === key)!; return <span key={key} className="flex items-center gap-1.5">{i > 0 && <ArrowRight size={13} className="text-[#EF4444]" />}<span className={`rounded-md border px-2 py-1 font-mono text-[11px] ${e.type === 'device' ? 'border-[#F59E0B]/40 bg-[#F59E0B]/10 text-[#FBBF24]' : 'border-[#374151] bg-[#0D1016] text-[#D1D6DD]'}`}>{e.value}</span></span> })}</div>}
            <p className="mt-4 max-w-3xl text-sm leading-6 text-[#AEB6C1]">{incidentSummary(top, steps)}</p>
            <div className="mt-4 flex flex-wrap gap-2 text-[10px]">{top.sourceKinds.map((k: SourceKind) => <span key={k} className="flex items-center gap-1.5 rounded-md border border-[#272E3A] bg-[#0D1016] py-1 pl-1 pr-2 text-[#AEB6C1]"><KindMark kind={k} size={11} />{KIND_LABEL[k]}</span>)}<span className="rounded-md border border-[#272E3A] bg-[#0D1016] px-2 py-1.5 text-[#AEB6C1]">{facts!.detections} temuan · {facts!.rules} aturan · {fmtSpan(facts!.span)}</span></div>
            <div className="mt-5 flex flex-wrap gap-2">{topCase && <button onClick={() => openCase(topCase.id)} className="flex items-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2.5 text-xs font-bold text-[#071018]"><ClipboardList size={14} />Tangani kasus {topCase.id}</button>}<button onClick={() => openGraph(top.id)} className="flex items-center gap-2 rounded-lg border border-[#272E3A] bg-[#191F2A] px-4 py-2.5 text-xs font-semibold hover:border-[#38BDF8]/40"><GitBranch size={14} />Lihat graf</button><button onClick={openTimeline} className="flex items-center gap-2 rounded-lg border border-[#272E3A] bg-[#191F2A] px-4 py-2.5 text-xs font-semibold hover:border-[#38BDF8]/40"><Activity size={14} />Timeline</button></div>
          </div>
        </section>
        <Card title="Mengapa skor ini?" icon={<ShieldAlert size={16} className="text-[#F59E0B]" />}><ScoreBreakdown incident={top} limit={5} /></Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[1.35fr_.65fr]">
        <Card title="Apa yang terjadi? — urutan waktu" icon={<Route size={16} className="text-[#38BDF8]" />}>
          <ol className="relative space-y-0">{steps.map((s, i) => <li key={i} className="relative grid grid-cols-[64px_18px_minmax(0,1fr)] gap-3 pb-4 last:pb-0">
            <span className="pt-0.5 text-right font-mono text-[11px] text-[#AEB6C1]">{fmtTime(s.first, false).slice(0, 5)}</span>
            <span className="relative flex justify-center"><span className="z-10 mt-1 size-2.5 rounded-full" style={{ background: LEVEL_COLOR[strongest(s.detections)] }} />{i < steps.length - 1 && <span className="absolute top-3 h-full w-px bg-[#272E3A]" />}</span>
            <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold">{s.label}</span>{s.places.map((p) => <span key={p} className="font-mono text-[10px] text-[#7DD3FC]">{p}</span>)}</div><div className="mt-1 flex flex-col gap-0.5">{s.detections.slice(0, 3).map((d) => <button key={d.id} onClick={() => openDetail(d.id)} className="truncate text-left text-xs text-[#8D97A6] hover:text-white">{d.title}</button>)}{s.detections.length > 3 && <span className="text-[10px] text-[#657080]">+{s.detections.length - 3} temuan lain</span>}</div></div>
          </li>)}</ol>
        </Card>
        <div className="space-y-4">
          <Card title="Langkah prioritas" icon={<ListChecks size={16} className="text-[#22C55E]" />}>
            {actions.length === 0 ? <p className="text-xs text-[#657080]">Tidak ada temuan kritis atau tinggi.</p> : <ol className="space-y-2">{actions.map((a, i) => <li key={a.detectionId} className="flex gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><span className="font-mono text-xs text-[#38BDF8]">{i + 1}</span><div className="min-w-0 flex-1"><div className="text-xs leading-5">{a.text}</div><button onClick={() => openDetail(a.detectionId)} className="mt-1 flex items-center gap-1 text-[10px] text-[#657080] hover:text-[#7DD3FC]"><span className="truncate">dari: {a.ruleTitle}</span><ChevronRight size={11} /></button></div><Badge className={`self-start ${levelStyle[a.level]}`}>{LEVEL_LABEL[a.level]}</Badge></li>)}</ol>}
            <p className="mt-3 text-[10px] leading-4 text-[#657080]">Diambil dari langkah respons aturan yang terpicu. Tindakan pada sistem operasional wajib seizin komandan.</p>
          </Card>
          {incidents.length > 1 && <Card title={`Insiden lain (${incidents.length - 1})`} icon={<GitBranch size={16} className="text-[#38BDF8]" />}><div className="space-y-2">{incidents.slice(1, 8).map((inc) => <button key={inc.id} onClick={() => inc.caseId && openCase(inc.caseId)} className="flex w-full items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-left hover:border-[#38BDF8]/40"><span className="w-10 font-mono text-xs">{scorePercent(inc.score)}%</span><span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium">{inc.title}</span><span className="font-mono text-[10px] text-[#657080]">{inc.caseId} · {inc.detectionIds.length} temuan · {fmtTime(inc.firstSeen, false)}</span></span><Badge className={levelStyle[inc.level]}>{LEVEL_LABEL[inc.level]}</Badge></button>)}{incidents.length > 8 && <p className="text-[10px] text-[#657080]">+{incidents.length - 8} insiden lain di halaman Kasus.</p>}</div></Card>}
        </div>
      </div>
    </>}

    {stats && <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[1.35fr_.65fr]">
      <ActivityChart data={data} />
      <div className="space-y-4">
        <Card title="Tingkat temuan" icon={<ShieldAlert size={16} className="text-[#EF4444]" />}><SeverityDonut detections={detections} /></Card>
        <Card title="Sumber log" icon={<Database size={16} className="text-[#22C55E]" />}><div className="space-y-3">{Object.entries(stats.byDataset).sort((a, b) => b[1] - a[1]).map(([name, n]) => <div key={name}><div className="mb-1 flex justify-between text-xs"><span className="font-mono text-[#AEB6C1]">{name}</span><span className="font-mono">{fmtNumber(n)}</span></div><div className="h-1.5 rounded-full bg-[#0D1016]"><div className="h-full rounded-full bg-[#38BDF8]" style={{ width: `${(n / stats.total) * 100}%` }} /></div></div>)}</div></Card>
      </div>
    </div>}
  </div>
}

function strongest(dets: Detection[]): Level {
  return dets.reduce((a, d) => (LEVEL_RANK[d.level] > LEVEL_RANK[a] ? d.level : a), 'informational' as Level)
}

function bucketLabel(ms: number) {
  return ms >= 86_400_000 ? `${ms / 86_400_000} hari` : ms >= 3_600_000 ? `${ms / 3_600_000} jam` : `${ms / 60_000} menit`
}

function ActivityChart({ data }: { data: Investigation }) {
  const stats = data.stats!
  const flagged = new Array<number>(stats.buckets.length).fill(0)
  for (const d of data.detections) {
    const i = Math.floor((d.ts - stats.bucketStart) / stats.bucketMs)
    if (i >= 0 && i < flagged.length) flagged[i]++
  }
  const max = Math.max(...stats.buckets, 1)
  const every = Math.ceil(stats.buckets.length / 8)
  const multiDay = stats.last - stats.first > 86_400_000
  return <Card title={`Aktivitas event · per ${bucketLabel(stats.bucketMs)}`} icon={<Activity size={16} className="text-[#38BDF8]" />}>
    <div className="flex h-48 items-end gap-[3px] border-b border-[#272E3A]">{stats.buckets.map((n, i) => { const start = stats.bucketStart + i * stats.bucketMs; return <div key={i} className="relative flex h-full flex-1 flex-col justify-end" title={`${fmtTime(start, false).slice(0, 5)} · ${fmtNumber(n)} event${flagged[i] ? ` · ${flagged[i]} temuan` : ''}`}>
      {flagged[i] > 0 && <span className="absolute left-1/2 -translate-x-1/2 rounded-sm bg-[#EF4444] px-1 font-mono text-[9px] font-bold leading-4 text-white" style={{ bottom: `calc(${Math.max(3, (n / max) * 100)}% + 4px)` }}>{flagged[i]}</span>}
      <div className={`w-full rounded-t ${flagged[i] ? 'bg-gradient-to-t from-[#B91C1C] to-[#EF4444]' : 'bg-gradient-to-t from-[#0284C7] to-[#38BDF8]'}`} style={{ height: `${Math.max(n ? 3 : 0, (n / max) * 100)}%` }} />
    </div> })}</div>
    <div className="mt-1.5 flex gap-[3px]">{stats.buckets.map((_, i) => <span key={i} className="flex-1 text-center font-mono text-[9px] text-[#596474]">{i % every === 0 ? (multiDay ? fmtDate(stats.bucketStart + i * stats.bucketMs).replace(/ \d{4}$/, '') : fmtTime(stats.bucketStart + i * stats.bucketMs, false).slice(0, 5)) : ''}</span>)}</div>
    <p className="mt-3 flex flex-wrap gap-4 text-[10px] text-[#657080]"><span><i className="mr-1 inline-block size-2 rounded-sm bg-[#38BDF8]" />Event normal per {bucketLabel(stats.bucketMs)}</span><span><i className="mr-1 inline-block size-2 rounded-sm bg-[#EF4444]" />Ada temuan (angka = jumlah temuan)</span><span>{fmtDate(stats.first)} {fmtTime(stats.first, false)} – {fmtDate(stats.last)} {fmtTime(stats.last, false)} WIB</span></p>
  </Card>
}

function SeverityDonut({ detections }: { detections: Detection[] }) {
  const counts = LEVELS.map((l) => ({ level: l, n: detections.filter((d) => d.level === l).length })).filter((c) => c.n > 0)
  const total = detections.length
  let acc = 0
  const gradient = counts.map((c) => { const from = (acc / total) * 100; acc += c.n; return `${LEVEL_COLOR[c.level]} ${from}% ${(acc / total) * 100}%` }).join(', ')
  return <div className="flex items-center gap-6"><div className="relative size-32 shrink-0 rounded-full" style={{ background: total ? `conic-gradient(${gradient})` : '#1D2632' }}><div className="absolute inset-4 grid place-items-center rounded-full bg-[#131720] text-center"><span><b className="block font-mono text-2xl">{total}</b><small className="text-[9px] text-[#657080]">TEMUAN</small></span></div></div><div className="flex-1 space-y-2.5">{counts.map((c) => <div key={c.level} className="flex items-center justify-between text-xs"><span className="flex items-center gap-2"><i className="size-2 rounded-full" style={{ background: LEVEL_COLOR[c.level] }} />{LEVEL_LABEL[c.level]}</span><b className="font-mono">{c.n}</b></div>)}</div></div>
}

