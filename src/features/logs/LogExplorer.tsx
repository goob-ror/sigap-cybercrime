import { useEffect, useMemo, useRef, useState } from 'react'
import { useLiveQuery } from 'dexie-react-hooks'
import { ChevronDown, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Filter, Search, ShieldAlert, Upload } from 'lucide-react'
import { KindMark } from '@/components/KindMark'
import { Badge } from '@/components/ui/Badge'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import { Select } from '@/components/ui/Select'
import { parseLogQuery, wibInputToMs, type LogFilter } from '@/core/logQuery'
import type { Detection, NormalizedEvent, SourceKind } from '@/core/model'
import { db } from '@/db/db'
import { eventPosition, matchLogs, readLogPage } from '@/db/logs'
import { fmtDate, fmtDateTime, fmtNumber, fmtTime } from '@/lib/format'
import { KIND_LABEL, LEVEL_LABEL, LEVEL_RANK, levelStyle } from '@/lib/styles'

type Props = {
  detections: Detection[]
  /** Event to open and scroll to, e.g. from "Buka di Log Explorer". */
  focusEventId: string | null
  openDetection: (id: string) => void
  openImport: () => void
}

const PAGE_SIZE = 100
const ALL_KINDS = 'Semua sumber'
const ALL_DATASETS = 'Semua jenis log'
const ALL_HOSTS = 'Semua host'
const KINDS: SourceKind[] = ['endpoint', 'server', 'network', 'ot']
const KIND_OPTIONS = [ALL_KINDS, ...KINDS.map((k) => KIND_LABEL[k])]
const TIME_INPUT = 'h-9 min-w-0 flex-1 rounded-lg border border-[#272E3A] bg-[#0D1016] px-2 text-xs text-[#CBD1D8] outline-none [color-scheme:dark] focus:border-[#38BDF8]/60'
const rowId = (eventId: string) => `log-${eventId}`

export function LogExplorer({ detections, focusEventId, openDetection, openImport }: Props) {
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState(ALL_KINDS)
  const [dataset, setDataset] = useState(ALL_DATASETS)
  const [host, setHost] = useState(ALL_HOSTS)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [page, setPage] = useState(0)
  const [openId, setOpenId] = useState<string | null>(focusEventId)
  const [focusMissing, setFocusMissing] = useState(false)

  // Typing should not start a scan of every event on each key press.
  useEffect(() => {
    if (text === query) return
    const timer = window.setTimeout(() => { setQuery(text); setPage(0) }, 200)
    return () => window.clearTimeout(timer)
  }, [text, query])

  // Highest level first, so a row can show its most serious finding.
  const byEvent = useMemo(() => {
    const map = new Map<string, Detection[]>()
    for (const d of detections) for (const id of d.eventIds) map.set(id, [...(map.get(id) ?? []), d])
    for (const list of map.values()) list.sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level])
    return map
  }, [detections])
  const flaggedIds = useMemo(() => new Set(byEvent.keys()), [byEvent])

  const filter = useMemo<LogFilter>(() => ({
    terms: parseLogQuery(query),
    kind: KINDS.find((k) => KIND_LABEL[k] === kind) ?? null,
    dataset: dataset === ALL_DATASETS ? null : dataset,
    host: host === ALL_HOSTS ? null : host,
    from: wibInputToMs(from),
    to: wibInputToMs(to, true),
    only: flaggedOnly ? flaggedIds : null,
  }), [query, kind, dataset, host, from, to, flaggedOnly, flaggedIds])

  // Each result names what it answers, so the page can tell when it is still showing an older one.
  const match = useLiveQuery(async () => ({ filter, ...(await matchLogs(filter)) }), [filter])
  const result = useLiveQuery(async () => (match ? { filter: match.filter, requested: page, total: match.total, ...(await readLogPage(match.filter, match, page, PAGE_SIZE)) } : undefined), [match, page])
  const searching = !result || result.filter !== filter || result.requested !== page

  const datasets = useLiveQuery(() => db.events.orderBy('dataset').uniqueKeys()) as string[] | undefined
  const hosts = useLiveQuery(() => db.events.orderBy('host').uniqueKeys()) as string[] | undefined
  const sources = useLiveQuery(() => db.artifacts.where('kind').equals('log').toArray())
  const sourceName = useMemo(() => new Map((sources ?? []).map((a) => [a.id.replace(/^log-/, ''), a.filename])), [sources])

  useEffect(() => {
    if (!focusEventId) return
    let cancelled = false
    void eventPosition(focusEventId).then((position) => {
      if (cancelled) return
      if (position === null) setFocusMissing(true)
      else setPage(Math.floor(position / PAGE_SIZE))
    })
    return () => { cancelled = true }
  }, [focusEventId])

  const scrolled = useRef(false)
  useEffect(() => {
    if (!focusEventId || scrolled.current || !result?.events.some((e) => e.id === focusEventId)) return
    scrolled.current = true
    document.getElementById(rowId(focusEventId))?.scrollIntoView({ block: 'center' })
  }, [result, focusEventId])

  const filtering = !!text || kind !== ALL_KINDS || dataset !== ALL_DATASETS || host !== ALL_HOSTS || !!from || !!to || flaggedOnly
  const reset = () => { setText(''); setQuery(''); setKind(ALL_KINDS); setDataset(ALL_DATASETS); setHost(ALL_HOSTS); setFrom(''); setTo(''); setFlaggedOnly(false); setPage(0) }
  const changed = <T,>(set: (value: T) => void) => (value: T) => { set(value); setPage(0) }

  if (!searching && result.total === 0 && !filtering) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]"><Upload size={22} /></div><h1 className="text-lg font-semibold">Belum ada log</h1><p className="mt-2 text-sm text-[#7E8998]">Impor log satuan atau muat skenario contoh untuk mulai menelusuri.</p><button onClick={openImport} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Impor Data</button></div></div>
  }

  const first = result && result.total ? result.page * PAGE_SIZE + 1 : 0
  const last = result ? Math.min((result.page + 1) * PAGE_SIZE, result.total) : 0

  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6"><PageTitle eyebrow="Investigasi / Log" title="Log Explorer" text="Semua event dari berkas yang diimpor, termasuk yang tidak memicu aturan. Pakai untuk memeriksa apa yang terjadi di sekitar sebuah temuan." /></div>

    <div className="mb-3 space-y-2 rounded-xl border border-[#272E3A] bg-[#131720] p-3">
      <div className="relative"><Search size={15} className="absolute left-3 top-2.5 text-[#687384]" /><input aria-label="Cari log" value={text} onChange={(e) => setText(e.target.value)} placeholder="Cari teks, atau kolom:nilai — mis. host:WS-MIN-03 EventID:4688" className="h-9 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] pl-9 pr-3 text-xs outline-none placeholder:text-[#56606E] focus:border-[#38BDF8]/60" /></div>
      <div className="flex flex-col gap-2 lg:flex-row lg:flex-wrap lg:items-center">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 lg:flex">
          <Select value={kind} setValue={changed(setKind)} options={KIND_OPTIONS} />
          <Select value={dataset} setValue={changed(setDataset)} options={[ALL_DATASETS, ...(datasets ?? [])]} />
          <Select value={host} setValue={changed(setHost)} options={[ALL_HOSTS, ...(hosts ?? [])]} />
        </div>
        <div className="flex min-w-0 items-center gap-2 lg:min-w-[420px] lg:flex-1"><input aria-label="Dari waktu (WIB)" title="Dari waktu (WIB)" type="datetime-local" value={from} onChange={(e) => changed(setFrom)(e.target.value)} className={TIME_INPUT} /><span className="text-[10px] text-[#657080]">s.d.</span><input aria-label="Sampai waktu (WIB)" title="Sampai waktu (WIB)" type="datetime-local" value={to} onChange={(e) => changed(setTo)(e.target.value)} className={TIME_INPUT} /></div>
        <div className="flex gap-2">
          <button aria-pressed={flaggedOnly} onClick={() => changed(setFlaggedOnly)(!flaggedOnly)} className={`flex h-9 flex-1 items-center justify-center gap-2 whitespace-nowrap rounded-lg border px-3 text-xs lg:flex-none ${flaggedOnly ? 'border-[#F59E0B]/40 bg-[#F59E0B]/10 text-[#FBBF24]' : 'border-[#272E3A] text-[#9BA5B4] hover:text-white'}`}><ShieldAlert size={14} />Hanya bertanda</button>
          <button disabled={!filtering} onClick={reset} className="flex h-9 flex-1 items-center justify-center gap-2 rounded-lg border border-[#272E3A] px-3 text-xs text-[#9BA5B4] hover:text-white disabled:opacity-40 lg:flex-none"><Filter size={14} />Reset</button>
        </div>
      </div>
    </div>

    {focusMissing && <p role="status" className="mb-3 rounded-lg border border-[#F59E0B]/30 bg-[#F59E0B]/10 px-3 py-2 text-xs text-[#FCD34D]">Event yang diminta tidak ada lagi di data lokal.</p>}

    <section className="overflow-hidden rounded-xl border border-[#272E3A] bg-[#0D1016]">
      <div className="flex items-center justify-between gap-3 border-b border-[#272E3A] px-4 py-2.5 text-[11px] text-[#7E8998]">
        <span role="status" aria-busy={searching}>{searching ? 'Mencari…' : `${fmtNumber(first)}–${fmtNumber(last)} dari ${fmtNumber(result.total)} event`}</span>
        {result && <Pager page={result.page} pageCount={result.pageCount} setPage={setPage} />}
      </div>
      <div className={searching ? 'opacity-50' : ''}>
      {result?.events.length === 0 ? <div className="grid min-h-64 place-items-center text-center"><div><Search className="mx-auto mb-3 text-[#536071]" /><div className="text-sm font-medium">Tidak ada event yang cocok</div><div className="mt-1 text-xs text-[#687384]">Ubah kata kunci atau filter pencarian.</div></div></div> :
        result?.events.map((e) => <LogRow key={e.id} event={e} detections={byEvent.get(e.id) ?? []} open={openId === e.id} focused={focusEventId === e.id} source={sourceName.get(e.importId)} toggle={() => setOpenId(openId === e.id ? null : e.id)} openDetection={openDetection} />)}
      </div>
      {result && result.pageCount > 1 && <div className="flex justify-end border-t border-[#272E3A] px-4 py-2.5"><Pager page={result.page} pageCount={result.pageCount} setPage={setPage} /></div>}
    </section>
  </div>
}

function Pager({ page, pageCount, setPage }: { page: number; pageCount: number; setPage: (page: number) => void }) {
  const button = 'grid size-7 place-items-center rounded-md border border-[#272E3A] text-[#AEB6C1] hover:text-white disabled:opacity-30'
  const atStart = page === 0
  const atEnd = page + 1 >= pageCount
  return <div className="flex shrink-0 items-center gap-1.5"><button aria-label="Halaman pertama (terlama)" title="Terlama" disabled={atStart} onClick={() => setPage(0)} className={button}><ChevronsLeft size={14} /></button><button aria-label="Halaman sebelumnya" disabled={atStart} onClick={() => setPage(page - 1)} className={button}><ChevronLeft size={14} /></button><span className="whitespace-nowrap px-0.5 font-mono text-[10px]">{fmtNumber(page + 1)} / {fmtNumber(pageCount)}</span><button aria-label="Halaman berikutnya" disabled={atEnd} onClick={() => setPage(page + 1)} className={button}><ChevronRight size={14} /></button><button aria-label="Halaman terakhir (terbaru)" title="Terbaru" disabled={atEnd} onClick={() => setPage(-1)} className={button}><ChevronsRight size={14} /></button></div>
}

type RowProps = { event: NormalizedEvent; detections: Detection[]; open: boolean; focused: boolean; source: string | undefined; toggle: () => void; openDetection: (id: string) => void }

function LogRow({ event: e, detections, open, focused, source, toggle, openDetection }: RowProps) {
  const top = detections[0]
  return <div id={rowId(e.id)} className={`border-b border-[#1D232D] last:border-0 ${focused ? 'bg-[#38BDF8]/[0.05] shadow-[inset_2px_0_0_#38BDF8]' : ''}`}>
    <button aria-expanded={open} onClick={toggle} className="grid w-full grid-cols-[74px_32px_minmax(0,1fr)_14px] gap-3 px-4 py-3 text-left transition hover:bg-[#131720] md:grid-cols-[112px_40px_minmax(0,1fr)_160px_96px_14px]">
      <div><div className="font-mono text-xs text-[#D8DCE2]">{fmtTime(e.ts, false)}</div><div className="mt-1 text-[10px] text-[#657080]">{fmtDate(e.ts)}</div></div>
      <div><KindMark kind={e.sourceKind} /></div>
      <div className="min-w-0"><p className="truncate text-xs text-[#CBD1D8]">{e.message || '—'}</p><div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-[#667180]"><span>{e.dataset}</span><span className="md:hidden">{e.host ?? e.srcIp}</span>{top && <Badge className={`md:hidden ${levelStyle[top.level]}`}>{LEVEL_LABEL[top.level]}</Badge>}</div></div>
      <div className="hidden min-w-0 md:block"><div className="truncate font-mono text-[11px]">{e.host ?? e.srcIp ?? '—'}</div><div className="mt-1 truncate text-[10px] text-[#7E8998]">{e.user ?? e.dstIp ?? ''}</div></div>
      <div className="hidden md:block">{top && <Badge className={levelStyle[top.level]}>{LEVEL_LABEL[top.level]}</Badge>}</div>
      <ChevronDown size={14} className={`mt-0.5 text-[#657080] transition ${open ? 'rotate-180' : ''}`} />
    </button>
    {open && <LogDetail event={e} detections={detections} source={source} openDetection={openDetection} />}
  </div>
}

function Row({ name, value }: { name: string; value: string }) {
  return <div className="grid grid-cols-1 gap-x-3 border-b border-[#1D232D] py-1.5 last:border-0 sm:grid-cols-[minmax(0,180px)_minmax(0,1fr)]"><dt className="break-words font-mono text-[10px] text-[#7E8998]">{name}</dt><dd className="max-h-64 overflow-y-auto whitespace-pre-wrap break-words font-mono text-[11px] text-[#D1D6DD]">{value}</dd></div>
}

function LogDetail({ event: e, detections, source, openDetection }: { event: NormalizedEvent; detections: Detection[]; source: string | undefined; openDetection: (id: string) => void }) {
  const line = e.id.split(':').pop()
  const summary: [string, string | number | undefined][] = [
    ['Waktu', fmtDateTime(e.ts)],
    ['Berkas sumber', source ? `${source} (baris/entri ${line})` : undefined],
    ['Host', e.host],
    ['Akun', e.user],
    ['IP sumber', e.srcIp],
    ['IP tujuan', e.dstIp ? `${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ''}` : undefined],
    ['Domain', e.domain],
    ['URL', e.url],
    ['Proses', e.process?.name],
    ['Baris perintah', e.process?.cmdline],
    ['Proses induk', e.process?.parent],
    ['Berkas', e.file?.path],
  ]
  const original = Object.entries(e.fields).filter(([, value]) => value !== null && value !== '')
  return <div className="grid grid-cols-1 gap-4 border-t border-[#272E3A]/70 bg-[#0B0E13] px-4 py-3 lg:grid-cols-2">
    <div className="min-w-0">
      {detections.length > 0 && <div className="mb-4"><Label>Temuan dari event ini</Label><div className="flex flex-col gap-1.5">{detections.map((d) => <button key={d.id} onClick={() => openDetection(d.id)} className="flex items-center gap-2 rounded-md border border-[#272E3A] bg-[#191F2A] px-2 py-1.5 text-left text-[11px] text-[#CBD1D8] hover:border-[#38BDF8]/50"><Badge className={`shrink-0 ${levelStyle[d.level]}`}>{LEVEL_LABEL[d.level]}</Badge><span className="min-w-0 truncate">{d.title}</span></button>)}</div></div>}
      <Label>Ringkasan</Label>
      <dl>{summary.filter((s): s is [string, string | number] => s[1] !== undefined && s[1] !== '').map(([name, value]) => <Row key={name} name={name} value={String(value)} />)}</dl>
    </div>
    <div className="min-w-0"><Label>Kolom asli ({original.length})</Label><dl>{original.map(([name, value]) => <Row key={name} name={name} value={String(value)} />)}</dl></div>
  </div>
}
