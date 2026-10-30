import { useEffect, useState } from 'react'
import { Activity, BookOpenCheck, ChevronRight, CircleCheck, ClipboardList, Clock3, FileSearch, FileText, Flag, GitBranch, LayoutDashboard, Menu, ShieldAlert, ShieldCheck, Trash2, Upload, X } from 'lucide-react'
import { ClearDataDialog, ConfirmDialog } from '@/components/Dialogs'
import { LoadingState } from '@/components/LoadingState'
import { StaticNotice } from '@/components/StaticNotice'
import { Badge } from '@/components/ui/Badge'
import { LEVEL_RANK } from '@/lib/styles'
import { fmtNumber } from '@/lib/format'
import { events as demoEvents } from '@/data/demoCase'
import { RULE_PACK } from '@/data/rules/catalog'
import { useInvestigation } from '@/db/hooks'
import { useIngest } from '@/db/ingestClient'
import { AttackView } from '@/features/attack/AttackView'
import { CaseView } from '@/features/case/CaseView'
import { DetailView } from '@/features/detail/DetailView'
import { GraphView } from '@/features/graph/GraphView'
import { ImportView } from '@/features/import/ImportView'
import { LogExplorer } from '@/features/logs/LogExplorer'
import { ReportView } from '@/features/report/ReportView'
import { SummaryView } from '@/features/summary/SummaryView'
import { TimelineView } from '@/features/timeline/TimelineView'
import { UrlAnalyzer } from '@/features/url/UrlAnalyzer'

type Page = 'Ringkasan' | 'Impor Data' | 'Timeline' | 'Log Explorer' | 'Detail' | 'ATT&CK' | 'Graf Investigasi' | 'Kasus' | 'Laporan' | 'URL Offline'

/** Pages still showing the static design mockup (wired to real data in Phase 2). */
const STATIC_PAGES: Page[] = ['Ringkasan', 'Graf Investigasi', 'Kasus', 'Laporan']
const ACTOR = 'operator.satuan'

function readJson<T>(key: string, fallback: T): T {
  try {
    return JSON.parse(localStorage.getItem(key) ?? '') as T
  } catch {
    return fallback
  }
}

function writeStorage(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch {
    // Storage can be unavailable (private mode); state still works for this session.
  }
}

async function downloadSamples() {
  const [{ generateScenario }, { default: JSZip }] = await Promise.all([import('@/data/scenario/generate'), import('jszip')])
  const zip = new JSZip()
  for (const file of generateScenario().files) zip.file(file.name, file.text)
  const url = URL.createObjectURL(await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' }))
  const a = Object.assign(document.createElement('a'), { href: url, download: 'sigap-skenario-contoh.zip' })
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

function App() {
  const data = useInvestigation()
  const ingest = useIngest()
  const [active, setActive] = useState<Page | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [logFocus, setLogFocus] = useState<string | null>(null)
  const [demoSelected, setDemoSelected] = useState(demoEvents[3])
  const [mobileNav, setMobileNav] = useState(false)
  const [followups, setFollowups] = useState<Record<string, string>>(() => readJson('sigap-followups-v2', {}))
  const [caseStatus, setCaseStatus] = useState(() => localStorage.getItem('sigap-case-status') || 'Investigating')
  const [notes, setNotes] = useState(() => localStorage.getItem('sigap-notes') || '')
  const [checks, setChecks] = useState<Record<string, boolean>>(() => readJson('sigap-checks-v2', {}))
  const [toast, setToast] = useState('')
  const [now, setNow] = useState(new Date())
  const [confirm, setConfirm] = useState<{ id: string; label: string; status: string } | null>(null)
  const [clearOpen, setClearOpen] = useState(false)

  useEffect(() => {
    const clock = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(clock)
  }, [])
  useEffect(() => writeStorage('sigap-followups-v2', JSON.stringify(followups)), [followups])
  useEffect(() => writeStorage('sigap-case-status', caseStatus), [caseStatus])
  useEffect(() => writeStorage('sigap-notes', notes), [notes])
  useEffect(() => writeStorage('sigap-checks-v2', JSON.stringify(checks)), [checks])

  // Until the user navigates, land on the Timeline when there is data, else on Impor Data.
  const page: Page = active ?? (data.detections.length ? 'Timeline' : 'Impor Data')
  const go = (p: Page) => { setActive(p); setLogFocus(null); setMobileNav(false) }
  const notify = (message: string) => { setToast(message); window.setTimeout(() => setToast(''), 3200) }

  const urgent = data.detections.filter((d) => LEVEL_RANK[d.level] >= LEVEL_RANK.high).length
  const topDetection = [...data.detections].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts)[0]
  const detailDetection = data.detections.find((d) => d.id === selectedId) ?? topDetection

  const runIngest = async (request: Parameters<typeof ingest.run>[0], after?: () => void) => {
    try {
      const s = await ingest.run(request)
      if (request.type === 'clear') notify('Seluruh data lokal telah dihapus')
      else notify(`${s.files.length} berkas · ${fmtNumber(s.events)} event diimpor · ${fmtNumber(s.detections)} temuan`)
      after?.()
    } catch (err) {
      notify(`Gagal memproses: ${(err as Error).message}`)
    }
  }
  const clearAll = () => {
    setClearOpen(false)
    setFollowups({})
    setChecks({})
    setNotes('')
    setCaseStatus('Investigating')
    setSelectedId(null)
    void runIngest({ type: 'clear' }, () => setActive('Impor Data'))
  }
  const changeStatus = () => {
    if (!confirm) return
    setFollowups((v) => ({ ...v, [confirm.id]: confirm.status }))
    notify(`Status "${confirm.label}" menjadi ${confirm.status}`)
    setConfirm(null)
  }
  const openDetail = (id: string) => { setSelectedId(id); go('Detail') }

  const nav = [
    ['Ringkasan', LayoutDashboard], ['Impor Data', Upload], ['Timeline', Activity], ['Log Explorer', FileSearch], ['Detail', FileText],
    ['ATT&CK', BookOpenCheck], ['Graf Investigasi', GitBranch], ['Kasus', ClipboardList], ['Laporan', Flag], ['URL Offline', ShieldCheck],
  ] as const

  return (
    <div className="min-h-screen bg-[#090B0F] text-[#F3F5F7]">
      {toast && <div role="status" className="fixed right-5 top-5 z-50 flex max-w-md items-center gap-2 rounded-lg border border-[#22C55E]/30 bg-[#132019] px-4 py-3 text-sm shadow-2xl"><CircleCheck size={16} className="shrink-0 text-[#22C55E]" />{toast}</div>}
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-[#272E3A] bg-[#0D1016] transition-transform lg:translate-x-0 ${mobileNav ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-16 shrink-0 items-center justify-between border-b border-[#272E3A] px-5">
          <div className="flex items-center gap-3"><div className="grid size-8 place-items-center rounded-lg bg-[#38BDF8] text-[#071018]"><ShieldAlert size={18} /></div><div><div className="text-sm font-extrabold tracking-[0.16em]">SIGAP</div><div className="text-[9px] text-[#6F7A89]">PENANGANAN AWAL INSIDEN</div></div></div>
          <button className="lg:hidden" onClick={() => setMobileNav(false)} aria-label="Tutup navigasi"><X size={18} /></button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
          <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-[#657080]">Ruang kerja</div>
          <nav className="space-y-0.5">{nav.map(([label, Icon]) => <button key={label} onClick={() => go(label)} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition ${page === label ? 'bg-[#191F2A] text-white shadow-[inset_2px_0_0_#38BDF8]' : 'text-[#9BA5B4] hover:bg-[#131720] hover:text-white'}`}><Icon size={16} className={page === label ? 'text-[#38BDF8]' : ''} />{label}{label === 'Timeline' && urgent > 0 && <span className="ml-auto rounded bg-[#EF4444]/15 px-1.5 py-0.5 font-mono text-[10px] text-[#FCA5A5]">{urgent}</span>}</button>)}</nav>
        </div>
        <div className="shrink-0 border-t border-[#272E3A] p-4">
          <div className="mb-2 rounded-lg border border-[#272E3A] bg-[#131720] p-3">
            <div className="mb-1 flex items-center justify-between text-xs"><span className="font-medium">Data lokal</span><Badge className="border-[#22C55E]/20 bg-[#22C55E]/10 text-[#86EFAC]">OFFLINE</Badge></div>
            <p className="text-[11px] leading-4 text-[#737E8E]">{fmtNumber(data.eventCount)} event · {fmtNumber(data.detections.length)} temuan · {data.imports.length} berkas. Tersimpan hanya di browser ini.</p>
            <button disabled={ingest.busy || !data.eventCount} onClick={() => setClearOpen(true)} className="mt-2 flex items-center gap-1.5 text-[10px] text-[#9BA5B4] hover:text-[#FCA5A5] disabled:opacity-40"><Trash2 size={11} />Hapus data lokal</button>
          </div>
          <div className="flex items-center gap-2 text-xs text-[#9BA5B4]"><span className="size-2 rounded-full bg-[#22C55E]" />{RULE_PACK.sigma.length + RULE_PACK.native.length} aturan deteksi aktif</div>
        </div>
      </aside>

      <div className="lg:pl-60">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#272E3A] bg-[#090B0F]/90 px-4 backdrop-blur md:px-6">
          <div className="flex min-w-0 items-center gap-3"><button onClick={() => setMobileNav(true)} className="lg:hidden" aria-label="Buka navigasi"><Menu size={20} /></button><div className="min-w-0"><div className="flex items-center gap-2 text-xs text-[#7E8998]">Ruang kerja lokal <ChevronRight size={12} />{page}</div><div className="mt-0.5 truncate text-sm font-semibold">{data.detections.length ? `${fmtNumber(data.detections.length)} temuan dari ${fmtNumber(data.eventCount)} event` : data.eventCount ? `${fmtNumber(data.eventCount)} event, tanpa temuan` : 'Belum ada data — impor log untuk memulai'}</div></div></div>
          <div className="flex items-center gap-2 md:gap-4"><div className="hidden items-center gap-2 border-r border-[#272E3A] pr-4 font-mono text-[11px] text-[#7E8998] md:flex"><Clock3 size={14} />{now.toLocaleTimeString('id-ID', { hour12: false, timeZone: 'Asia/Jakarta' })} WIB</div>{data.detections.length > 0 && <Badge className="hidden border-[#EF4444]/25 bg-[#EF4444]/10 text-[#FCA5A5] sm:inline-flex"><span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-[#EF4444]" />{caseStatus.toUpperCase()}</Badge>}</div>
        </header>

        <main className="p-4 md:p-6">
          {!data.loaded ? <LoadingState /> : <>
            {STATIC_PAGES.includes(page) && <StaticNotice />}
            {page === 'Impor Data' && <ImportView imports={data.imports} eventCount={data.eventCount} detectionCount={data.detections.length} busy={ingest.busy} progress={ingest.progress} onFiles={(files) => void runIngest({ type: 'import', files, actor: ACTOR })} onScenario={() => void runIngest({ type: 'scenario', actor: ACTOR }, () => setActive('Timeline'))} onDownloadSamples={() => void downloadSamples()} onClear={() => setClearOpen(true)} />}
            {page === 'Timeline' && <TimelineView detections={data.detections} eventsById={data.eventsById} eventCount={data.eventCount} selectedId={selectedId} onSelect={setSelectedId} openDetail={openDetail} openImport={() => go('Impor Data')} />}
            {page === 'Log Explorer' && <LogExplorer key={logFocus ?? 'all'} detections={data.detections} focusEventId={logFocus} openDetection={openDetail} />}
            {page === 'Detail' && <DetailView detection={detailDetection} detections={data.detections} eventsById={data.eventsById} followup={detailDetection ? followups[detailDetection.id] || 'Baru' : 'Baru'} changeStatus={(id, status) => setConfirm({ id, status, label: data.detections.find((d) => d.id === id)?.title ?? id })} select={setSelectedId} checks={checks} setChecks={setChecks} openLogs={(eventId) => { setLogFocus(eventId); setActive('Log Explorer') }} openTimeline={() => go('Timeline')} />}
            {page === 'ATT&CK' && <AttackView detections={data.detections} select={openDetail} />}
            {page === 'Kasus' && <CaseView status={caseStatus} setStatus={setCaseStatus} notes={notes} setNotes={setNotes} followups={followups} notify={notify} />}
            {page === 'Graf Investigasi' && <GraphView selected={demoSelected} selectEvent={setDemoSelected} openDetail={() => notify('Graf akan terhubung ke data impor pada tahap korelasi')} />}
            {page === 'URL Offline' && <UrlAnalyzer />}
            {page === 'Laporan' && <ReportView followups={followups} changeStatus={(id, status) => setConfirm({ id, status, label: id })} notify={notify} caseStatus={caseStatus} notes={notes} />}
            {page === 'Ringkasan' && <SummaryView setActive={go} />}
          </>}
        </main>
      </div>
      {confirm && <ConfirmDialog id={confirm.label} status={confirm.status} cancel={() => setConfirm(null)} confirm={changeStatus} />}
      {clearOpen && <ClearDataDialog cancel={() => setClearOpen(false)} confirm={clearAll} />}
    </div>
  )
}

export default App
