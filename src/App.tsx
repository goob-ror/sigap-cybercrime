import { useEffect, useRef, useState } from 'react'
import { Activity, BookOpenCheck, ChevronRight, CircleCheck, ClipboardList, Clock3, FileSearch, FileText, Flag, GitBranch, LayoutDashboard, Menu, ShieldAlert, ShieldCheck, Trash2, Upload, X } from 'lucide-react'
import { ClearDataDialog, ConfirmDialog } from '@/components/Dialogs'
import { LoadingState } from '@/components/LoadingState'
import { Badge } from '@/components/ui/Badge'
import type { Detection, FollowUpStatus } from '@/core/model'
import { CASE_STATUS_LABEL, caseStatusStyle } from '@/lib/styles'
import { fmtNumber } from '@/lib/format'
import { RULE_PACK } from '@/data/rules/catalog'
import { setFollowUp } from '@/db/cases'
import { orderedCases, useInvestigation } from '@/db/hooks'
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
import { ENGINE_VERSION } from '@/workers/protocol'

type Page = 'Ringkasan' | 'Impor Data' | 'Timeline' | 'Log Explorer' | 'Detail' | 'ATT&CK' | 'Graf Investigasi' | 'Kasus' | 'Laporan' | 'URL Offline'

const ACTOR = 'operator.satuan'

async function downloadSamples() {
  const [{ generateScenario }, { default: JSZip }] = await Promise.all([import('@/data/scenario/generate'), import('jszip')])
  const zip = new JSZip()
  for (const file of generateScenario().files) zip.file(file.name, file.text)
  const url = URL.createObjectURL(await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' }))
  const a = Object.assign(document.createElement('a'), { href: url, download: 'sigap-skenario-contoh.zip' })
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

type PendingFollowUp = { caseId: string; detection: Detection; status: FollowUpStatus }

function App() {
  const data = useInvestigation()
  const ingest = useIngest()
  const [active, setActive] = useState<Page | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [caseId, setCaseId] = useState<string | null>(null)
  const [graphIncident, setGraphIncident] = useState<string | null>(null)
  const [logFocus, setLogFocus] = useState<string | null>(null)
  const [mobileNav, setMobileNav] = useState(false)
  const [toast, setToast] = useState('')
  const [now, setNow] = useState(new Date())
  const [confirm, setConfirm] = useState<PendingFollowUp | null>(null)
  const [clearOpen, setClearOpen] = useState(false)

  useEffect(() => {
    const clock = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(clock)
  }, [])

  // Results stored by an older version of SIGAP are recomputed from the stored events. Decided
  // once, on the first load, so an import in progress never triggers it.
  const startupChecked = useRef(false)
  useEffect(() => {
    if (!data.loaded || startupChecked.current) return
    startupChecked.current = true
    if (!data.eventCount || data.engine === ENGINE_VERSION) return
    ingest.run({ type: 'reanalyze' }).then((s) => notify(`Analisis diperbarui: ${fmtNumber(s.detections)} temuan · ${fmtNumber(s.incidents)} insiden`), (err: Error) => notify(`Gagal memperbarui analisis: ${err.message}`))
  })

  // Until the user navigates, land on Ringkasan when there is data, else on Impor Data.
  const page: Page = active ?? (data.eventCount ? 'Ringkasan' : 'Impor Data')
  const go = (p: Page) => { setActive(p); setLogFocus(null); setMobileNav(false) }
  const notify = (message: string) => { setToast(message); window.setTimeout(() => setToast(''), 3200) }

  const openCases = data.cases.filter((c) => c.status !== 'Resolved').length
  const topCase = orderedCases(data)[0]?.c
  const topDetection = data.incidents[0] ? data.detectionsById.get(data.incidents[0].detectionIds[0]) : data.detections[0]
  const detailDetection = (selectedId ? data.detectionsById.get(selectedId) : undefined) ?? topDetection

  const runIngest = async (request: Parameters<typeof ingest.run>[0], after?: () => void) => {
    try {
      const s = await ingest.run(request)
      if (request.type === 'clear') notify('Seluruh data lokal telah dihapus')
      else notify(`${s.files.length} berkas · ${fmtNumber(s.events)} event · ${fmtNumber(s.detections)} temuan · ${fmtNumber(s.incidents)} insiden`)
      after?.()
    } catch (err) {
      notify(`Gagal memproses: ${(err as Error).message}`)
    }
  }
  const clearAll = () => {
    setClearOpen(false)
    setSelectedId(null)
    setCaseId(null)
    setGraphIncident(null)
    void runIngest({ type: 'clear' }, () => setActive('Impor Data'))
  }
  const applyFollowUp = () => {
    if (!confirm) return
    void setFollowUp(confirm.caseId, confirm.detection.id, confirm.detection.title, confirm.status, ACTOR)
    notify(`Tindak lanjut "${confirm.detection.title}" menjadi ${confirm.status}`)
    setConfirm(null)
  }
  const changeFollowUp = (id: string, detection: Detection, status: FollowUpStatus) => setConfirm({ caseId: id, detection, status })
  const openDetail = (id: string) => { setSelectedId(id); go('Detail') }
  const openCase = (id: string) => { setCaseId(id); go('Kasus') }
  const openGraph = (id: string) => { setGraphIncident(id); go('Graf Investigasi') }
  const openReport = (id: string) => { setCaseId(id); go('Laporan') }

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
          <nav className="space-y-0.5">{nav.map(([label, Icon]) => <button key={label} onClick={() => go(label)} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition ${page === label ? 'bg-[#191F2A] text-white shadow-[inset_2px_0_0_#38BDF8]' : 'text-[#9BA5B4] hover:bg-[#131720] hover:text-white'}`}><Icon size={16} className={page === label ? 'text-[#38BDF8]' : ''} />{label}{label === 'Kasus' && openCases > 0 && <span className="ml-auto rounded bg-[#EF4444]/15 px-1.5 py-0.5 font-mono text-[10px] text-[#FCA5A5]">{openCases}</span>}</button>)}</nav>
        </div>
        <div className="shrink-0 border-t border-[#272E3A] p-4">
          <div className="mb-2 rounded-lg border border-[#272E3A] bg-[#131720] p-3">
            <div className="mb-1 flex items-center justify-between text-xs"><span className="font-medium">Data lokal</span><Badge className="border-[#22C55E]/20 bg-[#22C55E]/10 text-[#86EFAC]">OFFLINE</Badge></div>
            <p className="text-[11px] leading-4 text-[#737E8E]">{fmtNumber(data.eventCount)} event · {fmtNumber(data.detections.length)} temuan · {data.cases.length} kasus · {data.imports.length} berkas. Tersimpan hanya di browser ini.</p>
            <button disabled={ingest.busy || !data.eventCount} onClick={() => setClearOpen(true)} className="mt-2 flex items-center gap-1.5 text-[10px] text-[#9BA5B4] hover:text-[#FCA5A5] disabled:opacity-40"><Trash2 size={11} />Hapus data lokal</button>
          </div>
          <div className="flex items-center gap-2 text-xs text-[#9BA5B4]"><span className="size-2 rounded-full bg-[#22C55E]" />{RULE_PACK.sigma.length + RULE_PACK.native.length} aturan deteksi aktif</div>
        </div>
      </aside>

      <div className="lg:pl-60">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#272E3A] bg-[#090B0F]/90 px-4 backdrop-blur md:px-6">
          <div className="flex min-w-0 items-center gap-3"><button onClick={() => setMobileNav(true)} className="lg:hidden" aria-label="Buka navigasi"><Menu size={20} /></button><div className="min-w-0"><div className="flex items-center gap-2 text-xs text-[#7E8998]">Ruang kerja lokal <ChevronRight size={12} />{page}</div><div className="mt-0.5 truncate text-sm font-semibold">{data.detections.length ? `${fmtNumber(data.incidents.length)} insiden · ${fmtNumber(data.detections.length)} temuan dari ${fmtNumber(data.eventCount)} event` : data.eventCount ? `${fmtNumber(data.eventCount)} event, tanpa temuan` : 'Belum ada data — impor log untuk memulai'}</div></div></div>
          <div className="flex items-center gap-2 md:gap-4"><div className="hidden items-center gap-2 border-r border-[#272E3A] pr-4 font-mono text-[11px] text-[#7E8998] md:flex"><Clock3 size={14} />{now.toLocaleTimeString('id-ID', { hour12: false, timeZone: 'Asia/Jakarta' })} WIB</div>{topCase && <button onClick={() => openCase(topCase.id)} className="hidden sm:block" title="Buka kasus prioritas"><Badge className={caseStatusStyle[topCase.status]}>{topCase.status !== 'Resolved' && <span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-current" />}{topCase.id} · {CASE_STATUS_LABEL[topCase.status].toUpperCase()}</Badge></button>}</div>
        </header>

        <main className="p-4 md:p-6">
          {!data.loaded ? <LoadingState /> : <>
            {page === 'Ringkasan' && <SummaryView data={data} openImport={() => go('Impor Data')} openCase={openCase} openGraph={openGraph} openTimeline={() => go('Timeline')} openDetail={openDetail} />}
            {page === 'Impor Data' && <ImportView imports={data.imports} eventCount={data.eventCount} detectionCount={data.detections.length} incidentCount={data.incidents.length} check={data.check} busy={ingest.busy} progress={ingest.progress} onFiles={(files) => void runIngest({ type: 'import', files, actor: ACTOR })} onScenario={() => void runIngest({ type: 'scenario', actor: ACTOR }, () => setActive('Ringkasan'))} onDownloadSamples={() => void downloadSamples()} onClear={() => setClearOpen(true)} />}
            {page === 'Timeline' && <TimelineView data={data} selectedId={selectedId} onSelect={setSelectedId} openDetail={openDetail} openImport={() => go('Impor Data')} openCase={openCase} />}
            {page === 'Log Explorer' && <LogExplorer key={logFocus ?? 'all'} detections={data.detections} focusEventId={logFocus} openDetection={openDetail} />}
            {page === 'Detail' && <DetailView detection={detailDetection} data={data} actor={ACTOR} changeFollowUp={changeFollowUp} select={setSelectedId} openLogs={(eventId) => { setLogFocus(eventId); setActive('Log Explorer') }} openTimeline={() => go('Timeline')} openCase={openCase} />}
            {page === 'ATT&CK' && <AttackView detections={data.detections} select={openDetail} />}
            {page === 'Graf Investigasi' && <GraphView data={data} incidentId={graphIncident} selectIncident={setGraphIncident} openDetail={openDetail} openImport={() => go('Impor Data')} />}
            {page === 'Kasus' && <CaseView data={data} caseId={caseId} selectCase={setCaseId} actor={ACTOR} notify={notify} changeFollowUp={changeFollowUp} openDetail={openDetail} openGraph={openGraph} openReport={openReport} openImport={() => go('Impor Data')} />}
            {page === 'Laporan' && <ReportView data={data} caseId={caseId} selectCase={setCaseId} actor={ACTOR} notify={notify} openImport={() => go('Impor Data')} />}
            {page === 'URL Offline' && <UrlAnalyzer />}
          </>}
        </main>
      </div>
      {confirm && <ConfirmDialog id={confirm.detection.title} status={confirm.status} cancel={() => setConfirm(null)} confirm={applyFollowUp} />}
      {clearOpen && <ClearDataDialog cancel={() => setClearOpen(false)} confirm={clearAll} />}
    </div>
  )
}

export default App
