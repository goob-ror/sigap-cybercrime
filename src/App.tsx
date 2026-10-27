import { useEffect, useMemo, useState } from 'react'
import {
  Activity, Bell, BookOpenCheck, Box, Braces, CheckSquare, ChevronDown,
  ChevronRight, CircleCheck, ClipboardList, Clock3, Cpu, Database, Download,
  ExternalLink, FileSearch, FileText, Filter, Flag, GitBranch, Globe2,
  LayoutDashboard, Link2, Mail, Menu, Monitor, Network, PanelLeftClose,
  RefreshCcw, Router, Search, ShieldAlert, ShieldCheck, StickyNote,
  TriangleAlert, UserRound, X, Zap,
} from 'lucide-react'

type Severity = 'Kritis' | 'Tinggi' | 'Sedang' | 'Rendah'
type Source = 'Email Gateway' | 'Endpoint' | 'Jaringan' | 'OT Simulator'
type Page = 'Ringkasan' | 'Kasus' | 'Timeline' | 'Log Explorer' | 'Graf Investigasi' | 'URL Offline' | 'ATT&CK' | 'Detail' | 'Laporan'
type Event = {
  id: string; time: string; date: string; title: string; detail: string; source: Source
  user: string; host: string; ip: string; severity: Severity; mitre?: string
  finding: string; evidence: string[]; rule: string; unknown: string; related: string[]
}

const events: Event[] = [
  { id: 'EVT-2401', time: '08:42:13.219', date: '18 Jun 2025', title: 'Lampiran phishing terkirim', detail: 'Dokumen invoice dengan macro diterima dari domain baru.', source: 'Email Gateway', user: 'n.rahma', host: 'WS-FIN-014', ip: '185.220.101.42', severity: 'Tinggi', mitre: 'T1566.001', finding: 'Initial access melalui spearphishing attachment', evidence: ['SHA256 lampiran: 7f3a…91bd', 'Domain pengirim berusia 2 hari', 'DMARC gagal; nama tampil meniru vendor'], rule: 'Lampiran executable/macro + domain baru + autentikasi email gagal', unknown: 'Belum diketahui apakah pengguna membuka dokumen.', related: ['EVT-2402'] },
  { id: 'EVT-2402', time: '08:45:37.904', date: '18 Jun 2025', title: 'Proses Office memanggil PowerShell', detail: 'WINWORD.EXE membuat proses PowerShell dengan argumen terenkripsi.', source: 'Endpoint', user: 'n.rahma', host: 'WS-FIN-014', ip: '10.20.4.18', severity: 'Kritis', mitre: 'T1059.001', finding: 'Eksekusi payload dan pencurian kredensial', evidence: ['Parent: WINWORD.EXE → powershell.exe', 'Command line memuat -EncodedCommand', 'Koneksi ke 185.220.101.42'], rule: 'Office child process + encoded command + IOC jaringan cocok', unknown: 'Kredensial spesifik yang terekspos masih diverifikasi.', related: ['EVT-2401', 'EVT-2403'] },
  { id: 'EVT-2403', time: '09:17:04.112', date: '18 Jun 2025', title: 'Login dari lokasi dan perangkat baru', detail: 'Autentikasi berhasil dari ASN yang belum pernah digunakan akun ini.', source: 'Jaringan', user: 'n.rahma', host: 'VPN-GW-01', ip: '103.156.92.17', severity: 'Tinggi', mitre: 'T1078', finding: 'Penyalahgunaan akun valid', evidence: ['Device fingerprint baru', 'Impossible travel: Jakarta → Sofia (34 menit)', 'MFA push disetujui satu kali'], rule: 'Perubahan ASN + impossible travel + korelasi akun korban', unknown: 'Belum ada konfirmasi apakah MFA disetujui pengguna.', related: ['EVT-2402', 'EVT-2404'] },
  { id: 'EVT-2404', time: '09:23:51.477', date: '18 Jun 2025', title: 'Pergerakan lateral melalui SMB', detail: 'Akun mengakses share administratif di server engineering.', source: 'Jaringan', user: 'n.rahma', host: 'ENG-SRV-02', ip: '10.20.4.18', severity: 'Kritis', mitre: 'T1021.002', finding: 'Lateral movement ke zona engineering', evidence: ['ADMIN$ diakses dari WS-FIN-014', 'Akun finansial tidak punya pola akses engineering', 'Session ID sama dengan logon anomali'], rule: 'Akses admin share lintas zona + baseline role mismatch', unknown: 'Artefak yang dipindahkan lewat share belum ditemukan.', related: ['EVT-2403', 'EVT-2405'] },
  { id: 'EVT-2405', time: '09:31:28.660', date: '18 Jun 2025', title: 'Perubahan setpoint PLC simulasi', detail: 'Setpoint tekanan dinaikkan 18% di luar change window.', source: 'OT Simulator', user: 'svc_engr', host: 'PLC-SIM-07', ip: '10.40.7.22', severity: 'Kritis', mitre: 'T0836', finding: 'Manipulasi proses OT simulasi', evidence: ['Setpoint 72 → 85 PSI', 'Tidak ada work order aktif', 'Sesi berasal dari ENG-SRV-02'], rule: 'Perubahan parameter safety-sensitive + tanpa change ticket', unknown: 'Dampak fisik tidak ada karena aset bersifat simulasi.', related: ['EVT-2404', 'EVT-2406'] },
  { id: 'EVT-2406', time: '09:44:09.031', date: '18 Jun 2025', title: 'Transfer data keluar berukuran besar', detail: 'Arsip terenkripsi 1,8 GB dikirim ke penyimpanan anonim.', source: 'Jaringan', user: 'n.rahma', host: 'ENG-SRV-02', ip: '45.153.160.2', severity: 'Kritis', mitre: 'T1041', finding: 'Eksfiltrasi data terindikasi kuat', evidence: ['Outbound 1,8 GB ke host tanpa reputasi', 'Arsip dibuat 3 menit sebelum transfer', 'Korelasi host dengan SMB lateral'], rule: 'Lonjakan outbound + arsip baru + tujuan anonim', unknown: 'Isi arsip masih menunggu hasil forensik.', related: ['EVT-2404', 'EVT-2405'] },
]

const severityStyle: Record<Severity, string> = {
  Kritis: 'text-[#FCA5A5] bg-[#EF4444]/10 border-[#EF4444]/25',
  Tinggi: 'text-[#FBBF24] bg-[#F59E0B]/10 border-[#F59E0B]/25',
  Sedang: 'text-[#7DD3FC] bg-[#38BDF8]/10 border-[#38BDF8]/25',
  Rendah: 'text-[#86EFAC] bg-[#22C55E]/10 border-[#22C55E]/25',
}

const sourceIcon: Record<Source, string> = {
  'Email Gateway': 'EM', Endpoint: 'ED', Jaringan: 'NW', 'OT Simulator': 'OT',
}

function Badge({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-semibold tracking-wide ${className}`}>{children}</span>
}

function App() {
  const [active, setActive] = useState<Page>('Timeline')
  const [selected, setSelected] = useState(events[3])
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('Semua')
  const [source, setSource] = useState('Semua sumber')
  const [panel, setPanel] = useState(true)
  const [mobileNav, setMobileNav] = useState(false)
  const [followups, setFollowups] = useState<Record<string, string>>(() => JSON.parse(localStorage.getItem('sigap-followups') || '{"EVT-2402":"Berjalan","EVT-2404":"Baru","EVT-2405":"Berjalan","EVT-2406":"Baru"}'))
  const [caseStatus, setCaseStatus] = useState(() => localStorage.getItem('sigap-case-status') || 'Investigating')
  const [notes, setNotes] = useState(() => localStorage.getItem('sigap-notes') || 'Validasi persetujuan MFA dan akuisisi artefak ENG-SRV-02 sebelum remediasi.')
  const [checks, setChecks] = useState<Record<string, boolean>>(() => JSON.parse(localStorage.getItem('sigap-checks') || '{}'))
  const [toast, setToast] = useState('')
  const [now, setNow] = useState(new Date())
  const [loading, setLoading] = useState(true)
  const [confirm, setConfirm] = useState<{ id: string; status: string } | null>(null)
  const [resetOpen, setResetOpen] = useState(false)

  useEffect(() => {
    const clock = window.setInterval(() => setNow(new Date()), 1000)
    const ready = window.setTimeout(() => setLoading(false), 650)
    return () => { window.clearInterval(clock); window.clearTimeout(ready) }
  }, [])
  useEffect(() => localStorage.setItem('sigap-followups', JSON.stringify(followups)), [followups])
  useEffect(() => localStorage.setItem('sigap-case-status', caseStatus), [caseStatus])
  useEffect(() => localStorage.setItem('sigap-notes', notes), [notes])
  useEffect(() => localStorage.setItem('sigap-checks', JSON.stringify(checks)), [checks])

  const filtered = useMemo(() => events.filter((e) => {
    const haystack = `${e.title} ${e.detail} ${e.user} ${e.host} ${e.ip} ${e.id}`.toLowerCase()
    return haystack.includes(query.toLowerCase()) && (severity === 'Semua' || e.severity === severity) && (source === 'Semua sumber' || e.source === source)
  }), [query, severity, source])

  const notify = (message: string) => { setToast(message); window.setTimeout(() => setToast(''), 2600) }
  const nav = [
    ['Ringkasan', LayoutDashboard], ['Kasus', ClipboardList], ['Timeline', Activity], ['Log Explorer', FileSearch],
    ['Graf Investigasi', GitBranch], ['URL Offline', ShieldCheck], ['ATT&CK', BookOpenCheck], ['Detail', FileText], ['Laporan', Flag],
  ] as const

  const selectEvent = (event: Event) => { setSelected(event); setPanel(true) }
  const requestStatus = (id: string, status: string) => setConfirm({ id, status })
  const changeStatus = () => {
    if (!confirm) return
    setFollowups((v) => ({ ...v, [confirm.id]: confirm.status }))
    notify(`Status ${confirm.id} diperbarui menjadi ${confirm.status}`)
    setConfirm(null)
  }
  const resetScenario = () => {
    setFollowups({ 'EVT-2402': 'Berjalan', 'EVT-2404': 'Baru', 'EVT-2405': 'Berjalan', 'EVT-2406': 'Baru' })
    setCaseStatus('Investigating')
    setNotes('Validasi persetujuan MFA dan akuisisi artefak ENG-SRV-02 sebelum remediasi.')
    setChecks({})
    setQuery(''); setSeverity('Semua'); setSource('Semua sumber'); setSelected(events[3])
    setResetOpen(false); notify('Skenario demo direset ke seed SIGAP-0618')
  }

  return (
    <div className="min-h-screen bg-[#090B0F] text-[#F3F5F7]">
      {toast && <div className="fixed right-5 top-5 z-50 flex items-center gap-2 rounded-lg border border-[#22C55E]/30 bg-[#132019] px-4 py-3 text-sm shadow-2xl"><CircleCheck size={16} className="text-[#22C55E]" />{toast}</div>}
      <aside className={`fixed inset-y-0 left-0 z-40 w-60 border-r border-[#272E3A] bg-[#0D1016] transition-transform lg:translate-x-0 ${mobileNav ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-16 items-center justify-between border-b border-[#272E3A] px-5">
          <div className="flex items-center gap-3"><div className="grid size-8 place-items-center rounded-lg bg-[#38BDF8] text-[#071018]"><ShieldAlert size={18} /></div><div><div className="text-sm font-extrabold tracking-[0.16em]">SIGAP</div><div className="text-[9px] text-[#6F7A89]">SIBER INCIDENT ANALYSIS</div></div></div>
          <button className="lg:hidden" onClick={() => setMobileNav(false)} aria-label="Tutup navigasi"><X size={18} /></button>
        </div>
        <div className="px-3 py-4">
          <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-[#657080]">Ruang kerja</div>
          <nav className="space-y-0.5">{nav.map(([label, Icon]) => <button key={label} onClick={() => { setActive(label); setMobileNav(false) }} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition ${active === label ? 'bg-[#191F2A] text-white shadow-[inset_2px_0_0_#38BDF8]' : 'text-[#9BA5B4] hover:bg-[#131720] hover:text-white'}`}><Icon size={16} className={active === label ? 'text-[#38BDF8]' : ''} />{label}{label === 'Timeline' && <span className="ml-auto rounded bg-[#EF4444]/15 px-1.5 py-0.5 font-mono text-[10px] text-[#FCA5A5]">4</span>}</button>)}</nav>
        </div>
        <div className="absolute bottom-0 w-full border-t border-[#272E3A] p-4">
          <div className="mb-2 rounded-lg border border-[#272E3A] bg-[#131720] p-3">
            <div className="mb-1 flex items-center justify-between text-xs"><span className="font-medium">Mode data</span><Badge className="border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]">SIMULASI</Badge></div>
            <p className="text-[11px] leading-4 text-[#737E8E]">Data sintetis lokal. Tidak terhubung ke sumber produksi.</p>
            <div className="mt-2 flex items-center justify-between font-mono text-[9px] text-[#596474]"><span>SEED SIGAP-0618</span><button title="Reset skenario" onClick={()=>setResetOpen(true)} className="text-[#9BA5B4] hover:text-white"><RefreshCcw size={12}/></button></div>
          </div>
          <div className="space-y-2 text-xs text-[#9BA5B4]"><div className="flex items-center gap-2"><span className="size-2 rounded-full bg-[#F59E0B]" />Backend belum terhubung</div><div className="flex items-center gap-2"><span className="size-2 rounded-full bg-[#22C55E]" />Dataset lokal tersedia</div></div>
        </div>
      </aside>

      <div className="lg:pl-60">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#272E3A] bg-[#090B0F]/90 px-4 backdrop-blur md:px-6">
          <div className="flex items-center gap-3"><button onClick={() => setMobileNav(true)} className="lg:hidden"><Menu size={20} /></button><div><div className="flex items-center gap-2 text-xs text-[#7E8998]">Kasus demo <ChevronRight size={12} /><select aria-label="Pilih kasus demo" className="bg-transparent font-mono text-[#CBD1D8] outline-none"><option>INC-2025-0618</option></select></div><div className="mt-0.5 text-sm font-semibold">Indikasi kompromi jaringan manufaktur</div></div></div>
          <div className="flex items-center gap-2 md:gap-4"><div className="hidden items-center gap-2 border-r border-[#272E3A] pr-4 font-mono text-[11px] text-[#7E8998] md:flex"><Clock3 size={14} />{now.toLocaleTimeString('id-ID', { hour12: false })} WIB</div><div title="Backend belum terhubung" className="hidden items-center gap-2 text-[10px] text-[#8D97A6] xl:flex"><span className="size-1.5 rounded-full bg-[#F59E0B]" />LOCAL DATA</div><Badge className="hidden border-[#EF4444]/25 bg-[#EF4444]/10 text-[#FCA5A5] sm:inline-flex"><span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-[#EF4444]" />{caseStatus.toUpperCase()}</Badge><button title="2 notifikasi investigasi" onClick={() => notify('2 notifikasi: 4 temuan kritis dan 2 tindak lanjut baru')} className="relative rounded-lg border border-[#272E3A] p-2 text-[#9BA5B4] transition hover:border-[#38BDF8]/40 hover:text-white"><Bell size={17} /><span className="absolute right-1.5 top-1.5 size-1.5 rounded-full bg-[#EF4444]" /></button></div>
        </header>

        <main className="p-4 md:p-6">
          {loading ? <LoadingState /> : <>
            {active === 'Timeline' && <TimelineView filtered={filtered} query={query} setQuery={setQuery} severity={severity} setSeverity={setSeverity} source={source} setSource={setSource} selected={selected} selectEvent={selectEvent} panel={panel} setPanel={setPanel} setActive={setActive} />}
            {active === 'Kasus' && <CaseView status={caseStatus} setStatus={setCaseStatus} notes={notes} setNotes={setNotes} followups={followups} notify={notify} />}
            {active === 'Log Explorer' && <LogExplorer selectEvent={(e)=>{setSelected(e);setActive('Detail')}} />}
            {active === 'Graf Investigasi' && <GraphView selected={selected} selectEvent={selectEvent} openDetail={() => setActive('Detail')} />}
            {active === 'URL Offline' && <UrlAnalyzer />}
            {active === 'ATT&CK' && <AttackView selectEvent={(e)=>{setSelected(e);setActive('Detail')}} />}
            {active === 'Detail' && <DetailView event={selected} followup={followups[selected.id] || 'Baru'} changeStatus={requestStatus} selectRelated={(id) => { const found = events.find(e => e.id === id); if (found) setSelected(found) }} notify={notify} checks={checks} setChecks={setChecks} openLogs={()=>setActive('Log Explorer')} />}
            {active === 'Laporan' && <ReportView followups={followups} changeStatus={requestStatus} notify={notify} caseStatus={caseStatus} notes={notes} />}
            {active === 'Ringkasan' && <SummaryView setActive={setActive} />}
          </>}
        </main>
      </div>
      {confirm && <ConfirmDialog id={confirm.id} status={confirm.status} cancel={() => setConfirm(null)} confirm={changeStatus} />}
      {resetOpen && <ResetDialog cancel={()=>setResetOpen(false)} confirm={resetScenario}/>}
    </div>
  )
}

function PageTitle({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) {
  return <div><div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em] text-[#38BDF8]">{eyebrow}</div><h1 className="text-xl font-semibold tracking-tight md:text-2xl">{title}</h1><p className="mt-1 max-w-2xl text-sm text-[#7E8998]">{text}</p></div>
}

function LoadingState() {
  return <div className="mx-auto max-w-[1600px] animate-pulse"><div className="mb-6 h-7 w-64 rounded bg-[#191F2A]" /><div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{[1,2,3,4].map(i => <div key={i} className="h-24 rounded-xl border border-[#272E3A] bg-[#131720]" />)}</div><div className="mt-4 grid gap-4 xl:grid-cols-[1fr_380px]"><div className="h-[480px] rounded-xl border border-[#272E3A] bg-[#131720]" /><div className="h-[480px] rounded-xl border border-[#272E3A] bg-[#131720]" /></div></div>
}

function ConfirmDialog({ id, status, cancel, confirm }: { id:string; status:string; cancel:()=>void; confirm:()=>void }) {
  return <div className="fixed inset-0 z-[70] grid place-items-center bg-[#05070A]/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true"><div className="w-full max-w-md rounded-2xl border border-[#374151] bg-[#131720] p-5 shadow-2xl"><div className="mb-4 flex size-10 items-center justify-center rounded-xl border border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]"><Flag size={18} /></div><h2 className="text-base font-semibold">Perbarui status tindak lanjut?</h2><p className="mt-2 text-sm leading-6 text-[#8D97A6]">Status <span className="font-mono text-[#D1D6DD]">{id}</span> akan diubah menjadi <b className="text-white">{status}</b>. Perubahan juga tampil pada laporan.</p><div className="mt-5 flex justify-end gap-2"><button onClick={cancel} className="rounded-lg border border-[#272E3A] px-4 py-2 text-xs text-[#AEB6C1] hover:bg-[#191F2A]">Batal</button><button onClick={confirm} className="rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]">Konfirmasi</button></div></div></div>
}

function ResetDialog({ cancel, confirm }: { cancel:()=>void; confirm:()=>void }) {
  return <div className="fixed inset-0 z-[70] grid place-items-center bg-[#05070A]/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true"><div className="w-full max-w-md rounded-2xl border border-[#EF4444]/30 bg-[#131720] p-5 shadow-2xl"><div className="mb-4 grid size-10 place-items-center rounded-xl bg-[#EF4444]/10 text-[#FCA5A5]"><TriangleAlert size={19}/></div><h2 className="font-semibold">Reset skenario demo?</h2><p className="mt-2 text-sm leading-6 text-[#8D97A6]">Status kasus, catatan, filter, dan tindak lanjut lokal akan dikembalikan ke seed deterministik <span className="font-mono text-white">SIGAP-0618</span>.</p><div className="mt-5 flex justify-end gap-2"><button onClick={cancel} className="rounded-lg border border-[#272E3A] px-4 py-2 text-xs">Batal</button><button onClick={confirm} className="rounded-lg bg-[#EF4444] px-4 py-2 text-xs font-bold text-white">Reset data lokal</button></div></div></div>
}

function SourceMark({ source, size = 15 }: { source: Source; size?: number }) {
  const Icon = source === 'Email Gateway' ? Mail : source === 'Endpoint' ? Monitor : source === 'Jaringan' ? Router : Cpu
  return <Icon size={size} />
}

function TimelineView(props: { filtered: Event[]; query: string; setQuery: (v: string) => void; severity: string; setSeverity: (v: string) => void; source: string; setSource: (v: string) => void; selected: Event; selectEvent: (e: Event) => void; panel: boolean; setPanel: (v: boolean) => void; setActive: (v: 'Detail') => void }) {
  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Investigasi / Kronologi" title="Timeline Peristiwa" text="Rangkaian aktivitas yang dikorelasikan dari empat sumber telemetri berdasarkan bukti bersama." /><div className="flex items-center gap-2"><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]"><Zap size={11} className="mr-1" />6 EVENT TERKORELASI</Badge></div></div>
    <div className="mb-5 grid grid-cols-2 gap-3 xl:grid-cols-4">
      {[['Total event', '6', '4 sumber'], ['Temuan kritis', '4', 'Butuh tindakan'], ['Rentang waktu', '01:01:56', '08:42 — 09:44'], ['Confidence kasus', '94%', 'Tinggi']].map(([a,b,c], i) => <div key={a} className="rounded-xl border border-[#272E3A] bg-[#131720] p-4"><div className="flex items-center justify-between text-xs text-[#7E8998]">{a}<span className={`size-2 rounded-full ${i === 1 ? 'bg-[#EF4444]' : i === 3 ? 'bg-[#22C55E]' : 'bg-[#38BDF8]'}`} /></div><div className="mt-2 font-mono text-xl font-semibold">{b}</div><div className="mt-1 text-[11px] text-[#657080]">{c}</div></div>)}
    </div>
    <div className="mb-3 flex flex-col gap-2 rounded-xl border border-[#272E3A] bg-[#131720] p-3 md:flex-row">
      <div className="relative min-w-0 flex-1"><Search size={15} className="absolute left-3 top-2.5 text-[#687384]" /><input value={props.query} onChange={e => props.setQuery(e.target.value)} placeholder="Cari event, pengguna, host, IP…" className="h-9 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] pl-9 pr-3 text-xs outline-none placeholder:text-[#56606E] focus:border-[#38BDF8]/60" /></div>
      <Select value={props.severity} setValue={props.setSeverity} options={['Semua', 'Kritis', 'Tinggi', 'Sedang', 'Rendah']} />
      <Select value={props.source} setValue={props.setSource} options={['Semua sumber', 'Email Gateway', 'Endpoint', 'Jaringan', 'OT Simulator']} />
      <button onClick={() => { props.setQuery(''); props.setSeverity('Semua'); props.setSource('Semua sumber') }} className="flex h-9 items-center justify-center gap-2 rounded-lg border border-[#272E3A] px-3 text-xs text-[#9BA5B4] hover:text-white"><Filter size={14} />Reset</button>
    </div>
    <div className={`grid gap-4 ${props.panel ? 'xl:grid-cols-[minmax(0,1fr)_380px]' : ''}`}>
      <section className="overflow-hidden rounded-xl border border-[#272E3A] bg-[#0D1016]">
        <div className="hidden grid-cols-[112px_40px_minmax(260px,1fr)_120px_100px] gap-3 border-b border-[#272E3A] px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-[#657080] md:grid"><span>Waktu</span><span></span><span>Aktivitas</span><span>Entitas</span><span>Severity</span></div>
        {props.filtered.length === 0 ? <div className="grid min-h-64 place-items-center text-center"><div><Search className="mx-auto mb-3 text-[#536071]" /><div className="text-sm font-medium">Tidak ada event ditemukan</div><div className="mt-1 text-xs text-[#687384]">Ubah kata kunci atau filter pencarian.</div></div></div> :
        props.filtered.map((event, index) => <div key={event.id} className={`border-b border-[#1D232D] last:border-0 ${props.selected.related.includes(event.id) ? 'bg-[#38BDF8]/[0.035]' : ''}`}><button onClick={() => props.selectEvent(event)} className={`grid w-full grid-cols-[74px_32px_minmax(0,1fr)] gap-3 px-4 py-4 text-left transition hover:bg-[#131720] md:grid-cols-[112px_40px_minmax(260px,1fr)_120px_100px] ${props.selected.id === event.id ? 'bg-[#131720] shadow-[inset_2px_0_0_#38BDF8]' : ''}`}>
          <div><div className="font-mono text-xs text-[#D8DCE2]">{event.time}</div><div className="mt-1 text-[10px] text-[#657080]">{event.date}</div></div>
          <div className="relative"><span title={event.source} className={`grid size-7 place-items-center rounded-md border ${event.source === 'OT Simulator' ? 'border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FBBF24]' : 'border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]'}`}><SourceMark source={event.source} size={13} /></span>{index < props.filtered.length - 1 && <span className="absolute left-3.5 top-8 hidden h-12 w-px bg-[#272E3A] md:block" />}</div>
          <div className="min-w-0"><div className="mb-1 flex items-center gap-2"><span className="truncate text-sm font-medium">{event.title}</span>{event.source === 'OT Simulator' && <Badge className="border-[#F59E0B]/20 text-[#FBBF24]">SIM</Badge>}{props.selected.related.includes(event.id) && <Badge className="border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]"><Link2 size={9} className="mr-1" />TERKAIT</Badge>}</div><p className="truncate text-xs text-[#7E8998]">{event.detail}</p><div className="mt-2 flex gap-3 font-mono text-[10px] text-[#667180]"><span>{event.id}</span><span className="hidden sm:inline">{event.ip}</span></div></div>
          <div className="hidden min-w-0 md:block"><div className="truncate font-mono text-[11px]">{event.host}</div><div className="mt-1 truncate text-[10px] text-[#7E8998]">{event.user}</div></div>
          <div className="hidden md:block"><Badge className={severityStyle[event.severity]}>{event.severity}</Badge></div>
        </button>{props.selected.id === event.id && <div className="grid gap-3 border-t border-[#272E3A]/70 bg-[#0B0E13] px-4 py-3 md:ml-[152px] md:grid-cols-3"><Info title="Aturan terpicu" text={event.rule} /><Info title="Bukti utama" text={event.evidence[0]} /><div><Label>Korelasi</Label><div className="flex flex-wrap gap-1.5">{event.related.map(id => <span key={id} className="rounded border border-[#38BDF8]/20 bg-[#38BDF8]/5 px-2 py-1 font-mono text-[10px] text-[#7DD3FC]">{id}</span>)}</div></div></div>}</div>)}
      </section>
      {props.panel && <EvidencePanel event={props.selected} close={() => props.setPanel(false)} openDetail={() => props.setActive('Detail')} selectEvent={props.selectEvent} />}
      {!props.panel && <button onClick={() => props.setPanel(true)} className="fixed bottom-5 right-5 flex items-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-semibold text-[#071018]"><PanelLeftClose size={15} />Buka detail</button>}
    </div>
  </div>
}

function Select({ value, setValue, options }: { value: string; setValue: (v: string) => void; options: string[] }) {
  return <div className="relative"><select value={value} onChange={e => setValue(e.target.value)} className="h-9 min-w-36 appearance-none rounded-lg border border-[#272E3A] bg-[#0D1016] pl-3 pr-8 text-xs text-[#CBD1D8] outline-none focus:border-[#38BDF8]/60">{options.map(o => <option key={o}>{o}</option>)}</select><ChevronDown size={13} className="pointer-events-none absolute right-2.5 top-3 text-[#687384]" /></div>
}

function EvidencePanel({ event, close, openDetail, selectEvent }: { event: Event; close: () => void; openDetail: () => void; selectEvent: (e: Event) => void }) {
  return <aside className="rounded-xl border border-[#272E3A] bg-[#131720] xl:sticky xl:top-20 xl:h-[calc(100vh-104px)] xl:overflow-y-auto">
    <div className="sticky top-0 flex items-start justify-between border-b border-[#272E3A] bg-[#131720] p-4"><div><div className="mb-2 flex items-center gap-2"><Badge className={severityStyle[event.severity]}>{event.severity}</Badge><span className="font-mono text-[10px] text-[#7E8998]">{event.id}</span></div><h2 className="text-sm font-semibold">{event.title}</h2></div><button onClick={close} className="text-[#657080] hover:text-white"><X size={17} /></button></div>
    <div className="space-y-5 p-4">
      <div><Label>Temuan</Label><p className="text-sm leading-5">{event.finding}</p></div>
      <div className="grid grid-cols-2 gap-2">{[['Pengguna', event.user], ['Hostname', event.host], ['IP', event.ip], ['MITRE', event.mitre || '—']].map(([a,b]) => <div key={a} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-2.5"><div className="text-[9px] uppercase tracking-wider text-[#657080]">{a}</div><div className="mt-1 truncate font-mono text-[11px]">{b}</div></div>)}</div>
      <div><Label>Mengapa ditandai?</Label><div className="rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3"><div className="mb-1 text-[10px] font-semibold text-[#FBBF24]">ATURAN KORELASI</div><p className="text-xs leading-5 text-[#CBD1D8]">{event.rule}</p></div></div>
      <div><Label>Bukti pendukung</Label><div className="space-y-2">{event.evidence.map((x, i) => <div key={x} className="flex gap-2 text-xs leading-5 text-[#AEB6C1]"><CircleCheck size={14} className="mt-0.5 shrink-0 text-[#22C55E]" /><span><b className="mr-1 font-mono text-[10px] text-[#657080]">B{i+1}</b>{x}</span></div>)}</div></div>
      <div><Label>Yang belum diketahui</Label><p className="text-xs leading-5 text-[#8D97A6]">{event.unknown}</p></div>
      <div><Label>Event terkait</Label><div className="flex flex-wrap gap-2">{event.related.map(id => <button key={id} onClick={() => { const found = events.find(e => e.id === id); if (found) selectEvent(found) }} className="flex items-center gap-1 rounded-md border border-[#272E3A] bg-[#191F2A] px-2 py-1 font-mono text-[10px] text-[#7DD3FC] hover:border-[#38BDF8]/50"><Link2 size={10} />{id}</button>)}</div></div>
      <button onClick={openDetail} className="w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]">Buka analisis lengkap</button>
    </div>
  </aside>
}

function Label({ children }: { children: React.ReactNode }) { return <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-[#657080]">{children}</div> }

function DetailView({ event, followup, changeStatus, selectRelated, notify, checks, setChecks, openLogs }: { event: Event; followup: string; changeStatus: (id: string, status: string) => void; selectRelated: (id: string) => void; notify: (message:string)=>void; checks:Record<string,boolean>; setChecks:React.Dispatch<React.SetStateAction<Record<string,boolean>>>; openLogs:()=>void }) {
  const recommendations = [
    ['P1', 'Isolasi host terdampak', `Putuskan ${event.host} dari jaringan untuk membatasi penyebaran.`, event.evidence[0]],
    ['P1', 'Rotasi kredensial akun', `Reset kredensial ${event.user} dan cabut seluruh sesi aktif.`, 'Korelasi akun pada EVT-2402–EVT-2404'],
    ['P2', 'Akuisisi bukti forensik', 'Ambil image memori dan disk sebelum remediasi lanjutan.', event.evidence[1]],
  ]
  return <div className="mx-auto max-w-6xl">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow={`Temuan / ${event.id}`} title={event.finding} text={event.detail} /><div className="flex flex-wrap gap-2"><Badge className={severityStyle[event.severity]}>{event.severity}</Badge><Badge className="border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]">CONFIDENCE 94%</Badge><Badge className="border-[#38BDF8]/25 bg-[#38BDF8]/10 text-[#7DD3FC]">{followup.toUpperCase()}</Badge></div></div>
    <div className="grid gap-4 lg:grid-cols-[1.4fr_.8fr]">
      <div className="space-y-4">
        <Card title="Mengapa Ditandai?" icon={<ShieldAlert size={16} className="text-[#F59E0B]" />}>
          <div className="grid gap-4 md:grid-cols-2"><Info title="Aturan dan kondisi" text={event.rule} /><Info title="Alasan pemeriksaan" text="Kombinasi indikator melampaui baseline perilaku dan memiliki hubungan entitas langsung dengan rangkaian insiden." /></div>
          <div className="mt-4"><Label>Bukti yang memenuhi kondisi</Label><div className="space-y-2">{event.evidence.map((e,i) => <div key={e} className="flex items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-xs"><span className="font-mono text-[#38BDF8]">B{i+1}</span><span className="flex-1 text-[#C3CAD3]">{e}</span><CircleCheck size={15} className="text-[#22C55E]" /></div>)}</div></div>
          <div className="mt-4 rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3"><div className="mb-1 text-[10px] font-semibold text-[#FBBF24]">BELUM DIKETAHUI</div><p className="text-xs text-[#AEB6C1]">{event.unknown}</p></div>
        </Card>
        <Card title="Rekomendasi Terlacak" icon={<CircleCheck size={16} className="text-[#22C55E]" />}>
          <div className="mb-3 flex gap-2 rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3 text-[11px] leading-5 text-[#D4A64B]"><TriangleAlert size={15} className="mt-0.5 shrink-0"/>Tindakan pada sistem produksi wajib diverifikasi, mendapat otorisasi, dan mengikuti change control.</div>
          <div className="space-y-3">{recommendations.map(([p,t,d,e], i) => { const key=`${event.id}-${i}`; return <div key={t} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-4"><div className="flex items-start gap-3"><button title="Tandai tindak lanjut" onClick={()=>setChecks(v=>({...v,[key]:!v[key]}))} className={`mt-0.5 ${checks[key]?'text-[#22C55E]':'text-[#56606E]'}`}><CheckSquare size={17}/></button><Badge className={p === 'P1' ? severityStyle.Kritis : severityStyle.Sedang}>{p}</Badge><div className="flex-1"><div className={`text-sm font-semibold ${checks[key]?'text-[#7E8998] line-through':''}`}>{t}</div><p className="mt-1 text-xs leading-5 text-[#8D97A6]">{d}</p><div className="mt-2 flex items-center gap-1 text-[10px] text-[#657080]"><Link2 size={11} />Bukti: {e}</div></div><select value={i === 0 ? followup : checks[key]?'Selesai':'Baru'} onChange={x => changeStatus(event.id, x.target.value)} className="rounded-md border border-[#272E3A] bg-[#191F2A] px-2 py-1 text-[10px]"><option>Baru</option><option>Berjalan</option><option>Selesai</option></select></div></div>})}</div>
        </Card>
      </div>
      <div className="space-y-4">
        <Card title="Entitas & Teknik" icon={<Network size={16} className="text-[#38BDF8]" />}>
          <div className="space-y-2">{[['Event ID', event.id], ['Pengguna', event.user], ['Hostname', event.host], ['Alamat IP', event.ip], ['Sumber', event.source], ['MITRE ATT&CK', event.mitre || 'Tidak tersedia']].map(([a,b]) => <div key={a} className="flex items-center justify-between border-b border-[#272E3A] py-2 text-xs last:border-0"><span className="text-[#707B8A]">{a}</span><span className="font-mono text-[#D1D6DD]">{b}</span></div>)}</div>
        </Card>
        <button onClick={() => {notify(`Membuka log sumber ${event.id}`);openLogs()}} className="flex w-full items-center justify-center gap-2 rounded-xl border border-[#38BDF8]/30 bg-[#38BDF8]/10 py-3 text-xs font-semibold text-[#7DD3FC] transition hover:bg-[#38BDF8]/15"><ExternalLink size={14} />Buka sumber log</button>
        <Card title="Event Terkait" icon={<Link2 size={16} className="text-[#38BDF8]" />}>
          <div className="space-y-2">{event.related.map(id => { const e = events.find(x => x.id === id)!; return <button onClick={() => selectRelated(id)} key={id} className="flex w-full items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-left hover:border-[#38BDF8]/40"><span className="grid size-8 place-items-center rounded bg-[#191F2A] font-mono text-[9px] text-[#7DD3FC]">{sourceIcon[e.source]}</span><span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium">{e.title}</span><span className="mt-1 block font-mono text-[10px] text-[#657080]">{id} · {e.time}</span></span><ChevronRight size={14} className="text-[#657080]" /></button>})}</div>
        </Card>
      </div>
    </div>
  </div>
}

function Card({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) { return <section className="rounded-xl border border-[#272E3A] bg-[#131720]"><div className="flex items-center gap-2 border-b border-[#272E3A] px-4 py-3 text-sm font-semibold">{icon}{title}</div><div className="p-4">{children}</div></section> }
function Info({ title, text }: { title: string; text: string }) { return <div><Label>{title}</Label><p className="text-xs leading-5 text-[#B4BCC7]">{text}</p></div> }

function CaseView({ status, setStatus, notes, setNotes, followups, notify }: { status:string; setStatus:(s:string)=>void; notes:string; setNotes:(s:string)=>void; followups:Record<string,string>; notify:(s:string)=>void }) {
  const findings=events.filter(e=>e.severity==='Kritis')
  return <div className="mx-auto max-w-6xl"><div className="mb-6 flex items-end justify-between gap-4"><PageTitle eyebrow="Case Management" title="INC-2025-0618" text="Indikasi kompromi jaringan manufaktur"/><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">SIMULASI · SEED SIGAP-0618</Badge></div>
    <div className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]"><div className="space-y-4"><Card title="Detail Kasus" icon={<ClipboardList size={16} className="text-[#38BDF8]"/>}><div className="grid gap-4 sm:grid-cols-2">{[['ID kasus','INC-2025-0618'],['Waktu mulai','18 Jun 2025 · 08:42 WIB'],['Analis','Nadia Pratama'],['Sumber log','Email, Endpoint, Jaringan, OT Simulasi']].map(([a,b])=><div key={a}><Label>{a}</Label><div className="font-mono text-xs text-[#D1D6DD]">{b}</div></div>)}</div><div className="mt-5"><Label>Ringkasan</Label><p className="text-sm leading-6 text-[#AEB6C1]">Enam event sintetis mengindikasikan rangkaian dari phishing hingga akses zona engineering, perubahan PLC simulasi, dan transfer data keluar. Hubungan dinilai dari entitas serta artefak yang cocok; sebab-akibat belum dianggap pasti.</p></div></Card>
      <Card title="Catatan Analis" icon={<StickyNote size={16} className="text-[#F59E0B]"/>}><textarea value={notes} maxLength={600} onChange={e=>setNotes(e.target.value)} className="min-h-32 w-full resize-y rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-sm leading-6 outline-none focus:border-[#38BDF8]/50" placeholder="Tambahkan catatan investigasi…"/><div className="mt-2 flex items-center justify-between text-[10px] text-[#657080]"><span>Tersimpan otomatis di browser lokal</span><span>{notes.length}/600</span></div></Card>
      <Card title="Batas Kesimpulan" icon={<ShieldAlert size={16} className="text-[#F59E0B]"/>}><div className="grid gap-3 md:grid-cols-3">{[['FAKTA','Log mencatat event, host, akun, IP, dan artefak yang tercantum.','#22C55E'],['INDIKASI','Kecocokan entitas dan aturan meningkatkan kemungkinan satu rangkaian.','#F59E0B'],['HIPOTESIS','Akun mungkin disalahgunakan setelah eksekusi payload; perlu forensik.','#38BDF8']].map(([a,b,c])=><div key={a} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><div className="mb-2 text-[10px] font-bold" style={{color:c}}>{a}</div><p className="text-xs leading-5 text-[#8D97A6]">{b}</p></div>)}</div></Card></div>
      <div className="space-y-4"><Card title="Status Kasus" icon={<Activity size={16} className="text-[#22C55E]"/>}><Label>Tahap investigasi</Label><div className="grid grid-cols-3 gap-2">{['Open','Investigating','Resolved'].map(s=><button key={s} onClick={()=>{setStatus(s);notify(`Status kasus disimpan: ${s}`)}} className={`rounded-lg border px-2 py-2 text-[10px] font-semibold ${status===s?'border-[#38BDF8] bg-[#38BDF8]/10 text-[#7DD3FC]':'border-[#272E3A] text-[#7E8998]'}`}>{s}</button>)}</div><div className="mt-4 rounded-lg bg-[#0D1016] p-3 text-[10px] text-[#657080]">Penyimpanan: <b className="text-[#86EFAC]">localStorage aktif</b><br/>Sinkronisasi server: tidak tersedia</div></Card>
      <Card title="Perlu Ditinjau" icon={<FileSearch size={16} className="text-[#EF4444]"/>}><div className="space-y-2">{findings.map(e=><div key={e.id} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><div className="flex justify-between"><span className="font-mono text-[10px] text-[#7DD3FC]">{e.id}</span><Badge className={severityStyle[e.severity]}>{e.severity}</Badge></div><div className="mt-2 text-xs font-medium">{e.finding}</div><div className="mt-1 text-[10px] text-[#657080]">Tindak lanjut: {followups[e.id]||'Baru'}</div></div>)}</div></Card></div></div>
  </div>
}

const rawLogs = events.map((e,i)=>({
  event:e, processed:i!==4, raw:{ timestamp:`2025-06-18T${e.time}+07:00`, source:e.source, event_id:e.id, hostname:e.host, user:e.user, src_ip:e.ip, message:e.detail, simulation:e.source==='OT Simulator' },
  normalized:{ '@timestamp':`2025-06-18T${e.time}+07:00`, 'event.id':e.id, 'event.severity':e.severity, 'host.name':e.host, 'user.name':e.user, 'source.ip':e.ip, 'sigap.rule':e.rule }
}))

function LogExplorer({ selectEvent }: { selectEvent:(e:Event)=>void }) {
  const [q,setQ]=useState(''); const [src,setSrc]=useState('Semua sumber'); const [sort,setSort]=useState<'asc'|'desc'>('asc'); const [chosen,setChosen]=useState(rawLogs[0]); const [view,setView]=useState<'raw'|'normalized'>('raw')
  const rows=rawLogs.filter(r=>(src==='Semua sumber'||r.event.source===src)&&JSON.stringify(r).toLowerCase().includes(q.toLowerCase())).sort((a,b)=>sort==='asc'?a.event.time.localeCompare(b.event.time):b.event.time.localeCompare(a.event.time))
  return <div className="mx-auto max-w-[1600px]"><div className="mb-6 flex items-end justify-between"><PageTitle eyebrow="Forensics / Telemetry" title="Log Explorer" text="Data mentah lokal dan hasil normalisasi dari sumber simulasi. Satu log OT ditandai gagal normalisasi untuk demonstrasi penanganan error."/><Badge className="border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]">{rawLogs.length} RECORD LOKAL</Badge></div>
    <div className="mb-3 flex flex-col gap-2 rounded-xl border border-[#272E3A] bg-[#131720] p-3 md:flex-row"><div className="relative flex-1"><Search size={14} className="absolute left-3 top-3 text-[#657080]"/><input value={q} onChange={e=>setQ(e.target.value)} className="h-9 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] pl-9 pr-3 text-xs outline-none" placeholder="Cari event ID, host, user, IP, isi log…"/></div><Select value={src} setValue={setSrc} options={['Semua sumber','Email Gateway','Endpoint','Jaringan','OT Simulator']}/><button onClick={()=>setSort(v=>v==='asc'?'desc':'asc')} className="rounded-lg border border-[#272E3A] px-3 text-xs text-[#AEB6C1]">Waktu {sort==='asc'?'↑':'↓'}</button></div>
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_440px]"><section className="overflow-x-auto rounded-xl border border-[#272E3A] bg-[#0D1016]">{rows.length===0?<div className="grid h-64 place-items-center text-sm text-[#657080]">Tidak ada log yang cocok dengan filter.</div>:<table className="w-full min-w-[880px] text-left text-[11px]"><thead className="bg-[#131720] text-[9px] uppercase tracking-wider text-[#657080]"><tr>{['Timestamp','Source','Event ID','Hostname','User','IP','Proses'].map(x=><th key={x} className="px-3 py-3">{x}</th>)}</tr></thead><tbody>{rows.map(r=><tr key={r.event.id} onClick={()=>setChosen(r)} className={`cursor-pointer border-t border-[#1D232D] hover:bg-[#131720] ${chosen.event.id===r.event.id?'bg-[#38BDF8]/5':''}`}><td className="px-3 py-3 font-mono">{r.event.time}</td><td className="px-3"><span className="flex items-center gap-2"><SourceMark source={r.event.source}/>{r.event.source}</span></td><td className="px-3 font-mono text-[#7DD3FC]">{r.event.id}</td><td className="px-3 font-mono">{r.event.host}</td><td className="px-3">{r.event.user}</td><td className="px-3 font-mono">{r.event.ip}</td><td className="px-3">{r.processed?<Badge className="border-[#22C55E]/20 text-[#86EFAC]">NORMAL</Badge>:<Badge className="border-[#EF4444]/20 text-[#FCA5A5]">GAGAL</Badge>}</td></tr>)}</tbody></table>}</section>
      <aside className="rounded-xl border border-[#272E3A] bg-[#131720]"><div className="flex items-center justify-between border-b border-[#272E3A] p-3"><div className="font-mono text-xs text-[#7DD3FC]">{chosen.event.id}</div><div className="flex rounded-lg bg-[#0D1016] p-1">{(['raw','normalized'] as const).map(v=><button key={v} onClick={()=>setView(v)} className={`rounded px-2 py-1 text-[9px] uppercase ${view===v?'bg-[#272E3A] text-white':'text-[#657080]'}`}>{v==='raw'?'Data asli':'Normalisasi'}</button>)}</div></div>{!chosen.processed&&view==='normalized'?<div className="m-4 rounded-lg border border-[#EF4444]/25 bg-[#EF4444]/5 p-4"><div className="flex items-center gap-2 text-xs font-semibold text-[#FCA5A5]"><TriangleAlert size={15}/>Normalisasi parsial</div><p className="mt-2 text-xs leading-5 text-[#8D97A6]">Field protokol OT tidak dikenali oleh parser demo. Data asli tetap dipertahankan dan dapat diperiksa.</p></div>:<pre className="max-h-[520px] overflow-auto p-4 font-mono text-[11px] leading-6 text-[#AEB6C1]">{JSON.stringify(view==='raw'?chosen.raw:chosen.normalized,null,2)}</pre>}<div className="border-t border-[#272E3A] p-3"><button onClick={()=>selectEvent(chosen.event)} className="w-full rounded-lg bg-[#38BDF8] py-2 text-xs font-bold text-[#071018]">Buka temuan terkait</button></div></aside>
    </div>
  </div>
}

function UrlAnalyzer() {
  const [input,setInput]=useState('https://micros0ft-login-support.top/auth/verify?session=827361928371')
  const [result,setResult]=useState<null|{host:string;score:number;items:string[]}>(null); const [error,setError]=useState('')
  const analyze=()=>{try{const u=new URL(input); if(!['http:','https:'].includes(u.protocol)) throw new Error(); const host=u.hostname.toLowerCase(); const items:string[]=[]; if(/0|1/.test(host))items.push('Karakter angka menyerupai huruf pada domain'); if(['top','xyz','click'].includes(host.split('.').pop()||''))items.push(`TLD .${host.split('.').pop()} termasuk daftar perhatian lokal`); if(host.length>24)items.push('Nama domain relatif panjang'); const entropy=new Set(host.replace(/\./g,'')).size/Math.max(1,host.replace(/\./g,'').length); if(entropy>.45)items.push('Keragaman karakter domain relatif tinggi'); if(u.search.length>20)items.push('Query string panjang'); setResult({host,score:Math.min(90,35+items.length*11)});setError('')}catch{setError('Masukkan URL HTTP/HTTPS yang valid. URL tidak akan diakses.');setResult(null)}}
  return <div className="mx-auto max-w-5xl"><div className="mb-6"><PageTitle eyebrow="Local Utility" title="Analisis URL Offline" text="Pemeriksaan heuristik lokal atas struktur URL. Tidak ada DNS lookup, HTTP request, atau layanan reputasi eksternal."/></div><div className="grid gap-4 lg:grid-cols-[1fr_.8fr]"><Card title="URL Inspector" icon={<Globe2 size={16} className="text-[#38BDF8]"/>}><Label>URL untuk diperiksa</Label><textarea value={input} onChange={e=>setInput(e.target.value)} className="min-h-28 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 font-mono text-xs outline-none focus:border-[#38BDF8]/50"/>{error&&<p className="mt-2 text-xs text-[#FCA5A5]">{error}</p>}<button onClick={analyze} className="mt-3 w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018]">Analisis secara lokal</button><div className="mt-3 flex items-center gap-2 text-[10px] text-[#657080]"><ShieldCheck size={13}/>Tidak mengakses URL atau internet</div></Card><Card title="Hasil Indikatif" icon={<FileSearch size={16} className="text-[#F59E0B]"/>}>{result?<><div className="flex items-center justify-between rounded-lg bg-[#0D1016] p-3"><div><div className="font-mono text-xs">{result.host}</div><div className="mt-1 text-[10px] text-[#657080]">Keyakinan heuristik</div></div><div className="font-mono text-xl text-[#FBBF24]">{result.score}%</div></div><div className="mt-4 space-y-2">{result.items.map(x=><div key={x} className="flex gap-2 rounded-lg border border-[#272E3A] p-3 text-xs text-[#AEB6C1]"><TriangleAlert size={14} className="shrink-0 text-[#F59E0B]"/>{x}</div>)}</div><p className="mt-4 text-[11px] leading-5 text-[#D4A64B]">Hasil adalah indikasi berbasis struktur, bukan kepastian phishing. Verifikasi tambahan tetap diperlukan.</p></>:<div className="grid h-64 place-items-center text-center text-xs text-[#657080]"><div><Braces className="mx-auto mb-3"/>Jalankan analisis untuk melihat indikator.</div></div>}</Card></div></div>
}

const attackDescriptions:Record<string,string>={'T1566.001':'Spearphishing Attachment','T1059.001':'PowerShell','T1078':'Valid Accounts','T1021.002':'SMB/Windows Admin Shares','T0836':'Modify Parameter','T1041':'Exfiltration Over C2 Channel'}
function AttackView({ selectEvent }:{selectEvent:(e:Event)=>void}) {
 return <div className="mx-auto max-w-6xl"><div className="mb-6"><PageTitle eyebrow="Knowledge Mapping" title="MITRE ATT&CK & ATT&CK for ICS" text="Pemetaan hanya ditampilkan untuk teknik yang telah tersedia pada data event simulasi."/></div><div className="grid gap-4 md:grid-cols-2">{events.map(e=><button key={e.id} onClick={()=>selectEvent(e)} className="rounded-xl border border-[#272E3A] bg-[#131720] p-4 text-left hover:border-[#38BDF8]/40"><div className="flex items-center justify-between"><Badge className={e.source==='OT Simulator'?'border-[#F59E0B]/25 text-[#FBBF24]':'border-[#38BDF8]/25 text-[#7DD3FC]'}>{e.source==='OT Simulator'?'ATT&CK FOR ICS · SIMULASI':'ENTERPRISE ATT&CK'}</Badge><span className="font-mono text-xs text-[#7DD3FC]">{e.mitre}</span></div><h2 className="mt-3 text-sm font-semibold">{attackDescriptions[e.mitre||'']}</h2><p className="mt-2 text-xs leading-5 text-[#8D97A6]">{e.detail}</p><div className="mt-3 flex items-center gap-2 border-t border-[#272E3A] pt-3 text-[10px] text-[#657080]"><Link2 size={11}/>Bukti: {e.id} · {e.source}</div></button>)}</div></div>
}

const graphNodes = [
  { id:'user', label:'n.rahma', type:'User', x:12, y:48, icon:UserRound, events:['EVT-2401','EVT-2402','EVT-2403','EVT-2404'] },
  { id:'mail', label:'invoice_0618.docm', type:'Email', x:31, y:18, icon:Mail, events:['EVT-2401','EVT-2402'] },
  { id:'ws', label:'WS-FIN-014', type:'Endpoint', x:36, y:55, icon:Monitor, events:['EVT-2401','EVT-2402','EVT-2404'] },
  { id:'c2', label:'185.220.101.42', type:'IP eksternal', x:52, y:18, icon:Globe2, events:['EVT-2401','EVT-2402'] },
  { id:'vpn', label:'VPN-GW-01', type:'Gateway', x:53, y:80, icon:Router, events:['EVT-2403'] },
  { id:'eng', label:'ENG-SRV-02', type:'Server', x:65, y:48, icon:Database, events:['EVT-2404','EVT-2405','EVT-2406'] },
  { id:'plc', label:'PLC-SIM-07', type:'OT simulasi', x:86, y:24, icon:Cpu, events:['EVT-2405'] },
  { id:'exfil', label:'45.153.160.2', type:'IP eksternal', x:87, y:74, icon:Globe2, events:['EVT-2406'] },
]
const graphEdges = [
  ['user','mail','penerima'], ['mail','ws','dibuka pada'], ['mail','c2','IOC cocok'], ['user','vpn','login akun'],
  ['ws','eng','SMB ADMIN$'], ['vpn','eng','sesi sama'], ['eng','plc','sesi engineering'], ['eng','exfil','transfer 1,8 GB'],
]

function GraphView({ selected, selectEvent, openDetail }: { selected:Event; selectEvent:(e:Event)=>void; openDetail:()=>void }) {
  const [nodeId, setNodeId] = useState('eng')
  const node = graphNodes.find(n => n.id === nodeId)!
  const linkedEvents = node.events.map(id => events.find(e => e.id === id)!)
  const connected = new Set(graphEdges.filter(e => e[0] === nodeId || e[1] === nodeId).flatMap(e => [e[0], e[1]]))
  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Korelasi / Entitas" title="Investigation Graph" text="Hubungan identitas, aset, dan infrastruktur yang diturunkan dari bukti pada enam event simulasi." /><div className="flex gap-2"><Badge className="border-[#38BDF8]/25 bg-[#38BDF8]/10 text-[#7DD3FC]">8 NODE</Badge><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">8 RELASI BERBUKTI</Badge></div></div>
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
      <section className="overflow-hidden rounded-xl border border-[#272E3A] bg-[#0B0E13]">
        <div className="flex items-center justify-between border-b border-[#272E3A] px-4 py-3"><div className="flex items-center gap-2 text-xs font-semibold"><GitBranch size={15} className="text-[#38BDF8]" />Peta korelasi kasus</div><div className="flex gap-3 text-[10px] text-[#657080]"><span><i className="mr-1 inline-block size-1.5 rounded-full bg-[#38BDF8]" />Entitas</span><span><i className="mr-1 inline-block size-1.5 rounded-full bg-[#F59E0B]" />OT simulasi</span></div></div>
        <div className="relative min-h-[540px] overflow-hidden bg-[radial-gradient(circle_at_center,rgba(56,189,248,0.06),transparent_55%)]">
          <div className="absolute inset-0 opacity-20 [background-image:linear-gradient(#272E3A_1px,transparent_1px),linear-gradient(90deg,#272E3A_1px,transparent_1px)] [background-size:32px_32px]" />
          <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 size-full">
            {graphEdges.map(([from,to,label]) => { const a=graphNodes.find(n=>n.id===from)!; const b=graphNodes.find(n=>n.id===to)!; const hot=from===nodeId||to===nodeId; return <g key={`${from}-${to}`}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} vectorEffect="non-scaling-stroke" stroke={hot?'#38BDF8':'#354052'} strokeWidth={hot?1.8:1} strokeDasharray={hot?'0':'4 5'} /><text x={(a.x+b.x)/2} y={(a.y+b.y)/2-1.5} fill={hot?'#BAE6FD':'#64748B'} fontSize="2.3" textAnchor="middle">{label}</text></g> })}
          </svg>
          {graphNodes.map(n => { const Icon=n.icon; const active=n.id===nodeId; const dim=connected.size>0&&!connected.has(n.id); return <button key={n.id} title={`${n.type}: ${n.label}`} onClick={()=>setNodeId(n.id)} className={`absolute z-10 -translate-x-1/2 -translate-y-1/2 rounded-xl border p-2.5 text-left shadow-xl transition duration-200 hover:-translate-y-[55%] ${active?'border-[#38BDF8] bg-[#172331] ring-4 ring-[#38BDF8]/10':n.type==='OT simulasi'?'border-[#F59E0B]/40 bg-[#1B1812]':'border-[#374151] bg-[#131720]'} ${dim?'opacity-45':'opacity-100'}`} style={{left:`${n.x}%`,top:`${n.y}%`}}><div className="flex items-center gap-2"><span className={`grid size-7 place-items-center rounded-lg ${n.type==='OT simulasi'?'bg-[#F59E0B]/10 text-[#FBBF24]':'bg-[#38BDF8]/10 text-[#7DD3FC]'}`}><Icon size={14}/></span><span><span className="block whitespace-nowrap font-mono text-[10px] font-semibold">{n.label}</span><span className="block text-[9px] text-[#657080]">{n.type}</span></span></div></button>})}
        </div>
      </section>
      <aside className="space-y-4">
        <Card title="Entitas Terpilih" icon={<Box size={16} className="text-[#38BDF8]" />}>
          <div className="mb-4 flex items-center gap-3"><div className="grid size-11 place-items-center rounded-xl border border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]"><node.icon size={20}/></div><div><div className="font-mono text-sm font-semibold">{node.label}</div><div className="text-[10px] uppercase tracking-wider text-[#657080]">{node.type}</div></div></div>
          <div className="grid grid-cols-2 gap-2"><div className="rounded-lg bg-[#0D1016] p-3"><div className="text-[9px] text-[#657080]">EVENT TERKAIT</div><div className="mt-1 font-mono text-lg">{node.events.length}</div></div><div className="rounded-lg bg-[#0D1016] p-3"><div className="text-[9px] text-[#657080]">RELASI</div><div className="mt-1 font-mono text-lg">{graphEdges.filter(e=>e[0]===nodeId||e[1]===nodeId).length}</div></div></div>
        </Card>
        <Card title="Jejak Bukti" icon={<Link2 size={16} className="text-[#22C55E]" />}>
          <div className="space-y-2">{linkedEvents.map(e=><button key={e.id} onClick={()=>selectEvent(e)} className={`w-full rounded-lg border p-3 text-left transition hover:border-[#38BDF8]/50 ${selected.id===e.id?'border-[#38BDF8]/50 bg-[#38BDF8]/5':'border-[#272E3A] bg-[#0D1016]'}`}><div className="flex items-center justify-between"><span className="font-mono text-[10px] text-[#7DD3FC]">{e.id}</span><Badge className={severityStyle[e.severity]}>{e.severity}</Badge></div><div className="mt-2 text-xs font-medium">{e.title}</div><div className="mt-1 text-[10px] text-[#657080]">{e.rule}</div></button>)}</div>
          <button onClick={openDetail} className="mt-3 w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018]">Analisis event terpilih</button>
        </Card>
      </aside>
    </div>
  </div>
}

function ReportView({ followups, changeStatus, notify, caseStatus, notes }: { followups: Record<string,string>; changeStatus: (id:string,s:string)=>void; notify:(s:string)=>void; caseStatus:string; notes:string }) {
  const findings = events.filter(e => ['EVT-2402','EVT-2404','EVT-2405','EVT-2406'].includes(e.id))
  return <div className="mx-auto max-w-6xl">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Kasus INC-2025-0618" title="Laporan Insiden" text="Pratinjau laporan konsisten dengan enam event dan empat temuan pada timeline." /><button onClick={() => { notify('Dialog cetak dibuka — pilih “Simpan sebagai PDF”'); window.setTimeout(() => window.print(), 300) }} className="flex items-center justify-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2.5 text-xs font-bold text-[#071018]"><Download size={15} />Ekspor PDF</button></div>
    <article className="report overflow-hidden rounded-xl border border-[#272E3A] bg-[#131720]">
      <div className="border-b border-[#272E3A] bg-[#191F2A] p-6 md:p-8"><div className="mb-8 flex items-start justify-between"><div className="flex items-center gap-3"><div className="grid size-10 place-items-center rounded-lg bg-[#38BDF8] text-[#071018]"><ShieldAlert /></div><div><div className="font-bold tracking-[0.18em]">SIGAP</div><div className="text-[10px] text-[#7E8998]">LAPORAN ANALISIS INSIDEN</div></div></div><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">SIMULASI</Badge></div><h1 className="text-2xl font-semibold">Indikasi kompromi jaringan manufaktur</h1><div className="mt-4 flex flex-wrap gap-5 font-mono text-[11px] text-[#7E8998]"><span>INC-2025-0618</span><span>18 JUN 2025</span><span>STATUS: {caseStatus.toUpperCase()}</span><span>SEVERITY: KRITIS</span><span>CONFIDENCE: 94%</span></div></div>
      <div className="space-y-8 p-6 md:p-8">
        <section><Label>01 / Ringkasan eksekutif</Label><p className="max-w-4xl text-sm leading-7 text-[#C3CAD3]">Investigasi menemukan rangkaian serangan terindikasi kuat yang berawal dari lampiran phishing, dilanjutkan eksekusi payload, penyalahgunaan akun, pergerakan lateral menuju zona engineering, perubahan parameter PLC simulasi, dan eksfiltrasi data. Korelasi didasarkan pada IOC, identitas, sesi, host asal, dan alur jaringan yang saling menguatkan.</p></section>
        <section><Label>02 / Kronologi</Label><div className="mt-3 grid gap-2">{events.map(e => <div key={e.id} className="grid grid-cols-[82px_1fr_auto] items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] px-3 py-2.5"><span className="font-mono text-[10px] text-[#7E8998]">{e.time}</span><span className="truncate text-xs">{e.title}</span><Badge className={severityStyle[e.severity]}>{e.severity}</Badge></div>)}</div></section>
        <section><Label>03 / Temuan dan tindak lanjut</Label><div className="mt-3 overflow-x-auto"><table className="w-full min-w-[700px] text-left text-xs"><thead className="text-[10px] uppercase tracking-wider text-[#657080]"><tr className="border-b border-[#272E3A]"><th className="pb-3">ID</th><th className="pb-3">Temuan</th><th className="pb-3">Bukti utama</th><th className="pb-3">Severity</th><th className="pb-3">Status</th></tr></thead><tbody>{findings.map(e => <tr key={e.id} className="border-b border-[#272E3A] last:border-0"><td className="py-3 font-mono text-[#7DD3FC]">{e.id}</td><td className="py-3">{e.finding}</td><td className="py-3 text-[#7E8998]">{e.evidence[0]}</td><td className="py-3"><Badge className={severityStyle[e.severity]}>{e.severity}</Badge></td><td className="py-3"><select value={followups[e.id] || 'Baru'} onChange={x => changeStatus(e.id,x.target.value)} className="rounded border border-[#272E3A] bg-[#0D1016] px-2 py-1"><option>Baru</option><option>Berjalan</option><option>Selesai</option></select></td></tr>)}</tbody></table></div></section>
        <section><Label>04 / Rekomendasi prioritas</Label><div className="mt-3 grid gap-3 md:grid-cols-3">{[['P1','Isolasi aset','Batasi WS-FIN-014 dan ENG-SRV-02 dari jaringan.'],['P1','Amankan identitas','Reset akun n.rahma dan cabut seluruh sesi.'],['P2','Forensik & pemulihan','Akuisisi bukti, validasi PLC, dan verifikasi data.']].map(([p,t,d]) => <div key={t} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-4"><Badge className={p==='P1'?severityStyle.Kritis:severityStyle.Sedang}>{p}</Badge><div className="mt-3 text-sm font-semibold">{t}</div><p className="mt-1 text-xs leading-5 text-[#7E8998]">{d}</p></div>)}</div></section>
        <section><Label>05 / Catatan analis</Label><p className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-4 text-sm leading-6 text-[#AEB6C1]">{notes || 'Belum ada catatan analis.'}</p></section>
      </div>
    </article>
  </div>
}

function SummaryView({ setActive }: { setActive: (v:'Timeline'|'Graf Investigasi')=>void }) {
  const severityCounts = (['Kritis','Tinggi','Sedang','Rendah'] as Severity[]).map(s=>({label:s,value:events.filter(e=>e.severity===s).length}))
  const sourceCounts = (['Email Gateway','Endpoint','Jaringan','OT Simulator'] as Source[]).map(s=>({label:s,value:events.filter(e=>e.source===s).length}))
  const activity = [2,0,0,0,1,0,1,1,1]
  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Pusat Investigasi" title="Command Overview" text="Ringkasan operasional kasus berdasarkan telemetri dan bukti simulasi yang tersedia." /><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">DATA SIMULASI</Badge></div>
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{[
      ['Total event', events.length, '6 event terkorelasi', Activity, '#38BDF8'],
      ['Temuan kritis', severityCounts[0].value, 'Perlu respons segera', ShieldAlert, '#EF4444'],
      ['Sumber log aktif', sourceCounts.filter(s=>s.value>0).length, 'Seluruh sumber tersedia', Database, '#22C55E'],
      ['Status investigasi', 'Aktif', '4 tindak lanjut', Zap, '#F59E0B'],
    ].map(([a,b,c,I,color])=><div key={String(a)} className="group rounded-xl border border-[#272E3A] bg-[#131720] p-4 transition hover:-translate-y-0.5 hover:border-[#3A4554]"><div className="flex items-center justify-between text-xs text-[#7E8998]">{String(a)}<span className="grid size-8 place-items-center rounded-lg bg-[#0D1016]" style={{color:String(color)}}><I size={15}/></span></div><div className="mt-3 font-mono text-2xl font-semibold">{String(b)}</div><div className="mt-1 text-[10px] text-[#657080]">{String(c)}</div></div>)}</div>
    <div className="mt-4 grid gap-4 xl:grid-cols-[1.35fr_.65fr]">
      <Card title="Aktivitas Event · 08:40–09:50" icon={<Activity size={16} className="text-[#38BDF8]" />}>
        <div className="flex h-48 items-end gap-2 border-b border-[#272E3A] px-2 pb-0">{activity.map((v,i)=><div key={i} className="flex h-full flex-1 flex-col justify-end gap-2"><div title={`${v} event`} className={`w-full rounded-t transition hover:brightness-125 ${v>0?'bg-gradient-to-t from-[#0284C7] to-[#38BDF8]':'bg-[#1D2632]'}`} style={{height:`${Math.max(6,v*38)}%`}} /><span className="text-center font-mono text-[9px] text-[#596474]">{`0${8+Math.floor(i/3)}:${40+(i%3)*10}`.replace('09:60','10:00')}</span></div>)}</div><p className="mt-3 text-[10px] text-[#657080]">Puncak awal merepresentasikan phishing dan eksekusi payload; tidak ada event pada interval kosong.</p>
      </Card>
      <Card title="Distribusi Severity" icon={<ShieldAlert size={16} className="text-[#EF4444]" />}>
        <div className="flex items-center gap-6"><div className="relative size-36 shrink-0 rounded-full" style={{background:'conic-gradient(#EF4444 0 66.67%, #F59E0B 66.67% 100%)'}}><div className="absolute inset-5 grid place-items-center rounded-full bg-[#131720] text-center"><span><b className="block font-mono text-2xl">6</b><small className="text-[9px] text-[#657080]">EVENT</small></span></div></div><div className="flex-1 space-y-3">{severityCounts.map(s=><div key={s.label} className="flex items-center justify-between text-xs"><span className="flex items-center gap-2"><i className={`size-2 rounded-full ${s.label==='Kritis'?'bg-[#EF4444]':s.label==='Tinggi'?'bg-[#F59E0B]':s.label==='Sedang'?'bg-[#38BDF8]':'bg-[#22C55E]'}`}/>{s.label}</span><b className="font-mono">{s.value}</b></div>)}</div></div>
      </Card>
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-[.8fr_1.2fr]">
      <Card title="Sumber Log" icon={<Database size={16} className="text-[#22C55E]" />}><div className="space-y-4">{sourceCounts.map(s=><div key={s.label}><div className="mb-1.5 flex justify-between text-xs"><span className="flex items-center gap-2"><SourceMark source={s.label}/>{s.label}</span><span className="font-mono text-[#AEB6C1]">{s.value}</span></div><div className="h-1.5 rounded-full bg-[#0D1016]"><div className="h-full rounded-full bg-[#38BDF8]" style={{width:`${(s.value/3)*100}%`}}/></div></div>)}</div></Card>
      <div className="relative overflow-hidden rounded-xl border border-[#EF4444]/25 bg-gradient-to-br from-[#1A1D25] to-[#11151C] p-6"><div className="absolute -right-16 -top-20 size-64 rounded-full bg-[#EF4444]/5 blur-3xl"/><div className="relative"><div className="flex items-center gap-2"><Badge className={severityStyle.Kritis}>KRITIS</Badge><span className="font-mono text-[10px] text-[#657080]">INC-2025-0618</span></div><h2 className="mt-4 text-xl font-semibold">Rantai serangan lintas IT–OT terindikasi</h2><p className="mt-2 max-w-2xl text-sm leading-6 text-[#8D97A6]">Enam event dari empat sumber menghubungkan phishing, akun, workstation, server engineering, PLC simulasi, dan tujuan eksfiltrasi.</p><div className="mt-5 flex flex-wrap gap-2"><button onClick={()=>setActive('Timeline')} className="flex items-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2.5 text-xs font-bold text-[#071018]">Periksa timeline <ChevronRight size={14}/></button><button onClick={()=>setActive('Graf Investigasi')} className="flex items-center gap-2 rounded-lg border border-[#272E3A] bg-[#191F2A] px-4 py-2.5 text-xs font-semibold hover:border-[#38BDF8]/40"><GitBranch size={14}/>Buka graph</button></div></div></div>
    </div>
  </div>
}

export default App
