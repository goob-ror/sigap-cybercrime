import { useRef, useState } from 'react'
import { CircleCheck, Database, Download, FileUp, FlaskConical, Network, ShieldCheck, Target, Trash2, TriangleAlert } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import type { Artifact } from '@/core/model'
import type { Progress } from '@/db/ingestClient'
import { RULE_PACK } from '@/data/rules/catalog'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import { fmtDateTime, fmtNumber, shortHash } from '@/lib/format'
import type { LogAnalysis, ScenarioCheck } from '@/workers/protocol'

type Props = {
  imports: Artifact[]
  eventCount: number
  detectionCount: number
  incidentCount: number
  check: ScenarioCheck | null
  busy: boolean
  progress: Progress | null
  onFiles: (files: File[]) => void
  onScenario: () => void
  onDownloadSamples: () => void
  onClear: () => void
}

const FORMATS = [
  ['Windows Event Log (JSON)', 'Sysmon, Security, System, PowerShell — dari PowerShell Get-WinEvent / Get-EventLog | ConvertTo-Json (UTF-8 atau UTF-16), Winlogbeat, evtx_dump, atau EvtxECmd'],
  ['Zeek (TSV / JSON)', 'conn, dns, http, modbus, modbus_detailed (gaya ICSNPP)'],
  ['Firewall syslog key=value', 'FortiGate dan perangkat lain dengan format key=value'],
] as const

/** Read-only export of recent Windows events, for trying SIGAP on one's own machine. */
const OWN_LOG_COMMAND = 'Get-WinEvent -LogName System,Security -MaxEvents 5000 -ErrorAction SilentlyContinue | ConvertTo-Json | Out-File log-windows.json'

export function ImportView({ imports, eventCount, detectionCount, incidentCount, check, busy, progress, onFiles, onScenario, onDownloadSamples, onClear }: Props) {
  const input = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const pct = progress ? Math.round((progress.done / Math.max(1, progress.total)) * 100) : 0

  return <div className="mx-auto max-w-6xl">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Data / Impor" title="Impor Data" text="Muat log dari perangkat satuan. Semua pemrosesan terjadi di browser ini — tidak ada data yang dikirim ke server mana pun." /><div className="flex gap-2"><Badge className="border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]"><ShieldCheck size={11} className="mr-1" />OFFLINE</Badge><Badge className="border-[#38BDF8]/25 bg-[#38BDF8]/10 text-[#7DD3FC]">{RULE_PACK.sigma.length + RULE_PACK.native.length} ATURAN AKTIF</Badge></div></div>

    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.3fr_.7fr]">
      <div className="space-y-4">
        <section
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); if (!busy && e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]) }}
          className={`rounded-xl border-2 border-dashed p-8 text-center transition ${dragging ? 'border-[#38BDF8] bg-[#38BDF8]/5' : 'border-[#272E3A] bg-[#131720]'}`}
        >
          <div className="mx-auto mb-3 grid size-12 place-items-center rounded-xl border border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]"><FileUp size={22} /></div>
          <div className="text-sm font-semibold">Tarik & lepas berkas log ke sini</div>
          <p className="mt-1 text-xs text-[#7E8998]">Beberapa berkas sekaligus diperbolehkan. Format dikenali otomatis.</p>
          <input ref={input} type="file" multiple accept=".jsonl,.json,.log,.txt,.ndjson" className="hidden" onChange={(e) => { if (e.target.files?.length) onFiles([...e.target.files]); e.target.value = '' }} />
          <button disabled={busy} onClick={() => input.current?.click()} className="mt-4 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC] disabled:opacity-50">Pilih berkas</button>
          {progress && <div className="mx-auto mt-5 max-w-sm text-left"><div className="mb-1 flex justify-between text-[11px] text-[#AEB6C1]"><span>{progress.message}</span><span className="font-mono">{pct}%</span></div><div className="h-1.5 overflow-hidden rounded-full bg-[#0D1016]"><div className="h-full rounded-full bg-[#38BDF8] transition-all" style={{ width: `${Math.max(5, pct)}%` }} /></div></div>}
        </section>

        <Card title="Berkas yang Telah Diimpor" icon={<Database size={16} className="text-[#38BDF8]" />}>
          {imports.length === 0 ? <p className="py-6 text-center text-xs text-[#657080]">Belum ada berkas. Impor log atau muat skenario contoh.</p> :
            <div className="overflow-x-auto"><table className="w-full min-w-[640px] text-left text-xs"><thead className="text-[9px] uppercase tracking-wider text-[#657080]"><tr className="border-b border-[#272E3A]">{['Berkas', 'Format', 'Event', 'SHA-256', 'Waktu impor'].map((h) => <th key={h} className="pb-2 pr-3">{h}</th>)}</tr></thead>
              <tbody>{imports.map((a) => { const info = a.analysis as LogAnalysis | undefined; return <tr key={a.id} className="border-b border-[#1D232D] last:border-0"><td className="py-2.5 pr-3 font-mono text-[11px]">{a.filename}</td><td className="pr-3 text-[#AEB6C1]">{info?.formatLabel ?? '—'}</td><td className="pr-3 font-mono">{fmtNumber(info?.eventCount ?? 0)}{info?.errorCount ? <span title={info.errors.map((e) => `baris ${e.line}: ${e.message}`).join('\n')} className="ml-2 text-[#FBBF24]">({info.errorCount} gagal)</span> : null}</td><td title={a.sha256} className="pr-3 font-mono text-[10px] text-[#7E8998]">{shortHash(a.sha256)}</td><td className="text-[10px] text-[#7E8998]">{fmtDateTime(a.addedAt)}</td></tr> })}</tbody></table></div>}
          {imports.length > 0 && <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[#272E3A] pt-3 text-[11px] text-[#8D97A6]"><span className="flex items-center gap-2"><CircleCheck size={14} className="text-[#22C55E]" />{fmtNumber(eventCount)} event · {fmtNumber(detectionCount)} temuan · {fmtNumber(incidentCount)} insiden · hash tercatat di rantai kustodi</span><button disabled={busy} onClick={onClear} className="flex items-center gap-1.5 rounded-lg border border-[#EF4444]/30 px-3 py-1.5 text-[#FCA5A5] hover:bg-[#EF4444]/10 disabled:opacity-50"><Trash2 size={13} />Hapus semua data</button></div>}
        </Card>
      </div>

      <div className="space-y-4">
        <Card title="Skenario Contoh" icon={<FlaskConical size={16} className="text-[#F59E0B]" />}>
          <p className="text-xs leading-5 text-[#AEB6C1]">Satuan fiktif, Senin 2 Nov 2026: ±5.000 event normal dari 9 host, sensor Zeek, firewall, dan pengendali genset — disisipi rantai serangan dari dokumen WhatsApp hingga manipulasi Modbus dan eksfiltrasi.</p>
          <button disabled={busy} onClick={onScenario} className="mt-4 w-full rounded-lg bg-[#F59E0B] py-2.5 text-xs font-bold text-[#140D02] hover:bg-[#FBBF24] disabled:opacity-50">Muat skenario contoh</button>
          <button disabled={busy} onClick={onDownloadSamples} className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg border border-[#272E3A] py-2 text-xs text-[#AEB6C1] hover:text-white disabled:opacity-50"><Download size={13} />Unduh berkas contoh (untuk uji impor)</button>
          <p className="mt-3 flex gap-2 text-[10px] leading-4 text-[#657080]"><TriangleAlert size={12} className="mt-0.5 shrink-0" />Semua nama, host, dan alamat dalam skenario adalah fiktif.</p>
        </Card>
        {check && <AccuracyCard check={check} />}
        <Card title="Format Didukung" icon={<FileUp size={16} className="text-[#38BDF8]" />}>
          <div className="space-y-3">{FORMATS.map(([name, text]) => <div key={name}><Label>{name}</Label><p className="text-xs leading-5 text-[#8D97A6]">{text}</p></div>)}</div>
          <div className="mt-3 border-t border-[#272E3A] pt-3"><Label>Coba dengan log komputer Anda</Label><p className="text-[11px] leading-5 text-[#8D97A6]">Jalankan di PowerShell, lalu impor berkasnya. Log Security memerlukan PowerShell sebagai Administrator.</p><code className="mt-2 block select-all break-all rounded-lg border border-[#272E3A] bg-[#0D1016] p-2.5 font-mono text-[10px] leading-4 text-[#7DD3FC]">{OWN_LOG_COMMAND}</code></div>
          <p className="mt-3 border-t border-[#272E3A] pt-3 text-[10px] leading-4 text-[#657080]">Berkas yang sama diimpor dua kali tidak menggandakan data (dikenali dari hash SHA-256 berkas asli).</p>
        </Card>
        <Card title="Profil Jaringan Satuan" icon={<Network size={16} className="text-[#38BDF8]" />}>
          <p className="text-xs leading-5 text-[#AEB6C1]">{DEFAULT_UNIT_PROFILE.name}. Dipakai untuk menghubungkan alamat IP dengan nama aset dan menilai perintah OT.</p>
          <div className="mt-3 space-y-1.5">{DEFAULT_UNIT_PROFILE.assets.map((a) => <div key={a.name} className="flex items-center justify-between gap-2 rounded-lg border border-[#272E3A] bg-[#0D1016] px-3 py-2 text-[11px]"><span className="min-w-0"><span className={`block font-mono ${a.kind === 'ot' ? 'text-[#FBBF24]' : 'text-[#D1D6DD]'}`}>{a.name}</span><span className="block truncate text-[10px] text-[#657080]">{a.role}</span></span><span className="font-mono text-[#8D97A6]">{a.ip}</span></div>)}</div>
          <div className="mt-3 space-y-1 text-[11px] text-[#8D97A6]"><div>Segmen OT: <span className="font-mono text-[#D1D6DD]">{DEFAULT_UNIT_PROFILE.otSubnets.join(', ')}</span></div><div>Boleh mengirim perintah Modbus: <span className="font-mono text-[#D1D6DD]">{DEFAULT_UNIT_PROFILE.engineeringHosts.join(', ')}</span></div></div>
          <p className="mt-3 border-t border-[#272E3A] pt-3 text-[10px] leading-4 text-[#657080]">Alamat workstation tidak perlu didaftarkan: SIGAP mempelajarinya dari log (koneksi Sysmon dan logon jarak jauh).</p>
        </Card>
      </div>
    </div>
  </div>
}

const pct = (n: number, of: number) => (of ? `${((n / of) * 100).toFixed(1).replace('.', ',')}%` : '—')

/** Detection results compared with the scenario's answer key. */
function AccuracyCard({ check }: { check: ScenarioCheck }) {
  return <Card title="Uji Akurasi pada Skenario" icon={<Target size={16} className="text-[#22C55E]" />}>
    <p className="text-xs leading-5 text-[#AEB6C1]">Generator skenario menandai event serangan yang ia sisipkan. SIGAP tidak melihat tanda itu; angka di bawah membandingkan hasil deteksi dengan kunci jawaban tersebut.</p>
    <div className="mt-3 grid grid-cols-2 gap-2">
      <div className="rounded-lg border border-[#22C55E]/25 bg-[#22C55E]/5 p-3"><div className="text-[9px] uppercase tracking-wider text-[#657080]">Event normal salah ditandai</div><div className="mt-1 font-mono text-xl text-[#86EFAC]">{fmtNumber(check.benignFlagged)}</div><div className="text-[10px] text-[#657080]">dari {fmtNumber(check.benignEvents)} ({pct(check.benignFlagged, check.benignEvents)})</div></div>
      <div className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><div className="text-[9px] uppercase tracking-wider text-[#657080]">Event serangan ditandai</div><div className="mt-1 font-mono text-xl">{fmtNumber(check.attackFlagged)}</div><div className="text-[10px] text-[#657080]">dari {fmtNumber(check.attackEvents)} ({pct(check.attackFlagged, check.attackEvents)})</div></div>
    </div>
    <p className="mt-3 text-[10px] leading-4 text-[#657080]">Tidak semua event serangan perlu memicu aturan sendiri — misalnya koneksi yang sama tercatat oleh Zeek, firewall, dan Sysmon sekaligus. Diukur dari {check.files} dari {check.totalFiles} berkas skenario yang diimpor.</p>
  </Card>
}
