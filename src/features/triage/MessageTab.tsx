import { useState } from 'react'
import { MessageSquareWarning, Search, ShieldCheck, TriangleAlert } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { scorePercent } from '@/core/report/narrative'
import { analyzeMessage, type MessageReport } from '@/core/triage/message'
import { LEVEL_LABEL, levelStyle } from '@/lib/styles'

const MAX_MESSAGE = 4000

/** A pasted message, read only in this browser. It can flag a message and can never clear one. */
export function MessageTab({ checkLink }: { checkLink: (url: string) => void }) {
  const [text, setText] = useState('')
  const [report, setReport] = useState<MessageReport | null>(null)

  return <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
    <Card title="Pesan Mencurigakan" icon={<MessageSquareWarning size={16} className="text-[#38BDF8]" />}>
      <Label>Tempel isi pesan, misalnya dari WhatsApp</Label>
      <textarea aria-label="Isi pesan" value={text} maxLength={MAX_MESSAGE} onChange={(e) => setText(e.target.value)} placeholder="Yth. Bapak, tukin Anda tertahan. Segera verifikasi di http://…" className="min-h-40 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-xs leading-5 outline-none focus:border-[#38BDF8]/50" />
      <button disabled={!text.trim()} onClick={() => setReport(analyzeMessage(text))} className="mt-3 w-full rounded-lg bg-[#38BDF8] py-2.5 text-xs font-bold text-[#071018] disabled:opacity-50">Periksa secara lokal</button>
      <div className="mt-3 flex items-center gap-2 text-[10px] text-[#657080]"><ShieldCheck size={13} />Pemeriksaan ini berjalan di browser ini. Jangan membuka tautan atau membalas pesannya.</div>
    </Card>

    <Card title="Hasil Pemeriksaan" icon={<Search size={16} className="text-[#F59E0B]" />}>
      {!report ? <div className="grid h-52 place-items-center text-center text-xs text-[#657080]"><div><MessageSquareWarning className="mx-auto mb-3" />Tempel pesan untuk melihat cirinya.</div></div> : <>
        {report.signals.length === 0
          ? <p className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-xs leading-5 text-[#AEB6C1]">Tidak ada ciri penipuan yang dikenali. <b>Ini bukan berarti pesan aman</b>: pastikan pengirimnya lewat jalur resmi bila ragu.</p>
          : <div className="space-y-2">{report.signals.map((s) => <div key={s.id} className="flex items-start gap-2 rounded-lg border border-[#272E3A] p-3 text-xs leading-5 text-[#AEB6C1]"><TriangleAlert size={14} className="mt-0.5 shrink-0 text-[#F59E0B]" /><span className="min-w-0 flex-1">{s.label}</span><Badge className={levelStyle[s.level]}>{LEVEL_LABEL[s.level]}</Badge></div>)}</div>}
        {report.links.length > 0 && <div className="mt-3"><Label>Tautan dalam pesan</Label><div className="space-y-1.5">{report.links.map((l) => <div key={l.input} className="flex items-center gap-2 rounded-lg border border-[#272E3A] bg-[#0D1016] p-2 text-[11px]"><span className="min-w-0 flex-1 truncate font-mono text-[#C3CAD3]">{l.host}</span><span className="font-mono text-[#8D97A6]">{scorePercent(l.score)}%</span><button onClick={() => checkLink(l.input)} className="shrink-0 rounded border border-[#272E3A] px-2 py-1 text-[10px] hover:border-[#38BDF8]/40">Periksa →</button></div>)}</div></div>}
        <p className="mt-3 text-[11px] leading-5 text-[#D4A64B]">Hasil ini mencari ciri umum penipuan, bukan kepastian. Laporkan pesan yang meragukan sesuai prosedur satuan.</p>
      </>}
    </Card>
  </div>
}
