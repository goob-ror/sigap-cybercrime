import { BookText, ShieldAlert } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import { PLAYBOOKS } from '@/data/playbooks'
import { TACTIC_LABEL } from '@/data/attack'

export function PlaybookView() {
  return <div className="mx-auto max-w-5xl">
    <div className="mb-6"><PageTitle eyebrow="Panduan Respons" title="Playbook Penanganan" text="Langkah tanggap insiden dalam Bahasa Indonesia untuk operator satuan. Di dalam sebuah kasus, langkah dapat dicentang dan progresnya tersimpan." /></div>
    <div className="mb-4 flex gap-2 rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-3 text-[11px] leading-5 text-[#D4A64B]"><ShieldAlert size={15} className="mt-0.5 shrink-0" />Tindakan pada sistem operasional (genset/PLC) wajib diverifikasi, mendapat otorisasi komandan, dan dicatat.</div>
    <div className="space-y-4">{PLAYBOOKS.map((pb) => <Card key={pb.id} title={pb.title} icon={<BookText size={16} className="text-[#38BDF8]" />}>
      <p className="text-xs leading-5 text-[#8D97A6]">{pb.summary}</p>
      <div className="mt-2 flex flex-wrap gap-1.5">{pb.tactics.map((t) => <Badge key={t} className="border-[#38BDF8]/20 bg-[#38BDF8]/10 text-[#7DD3FC]">{TACTIC_LABEL[t] ?? t}</Badge>)}</div>
      <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">{pb.phases.map((ph) => <div key={ph.title}><Label>{ph.title}</Label><ol className="mt-1 space-y-1.5 text-xs leading-5 text-[#AEB6C1]">{ph.steps.map((s, i) => <li key={i} className="flex gap-2"><span className="font-mono text-[10px] text-[#657080]">{i + 1}.</span><span className="min-w-0 flex-1">{s}</span></li>)}</ol></div>)}</div>
    </Card>)}</div>
  </div>
}
