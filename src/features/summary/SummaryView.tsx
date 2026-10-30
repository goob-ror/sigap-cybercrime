import { Activity, ChevronRight, Database, GitBranch, ShieldAlert, Zap } from 'lucide-react'
import { SourceMark } from '@/components/SourceMark'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { PageTitle } from '@/components/ui/PageTitle'
import { type Severity, type Source, events } from '@/data/demoCase'
import { severityStyle } from '@/lib/styles'

export function SummaryView({ setActive }: { setActive: (v:'Timeline'|'Graf Investigasi')=>void }) {
  const severityCounts = (['Kritis','Tinggi','Sedang','Rendah'] as Severity[]).map(s=>({label:s,value:events.filter(e=>e.severity===s).length}))
  const sourceCounts = (['Email Gateway','Endpoint','Jaringan','OT Simulator'] as Source[]).map(s=>({label:s,value:events.filter(e=>e.source===s).length}))
  const activity = [2,0,0,0,1,0,1,1,1]
  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow="Pusat Investigasi" title="Command Overview" text="Ringkasan operasional kasus berdasarkan telemetri dan bukti simulasi yang tersedia." /><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">DATA SIMULASI</Badge></div>
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{([
      ['Total event', events.length, '6 event terkorelasi', Activity, '#38BDF8'],
      ['Temuan kritis', severityCounts[0].value, 'Perlu respons segera', ShieldAlert, '#EF4444'],
      ['Sumber log aktif', sourceCounts.filter(s=>s.value>0).length, 'Seluruh sumber tersedia', Database, '#22C55E'],
      ['Status investigasi', 'Aktif', '4 tindak lanjut', Zap, '#F59E0B'],
    ] as const).map(([a,b,c,I,color])=><div key={String(a)} className="group rounded-xl border border-[#272E3A] bg-[#131720] p-4 transition hover:-translate-y-0.5 hover:border-[#3A4554]"><div className="flex items-center justify-between text-xs text-[#7E8998]">{String(a)}<span className="grid size-8 place-items-center rounded-lg bg-[#0D1016]" style={{color:String(color)}}><I size={15}/></span></div><div className="mt-3 font-mono text-2xl font-semibold">{String(b)}</div><div className="mt-1 text-[10px] text-[#657080]">{String(c)}</div></div>)}</div>
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
