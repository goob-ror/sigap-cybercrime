import { useState } from 'react'
import { Box, GitBranch, Link2 } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { PageTitle } from '@/components/ui/PageTitle'
import { type Event, events, graphEdges, graphNodes } from '@/data/demoCase'
import { severityStyle } from '@/lib/styles'

export function GraphView({ selected, selectEvent, openDetail }: { selected:Event; selectEvent:(e:Event)=>void; openDetail:()=>void }) {
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
