import { useMemo, useState } from 'react'
import dagre from '@dagrejs/dagre'
import { ArrowRight, Box, ChevronRight, GitBranch, Link2, Upload } from 'lucide-react'
import { ENTITY_ICONS, EntityIcon, entityTone, entityTypeLabel, isIndicator } from '@/components/EntityIcon'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import { Select } from '@/components/ui/Select'
import type { Incident, IncidentEntity, Relation } from '@/core/model'
import { scorePercent } from '@/core/report/narrative'
import type { Investigation } from '@/db/hooks'
import { fmtDateTime, fmtTime } from '@/lib/format'
import { LEVEL_COLOR, LEVEL_LABEL, LEVEL_RANK, levelStyle } from '@/lib/styles'

type Props = {
  data: Investigation
  incidentId: string | null
  selectIncident: (id: string) => void
  openDetail: (detectionId: string) => void
  openImport: () => void
}

const NODE_W = 170
const NODE_H = 46

type Point = { x: number; y: number }
type Laid = { nodes: (IncidentEntity & { x: number; y: number })[]; edges: (Relation & { points: Point[]; label: Point })[]; width: number; height: number }

const CHAR_W = 5.8
/** Full description of an edge, for tooltips and the side panel. */
const edgeText = (r: Relation) => `${r.labels.join(' · ')}${r.count > 1 ? ` ×${r.count}` : ''}`
const clip = (text: string, max: number) => (text.length > max ? `${text.slice(0, max - 1)}…` : text)
/** Two short lines drawn on the edge: the most severe action, then how much more there is. */
function edgeLines(r: Relation): string[] {
  const extra = [r.labels.length > 1 && `+${r.labels.length - 1} jenis`, r.count > 1 && `${r.count}×`].filter(Boolean).join(' · ')
  return [clip(r.labels[0].replace(/^Modbus /, ''), 22), ...(extra ? [extra] : [])]
}

const labelSize = (r: Relation) => { const lines = edgeLines(r); return { w: Math.max(...lines.map((l) => l.length)) * CHAR_W + 12, h: lines.length * 12 + 4 } }

/** Point at fraction `t` of a polyline's length. */
function pointAt(points: Point[], t: number): Point {
  const seg = points.slice(1).map((p, i) => Math.hypot(p.x - points[i].x, p.y - points[i].y))
  let left = seg.reduce((a, b) => a + b, 0) * t
  for (let i = 0; i < seg.length; i++) {
    if (left <= seg[i]) {
      const t = seg[i] ? left / seg[i] : 0
      return { x: points[i].x + (points[i + 1].x - points[i].x) * t, y: points[i].y + (points[i + 1].y - points[i].y) * t }
    }
    left -= seg[i]
  }
  return points[0] ?? { x: 0, y: 0 }
}

/**
 * Left-to-right layered layout (dagre): sources of activity on the left, targets on the right.
 * Labels are not given space in the layout (dagre would add a column per label); they are drawn
 * at each edge's midpoint instead, which keeps the graph about a third narrower.
 */
function layout(incident: Incident): Laid {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'LR', nodesep: 30, ranksep: 140, marginx: 20, marginy: 20 })
  g.setDefaultEdgeLabel(() => ({}))
  for (const e of incident.entities) g.setNode(e.key, { width: NODE_W, height: NODE_H })
  for (const r of incident.relations) g.setEdge(r.from, r.to)
  dagre.layout(g)
  return {
    nodes: incident.entities.map((e) => ({ ...e, x: g.node(e.key).x, y: g.node(e.key).y })),
    edges: incident.relations.map((r) => {
      const points = g.edge(r.from, r.to).points ?? []
      // Slide the label along its edge until it clears every node box.
      const { w, h } = labelSize(r)
      const clear = (p: Point) => incident.entities.every((e) => { const n = g.node(e.key); return Math.abs(p.x - n.x) > (NODE_W + w) / 2 + 4 || Math.abs(p.y - n.y) > (NODE_H + h) / 2 + 2 })
      const label = [0.5, 0.4, 0.6, 0.3, 0.7, 0.2, 0.8].map((t) => pointAt(points, t)).find(clear) ?? pointAt(points, 0.5)
      return { ...r, points, label }
    }),
    width: g.graph().width ?? 600,
    height: g.graph().height ?? 400,
  }
}

function pathD(points: { x: number; y: number }[]) {
  if (points.length < 2) return ''
  // Smooth curve through dagre's control points.
  let d = `M${points[0].x},${points[0].y}`
  for (let i = 1; i < points.length - 1; i++) {
    const mx = (points[i].x + points[i + 1].x) / 2
    const my = (points[i].y + points[i + 1].y) / 2
    d += ` Q${points[i].x},${points[i].y} ${mx},${my}`
  }
  const last = points.at(-1)!
  return `${d} L${last.x},${last.y}`
}

export function GraphView({ data, incidentId, selectIncident, openDetail, openImport }: Props) {
  const incident = data.incidents.find((i) => i.id === incidentId) ?? data.incidents[0]
  const laid = useMemo(() => (incident ? layout(incident) : null), [incident])
  const [nodeKey, setNodeKey] = useState<string | null>(null)

  if (!incident || !laid) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]"><Upload size={22} /></div><h1 className="text-lg font-semibold">Belum ada insiden</h1><p className="mt-2 text-sm text-[#7E8998]">Graf disusun dari entitas pada temuan yang saling terkait. Impor log atau muat skenario contoh.</p><button onClick={openImport} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Impor Data</button></div></div>
  }

  const node = incident.entities.find((e) => e.key === nodeKey) ?? incident.entities.find((e) => e.key === incident.path[0]) ?? incident.entities[0]
  const touching = incident.relations.filter((r) => r.from === node.key || r.to === node.key)
  const neighbors = new Set(touching.flatMap((r) => [r.from, r.to]))
  const byKey = new Map(incident.entities.map((e) => [e.key, e]))
  const nodeDetections = node.detectionIds.map((id) => data.detectionsById.get(id)).filter((d) => !!d).sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts)
  const options = data.incidents.map((i) => `${i.caseId ?? i.id} · ${i.title}`)

  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow={`Korelasi / ${incident.caseId ?? incident.id}`} title="Graf Investigasi" text="Aset, akun, dan infrastruktur yang muncul pada temuan insiden ini, beserta hubungan yang tercatat di log. Pilih simpul untuk melihat buktinya." /><div className="flex flex-wrap gap-2"><Badge className="border-[#38BDF8]/25 bg-[#38BDF8]/10 text-[#7DD3FC]">{incident.entities.length} ENTITAS</Badge><Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">{incident.relations.length} RELASI</Badge><Badge className={levelStyle[incident.level]}>SKOR {scorePercent(incident.score)}%</Badge></div></div>
    {data.incidents.length > 1 && <div className="mb-3 flex items-center gap-2 rounded-xl border border-[#272E3A] bg-[#131720] p-3 text-xs"><span className="text-[#7E8998]">Insiden</span><Select value={options[data.incidents.indexOf(incident)]} setValue={(v) => { const i = options.indexOf(v); if (i >= 0) { selectIncident(data.incidents[i].id); setNodeKey(null) } }} options={options} /></div>}
    <div className="grid grid-cols-1 gap-4 2xl:grid-cols-[minmax(0,1fr)_360px]">
      <section className="overflow-hidden rounded-xl border border-[#272E3A] bg-[#0B0E13]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#272E3A] px-4 py-3"><div className="flex min-w-0 items-center gap-2 text-xs font-semibold"><GitBranch size={15} className="shrink-0 text-[#38BDF8]" /><span className="truncate">{incident.title}</span></div><div className="flex flex-wrap gap-3 text-[10px] text-[#657080]">{[['#7DD3FC', 'Aset / IP internal'], ['#C4B5FD', 'Akun'], ['#FCA5A5', 'Indikator eksternal'], ['#FBBF24', 'Perangkat OT']].map(([c, t]) => <span key={t}><i className="mr-1 inline-block size-1.5 rounded-full" style={{ background: c }} />{t}</span>)}</div></div>
        <div className="max-h-[640px] overflow-auto bg-[radial-gradient(circle_at_center,rgba(56,189,248,0.05),transparent_60%)] p-2">
          <svg width={laid.width} height={laid.height} viewBox={`0 0 ${laid.width} ${laid.height}`} className="mx-auto block max-w-none" role="img" aria-label={`Graf ${incident.entities.length} entitas dan ${incident.relations.length} relasi`}>
            <defs>{(['critical', 'high', 'medium', 'low', 'informational'] as const).map((l) => <marker key={l} id={`arrow-${l}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill={LEVEL_COLOR[l]} /></marker>)}</defs>
            {laid.edges.map((r) => { const hot = r.from === node.key || r.to === node.key; return <path key={`${r.from}>${r.to}`} d={pathD(r.points)} fill="none" opacity={hot ? 1 : 0.5} stroke={LEVEL_COLOR[r.level]} strokeWidth={hot ? 2 : 1.2} strokeDasharray={LEVEL_RANK[r.level] >= LEVEL_RANK.high ? undefined : '4 4'} markerEnd={`url(#arrow-${r.level})`}><title>{edgeText(r)}</title></path> })}
            {laid.nodes.map((e) => { const tone = entityTone(e); const Icon = ENTITY_ICONS[e.type]; const active = e.key === node.key; const dim = !active && !neighbors.has(e.key); return <g key={e.key} transform={`translate(${e.x - NODE_W / 2},${e.y - NODE_H / 2})`} opacity={dim ? 0.55 : 1} onClick={() => setNodeKey(e.key)} className="cursor-pointer" role="button" aria-label={`${entityTypeLabel(e)} ${e.value}`}>
              <title>{`${entityTypeLabel(e)}: ${e.value}${e.aliases.length ? ` (${e.aliases.join(', ')})` : ''}`}</title>
              <rect width={NODE_W} height={NODE_H} rx={10} fill={active ? '#172331' : '#131720'} stroke={active ? '#38BDF8' : tone.border} strokeWidth={active ? 2 : 1} />
              <rect x={8} y={9} width={28} height={28} rx={7} fill={tone.bg} />
              <Icon x={14} y={15} width={16} height={16} color={tone.fg} />
              <text x={44} y={20} fontSize="11" fontWeight="600" fill="#F3F5F7" fontFamily="ui-monospace, monospace">{clip(e.value, 19)}</text>
              <text x={44} y={34} fontSize="9" fill="#7E8998">{clip(`${entityTypeLabel(e)}${e.aliases.length ? ` · ${e.aliases[0]}` : ''}${e.common ? ' · umum' : ''}`, 26)}</text>
            </g> })}
            {laid.edges.map((r) => { const hot = r.from === node.key || r.to === node.key; const lines = edgeLines(r); const { w, h } = labelSize(r); return <g key={`label:${r.from}>${r.to}`} opacity={hot ? 1 : 0.75} pointerEvents="none">
              <rect x={r.label.x - w / 2} y={r.label.y - h / 2} width={w} height={h} rx={4} fill="#0B0E13" stroke={hot ? LEVEL_COLOR[r.level] : '#272E3A'} />
              {lines.map((line, i) => <text key={i} x={r.label.x} y={r.label.y - h / 2 + 12 + i * 12} textAnchor="middle" fontSize={i ? 9 : 10} fill={i ? '#7E8998' : hot ? '#F3F5F7' : '#AEB6C1'} fontFamily="ui-monospace, monospace">{line}</text>)}
            </g> })}
          </svg>
        </div>
        <p className="border-t border-[#272E3A] px-4 py-2 text-[10px] text-[#657080]">Panah = arah aktivitas (dari sumber ke tujuan). Garis tegas = temuan kritis/tinggi, putus-putus = sedang/rendah. Tata letak otomatis (dagre); geser bila graf lebih lebar dari layar.</p>
      </section>
      <aside className="grid grid-cols-1 content-start gap-4 md:grid-cols-2 2xl:grid-cols-1">
        <Card title="Entitas Terpilih" icon={<Box size={16} className="text-[#38BDF8]" />}>
          <div className="mb-4 flex items-center gap-3"><EntityIcon entity={node} size={18} /><div className="min-w-0"><div className="break-all font-mono text-sm font-semibold">{node.value}</div><div className="text-[10px] uppercase tracking-wider text-[#657080]">{entityTypeLabel(node)}</div></div></div>
          <div className="space-y-1.5 text-xs">{[['Juga dikenal sebagai', node.aliases.join(', ')], ['Pertama terlihat', fmtDateTime(node.firstSeen)], ['Peran', node.actor ? 'Tempat/sumber aktivitas' : 'Tujuan / objek aktivitas'], ['Catatan', [node.common && 'Infrastruktur/akun umum (dipakai ≥ ½ host) — tidak dipakai untuk menggabungkan temuan', isIndicator(node) && 'Indikator — kandidat diblokir'].filter(Boolean).join('. ')]].filter(([, v]) => v).map(([k, v]) => <div key={k} className="flex justify-between gap-3 border-b border-[#272E3A] py-1.5 last:border-0"><span className="shrink-0 text-[#707B8A]">{k}</span><span className="text-right font-mono text-[11px] text-[#D1D6DD]">{v}</span></div>)}</div>
          <div className="mt-4"><Label>Relasi ({touching.length})</Label><div className="space-y-1.5">{touching.map((r) => { const other = byKey.get(r.from === node.key ? r.to : r.from)!; return <button key={`${r.from}>${r.to}`} onClick={() => setNodeKey(other.key)} className="flex w-full items-center gap-2 rounded-lg border border-[#272E3A] bg-[#0D1016] px-2.5 py-2 text-left text-[11px] hover:border-[#38BDF8]/40">{r.from === node.key ? <ArrowRight size={12} className="shrink-0 text-[#7DD3FC]" /> : <ArrowRight size={12} className="shrink-0 rotate-180 text-[#FBBF24]" />}<span className="min-w-0 flex-1 truncate font-mono">{other.value}</span><span className="max-w-[45%] truncate text-[10px] text-[#7E8998]">{edgeText(r)}</span></button> })}</div></div>
        </Card>
        <Card title={`Temuan pada entitas ini (${nodeDetections.length})`} icon={<Link2 size={16} className="text-[#22C55E]" />}>
          <div className="max-h-80 space-y-2 overflow-y-auto">{nodeDetections.map((d) => <button key={d.id} onClick={() => openDetail(d.id)} className="flex w-full items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-left hover:border-[#38BDF8]/50"><span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium">{d.title}</span><span className="mt-1 block font-mono text-[10px] text-[#657080]">{fmtTime(d.ts)}</span></span><Badge className={levelStyle[d.level]}>{LEVEL_LABEL[d.level]}</Badge><ChevronRight size={13} className="text-[#657080]" /></button>)}</div>
        </Card>
      </aside>
    </div>
  </div>
}
