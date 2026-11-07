import { useEffect, useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, Pause, Play, Scissors, ShieldCheck, TriangleAlert, Zap } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { cutOptions, runningAt, simulateCut, valueAt, type OtAnalysis, type OtCut, type OtNode, type OtZone } from '@/core/ot/analysis'
import { fmtDate, fmtSpan, fmtTime } from '@/lib/format'
import { LEVEL_LABEL, levelStyle } from '@/lib/styles'

const STEP_MS = 1300
const VIEW = { width: 960, height: 330 }
const NODE = { width: 132, height: 36 }
const COLUMN: Record<OtZone, number> = { internet: 86, it: 300, hmi: 540, plc: 700 }
const PROCESS_X = 876
const BOUNDARY_X = 432
const MAX_PER_ZONE = 5

type Place = { node: OtNode; x: number; y: number }

function layout(nodes: OtNode[]): Place[] {
  const places: Place[] = []
  for (const zone of ['internet', 'it', 'hmi', 'plc'] as const) {
    const own = nodes.filter((n) => n.zone === zone).sort((a, b) => a.firstSeen - b.firstSeen).slice(0, MAX_PER_ZONE)
    const gap = Math.min(66, (VIEW.height - 90) / Math.max(own.length, 1))
    const top = 60 + (VIEW.height - 70 - gap * own.length) / 2
    // The HMI sits above the controller, so an intruder's line into the controller cannot read as passing through it.
    const lift = zone === 'hmi' ? -70 : 0
    own.forEach((node, i) => places.push({ node, x: COLUMN[zone], y: top + gap * i + gap / 2 + lift }))
  }
  return places
}

function linkPath(a: Place, b: Place): string {
  const forward = b.x >= a.x
  const startX = a.x + (forward ? NODE.width / 2 : -NODE.width / 2)
  const endX = b.x + (forward ? -NODE.width / 2 : NODE.width / 2)
  if (a.x === b.x) {
    // Same column: an arc along the side, so the line does not pass through the boxes.
    const side = a.x + NODE.width / 2
    return `M${side} ${a.y}C${side + 34} ${a.y} ${side + 34} ${b.y} ${side} ${b.y}`
  }
  const bend = (endX - startX) / 2
  return `M${startX} ${a.y}C${startX + bend} ${a.y} ${endX - bend} ${b.y} ${endX} ${b.y}`
}

const clip = (text: string, max = 17) => (text.length > max ? `${text.slice(0, max - 1)}…` : text)

/**
 * The attack played back over the network zones, with the process beside it. Choosing a cut replays it
 * with that host isolated or that path blocked, using only the paths the logs show.
 */
export function AttackReplay({ a, openDetail }: { a: OtAnalysis; openDetail: (id: string) => void }) {
  const [index, setIndex] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [cutId, setCutId] = useState<string | null>(null)
  const options = useMemo(() => cutOptions(a), [a])
  const selected = options.find((o) => o.id === cutId)
  const cut: OtCut = useMemo(() => selected?.cut ?? {}, [selected])
  const result = useMemo(() => simulateCut(a, cut), [a, cut])
  const moments = a.moments
  const last = moments.length - 1
  const current = moments[Math.min(index, last)]
  const t = current?.ts ?? a.span.from

  useEffect(() => {
    if (!playing) return
    if (index >= last) { setPlaying(false); return }
    const timer = window.setTimeout(() => setIndex((i) => i + 1), STEP_MS)
    return () => window.clearTimeout(timer)
  }, [playing, index, last])

  const blocked = useMemo(() => new Set([...result.cutOff, ...(cut.node ? [cut.node] : [])]), [result, cut])
  const places = useMemo(() => layout(a.nodes), [a.nodes])
  const at = useMemo(() => new Map(places.map((p) => [p.node.key, p])), [places])
  const shownOut = a.nodes.length - places.length
  const processY = places.find((p) => p.node.zone === 'plc')?.y ?? VIEW.height / 2

  const reached = (n: OtNode) => n.inAttack && n.firstSeen <= t && !blocked.has(n.key)
  const setpoint = a.series.find((s) => s.kind === 'setpoint') ?? a.series.find((s) => s.kind === 'ditulis')
  const measured = a.series.find((s) => s.kind === 'terukur')
  const run = a.runs[0]
  // If the path is cut, nothing reaches the controller: the process keeps its normal values.
  const protectedOt = selected?.result.protectsOt ?? false
  const beforeAttack = a.firstWrite ?? a.span.from
  const processT = protectedOt ? Math.min(t, beforeAttack - 1) : t
  const setpointNow = setpoint ? valueAt(setpoint, processT) : undefined
  const measuredNow = measured ? valueAt(measured, processT) : undefined
  const runningNow = run ? runningAt(run, processT) : undefined
  const outside = setpoint?.band && setpointNow !== undefined && (setpointNow < setpoint.band.min || setpointNow > setpoint.band.max)
  const harmed = !!outside || runningNow === false
  const unit = setpoint?.unit ? ` ${setpoint.unit}` : ''
  const avoidedMoment = (nodes: string[]) => nodes.length > 0 && nodes.every((k) => blocked.has(k))

  const choose = (id: string | null) => {
    setCutId(id)
    setIndex(0)
    setPlaying(id !== null)
  }

  if (!moments.length) return null

  return <Card title="Putar Ulang Serangan" icon={<Zap size={16} className="text-[#F59E0B]" />}>
    <div className="mb-3 flex flex-wrap items-center gap-1.5" role="group" aria-label="Uji pemutusan">
      <Scissors size={13} className="mr-1 text-[#8D97A6]" />
      <button aria-pressed={cutId === null} onClick={() => choose(null)} className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold ${cutId === null ? 'border-[#38BDF8] bg-[#38BDF8]/10 text-[#7DD3FC]' : 'border-[#272E3A] text-[#AEB6C1] hover:text-white'}`}>Seperti yang terjadi</button>
      {options.map((o) => <button key={o.id} aria-pressed={cutId === o.id} onClick={() => choose(o.id)} className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold ${cutId === o.id ? 'border-[#38BDF8] bg-[#38BDF8]/10 text-[#7DD3FC]' : 'border-[#272E3A] text-[#AEB6C1] hover:text-white'}`}>{o.label}</button>)}
    </div>

    <div className="overflow-x-auto rounded-lg border border-[#272E3A] bg-[#0D1016]">
      <svg data-testid="zone-map" role="img" aria-label="Peta jalur serangan menurut zona jaringan" viewBox={`0 0 ${VIEW.width} ${VIEW.height}`} className="block w-full min-w-[720px]">
        <defs>
          <marker id="arrow-bad" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L8 4L0 8Z" fill="#EF4444" /></marker>
          <marker id="arrow-good" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L8 4L0 8Z" fill="#22C55E" /></marker>
        </defs>
        {([['INTERNET', 86], ['JARINGAN TI', 300], ['HMI / ENGINEERING', 540], ['PENGENDALI', 700], ['PROSES FISIK', PROCESS_X]] as const).map(([label, x]) => <text key={label} x={x} y={26} textAnchor="middle" fontSize={10} letterSpacing="1.2" fill="#657080">{label}</text>)}
        <line x1={BOUNDARY_X} x2={BOUNDARY_X} y1={16} y2={VIEW.height - 12} stroke="#F59E0B" strokeOpacity={0.55} />
        <text x={BOUNDARY_X} y={VIEW.height - 2} textAnchor="middle" fontSize={9} fill="#D4A64B">BATAS TI / OT</text>

        {a.links.map((l) => {
          const from = at.get(l.from)
          const to = at.get(l.to)
          if (!from || !to) return null
          const stopped = !l.normal && (blocked.has(l.to) || blocked.has(l.from) || (cut.link?.[0] === l.from && cut.link?.[1] === l.to))
          const live = l.normal || (l.firstSeen <= t && !stopped)
          return <path key={`${l.from}>${l.to}`} d={linkPath(from, to)} fill="none" stroke={l.normal ? '#22C55E' : stopped ? '#657080' : live ? '#EF4444' : '#272E3A'} strokeWidth={live && !l.normal ? 2 : 1.5} strokeOpacity={l.normal ? 0.6 : 1} strokeDasharray={stopped ? '5 5' : undefined} markerEnd={l.normal ? 'url(#arrow-good)' : live ? 'url(#arrow-bad)' : undefined} />
        })}

        {places.map(({ node, x, y }) => {
          const isBlocked = blocked.has(node.key) && node.inAttack
          const hit = reached(node)
          const hitOt = hit && (node.zone === 'plc' || node.zone === 'hmi')
          return <g key={node.key} data-node={node.label} data-state={isBlocked ? 'terputus' : hit ? 'tercapai' : node.inAttack ? 'belum' : 'normal'}>
            <rect x={x - NODE.width / 2} y={y - NODE.height / 2} width={NODE.width} height={NODE.height} rx={8} fill={hitOt ? '#3B1215' : hit ? '#2A1A1C' : '#131720'} stroke={isBlocked ? '#657080' : hit ? '#EF4444' : node.inAttack ? '#272E3A' : '#22C55E'} strokeOpacity={!node.inAttack ? 0.6 : 1} strokeDasharray={isBlocked ? '5 4' : undefined} />
            <text x={x} y={y + 4} textAnchor="middle" fontSize={11} fontFamily="ui-monospace,monospace" fill={hit ? '#F3F5F7' : isBlocked ? '#657080' : node.inAttack ? '#596474' : '#AEB6C1'} textDecoration={isBlocked ? 'line-through' : undefined}>{clip(node.label)}</text>
            <title>{node.label}</title>
          </g>
        })}

        {(setpoint || run) && <g data-testid="process-node" data-state={harmed ? 'terganggu' : 'normal'}>
          <path d={`M${COLUMN.plc + NODE.width / 2} ${processY}L${PROCESS_X - 62} ${processY}`} stroke={harmed ? '#EF4444' : '#22C55E'} strokeOpacity={harmed ? 1 : 0.6} strokeWidth={harmed ? 2 : 1.5} markerEnd={harmed ? 'url(#arrow-bad)' : 'url(#arrow-good)'} />
          <rect x={PROCESS_X - 62} y={processY - 44} width={124} height={88} rx={10} fill={harmed ? '#3B1215' : '#0F2018'} stroke={harmed ? '#EF4444' : '#22C55E'} />
          <text x={PROCESS_X} y={processY - 20} textAnchor="middle" fontSize={10} fill="#AEB6C1">{runningNow === false ? 'BERHENTI' : runningNow === true ? 'MENYALA' : 'STATUS ?'}</text>
          <text x={PROCESS_X} y={processY + 8} textAnchor="middle" fontSize={22} fontWeight={600} fontFamily="ui-monospace,monospace" fill="#F3F5F7">{setpointNow ?? '—'}{unit}</text>
          <text x={PROCESS_X} y={processY + 28} textAnchor="middle" fontSize={9} fill="#8D97A6">{setpoint?.label ?? ''}</text>
        </g>}
      </svg>
    </div>
    {shownOut > 0 && <p className="mt-1 text-[10px] text-[#657080]">{shownOut} simpul lain tidak digambar agar peta tetap terbaca.</p>}

    <div className="mt-3 flex items-center gap-2">
      <button aria-label="Momen sebelumnya" onClick={() => { setPlaying(false); setIndex(Math.max(0, index - 1)) }} className="grid size-9 shrink-0 place-items-center rounded-lg border border-[#272E3A] text-[#AEB6C1] hover:text-white"><ChevronLeft size={15} /></button>
      <button data-testid="replay-play" onClick={() => { if (index >= last) setIndex(0); setPlaying(!playing) }} className="flex h-9 shrink-0 items-center gap-1.5 rounded-lg bg-[#38BDF8] px-3 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]">{playing ? <Pause size={14} /> : <Play size={14} />}{playing ? 'Jeda' : 'Putar'}</button>
      <button aria-label="Momen berikutnya" onClick={() => { setPlaying(false); setIndex(Math.min(last, index + 1)) }} className="grid size-9 shrink-0 place-items-center rounded-lg border border-[#272E3A] text-[#AEB6C1] hover:text-white"><ChevronRight size={15} /></button>
      <input aria-label="Momen serangan" data-testid="replay-slider" type="range" min={0} max={last} value={Math.min(index, last)} onChange={(e) => { setPlaying(false); setIndex(Number(e.target.value)) }} className="h-9 min-w-0 flex-1 accent-[#38BDF8]" />
      <span className="shrink-0 font-mono text-[11px] text-[#AEB6C1]">{Math.min(index, last) + 1}/{moments.length}</span>
    </div>

    <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <div data-testid="replay-moment" className={`min-w-0 rounded-lg border p-3 ${current.kind === 'proses' ? 'border-[#F59E0B]/40 bg-[#F59E0B]/5' : 'border-[#272E3A] bg-[#0D1016]'}`}>
        <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-[#8D97A6]"><span>{fmtDate(t)} · {fmtTime(t, false)} WIB</span>{current.level && <Badge className={levelStyle[current.level]}>{LEVEL_LABEL[current.level]}</Badge>}{current.kind === 'proses' && <Badge className="border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FBBF24]">PROSES FISIK</Badge>}{avoidedMoment(current.nodes) && <Badge className="border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]">TERHINDAR</Badge>}</div>
        <p className={`mt-1.5 text-sm leading-5 ${avoidedMoment(current.nodes) ? 'text-[#8D97A6] line-through' : 'text-[#F3F5F7]'}`}>{current.title}</p>
        {current.detectionId && <button onClick={() => openDetail(current.detectionId!)} className="mt-1 text-[11px] text-[#7DD3FC] hover:text-white">Lihat buktinya →</button>}
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-lg bg-[#0D1016] p-3"><Label>{setpoint?.label ?? 'Nilai'}</Label><div className="font-mono text-lg">{setpointNow ?? '—'}{unit}</div>{setpoint?.band && <div className="mt-0.5 text-[10px] text-[#657080]">batas {setpoint.band.min}–{setpoint.band.max}{unit}</div>}</div>
        <div className="rounded-lg bg-[#0D1016] p-3"><Label>{measured?.label ?? 'Status'}</Label><div className="font-mono text-lg">{measured ? `${measuredNow ?? '—'}${measured.unit ? ` ${measured.unit}` : ''}` : runningNow === false ? 'Berhenti' : runningNow ? 'Menyala' : '—'}</div></div>
      </div>
    </div>

    {selected ? <div data-testid="cut-result" className={`mt-3 flex gap-2 rounded-lg border p-3 text-xs leading-5 ${selected.result.protectsOt ? 'border-[#22C55E]/30 bg-[#22C55E]/5 text-[#C3E9D2]' : 'border-[#F59E0B]/30 bg-[#F59E0B]/5 text-[#FCD34D]'}`}>
      {selected.result.protectsOt ? <ShieldCheck size={15} className="mt-0.5 shrink-0 text-[#22C55E]" /> : <TriangleAlert size={15} className="mt-0.5 shrink-0" />}
      <span><b>{selected.label}:</b> {selected.result.protectsOt ? 'jalur yang tercatat tidak lagi sampai ke perangkat OT.' : 'jalur yang tercatat masih sampai ke perangkat OT.'} {selected.result.avoided} dari {selected.result.total} temuan bergantung pada jalur ini.{selected.result.deadline !== undefined && <> Harus berlaku sebelum {fmtTime(selected.result.deadline, false)} WIB{selected.result.leadMs ? `, ${fmtSpan(selected.result.leadMs)} setelah temuan pertama` : ''}.</>}</span>
    </div> : <p className="mt-3 text-[11px] leading-5 text-[#8D97A6]">Pilih salah satu tindakan di atas untuk memutar ulang serangan seolah tindakan itu sudah dilakukan.</p>}
    <p className="mt-2 text-[10px] leading-4 text-[#657080]">Uji ini memakai jalur yang tercatat di log. Penyerang bisa memiliki jalur lain yang tidak tercatat, jadi hasilnya perkiraan, bukan jaminan.</p>
  </Card>
}
