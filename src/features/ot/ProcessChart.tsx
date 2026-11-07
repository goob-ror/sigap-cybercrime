import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'
import type { OtRun, OtSeries, OtWrite } from '@/core/ot/analysis'
import { fmtSpan, fmtTime } from '@/lib/format'

const HEIGHT = 210
const MARGIN = { top: 18, right: 18, bottom: 26, left: 42 }
const SURFACE = '#131720'
const GRID = '#1D232D'
const LINE = '#38BDF8'
const GOOD = '#22C55E'
const BAD = '#EF4444'

function niceTicks(min: number, max: number, count = 4): number[] {
  const span = max - min || 1
  const raw = span / count
  const power = 10 ** Math.floor(Math.log10(raw))
  const step = [1, 2, 5, 10].map((m) => m * power).find((s) => s >= raw) ?? raw
  const ticks: number[] = []
  for (let v = Math.ceil(min / step) * step; v <= max + 1e-9; v += step) ticks.push(Math.round(v * 1000) / 1000)
  return ticks
}

function timeTicks(from: number, to: number, width: number): number[] {
  const wanted = Math.max(2, Math.floor(width / 90))
  const step = [15, 30, 60, 120, 180, 240, 360, 720, 1440].map((m) => m * 60_000).find((s) => (to - from) / s <= wanted) ?? 1440 * 60_000
  const ticks: number[] = []
  for (let t = Math.ceil(from / step) * step; t <= to; t += step) ticks.push(t)
  return ticks
}

/** Value over time: one series, one axis. Writes are drawn on it, and the safe range behind it. */
export function ProcessChart({ series, writes, domain }: { series: OtSeries; writes: OtWrite[]; domain: [number, number] }) {
  const box = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(720)
  const [active, setActive] = useState<number | null>(null)

  useEffect(() => {
    const el = box.current
    if (!el) return
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(280, entry.contentRect.width)))
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const unit = series.unit ? ` ${series.unit}` : ''
  const own = useMemo(() => writes.filter((w) => w.dst === series.device && w.address === series.address && w.kind === 'register'), [writes, series])

  const { x, y, yTicks, path } = useMemo(() => {
    const values = series.points.map(([, v]) => v)
    if (series.band) values.push(series.band.min, series.band.max)
    const low = Math.min(...values)
    const high = Math.max(...values)
    const pad = Math.max(1, (high - low) * 0.1)
    const yMin = low - pad
    const yMax = high + pad
    const [from, to] = domain
    const xOf = (t: number) => MARGIN.left + ((t - from) / (to - from || 1)) * (width - MARGIN.left - MARGIN.right)
    const yOf = (v: number) => MARGIN.top + (1 - (v - yMin) / (yMax - yMin)) * (HEIGHT - MARGIN.top - MARGIN.bottom)
    // A setpoint holds until it is changed, so it steps. A measurement moves between readings.
    const stepped = series.kind !== 'terukur'
    let d = ''
    series.points.forEach(([t, v], i) => {
      if (i === 0) d = `M${xOf(t).toFixed(1)} ${yOf(v).toFixed(1)}`
      else if (stepped) d += `H${xOf(t).toFixed(1)}V${yOf(v).toFixed(1)}`
      else d += `L${xOf(t).toFixed(1)} ${yOf(v).toFixed(1)}`
    })
    return { x: xOf, y: yOf, yTicks: niceTicks(yMin, yMax), path: d }
  }, [series, domain, width])

  const nearest = (clientX: number, left: number) => {
    const t = domain[0] + ((clientX - left - MARGIN.left) / (width - MARGIN.left - MARGIN.right)) * (domain[1] - domain[0])
    let best = 0
    series.points.forEach(([ts], i) => { if (Math.abs(ts - t) < Math.abs(series.points[best][0] - t)) best = i })
    return best
  }
  const onMove = (e: PointerEvent<HTMLDivElement>) => setActive(nearest(e.clientX, e.currentTarget.getBoundingClientRect().left))
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return
    e.preventDefault()
    const delta = e.key === 'ArrowLeft' ? -1 : 1
    setActive((i) => Math.max(0, Math.min(series.points.length - 1, (i ?? (delta > 0 ? -1 : series.points.length)) + delta)))
  }

  const point = active !== null ? series.points[active] : null
  // Only the command that set this value: the reading just before a command is not its result.
  const nearWrite = point ? own.find((w) => w.value === point[1] && Math.abs(w.ts - point[0]) < 90_000) : undefined
  const firstBad = own.find((w) => !w.trusted)
  const inner = HEIGHT - MARGIN.top - MARGIN.bottom

  return <div ref={box} className="relative" data-testid="process-chart">
    <div role="img" tabIndex={0} aria-label={`${series.label} pada ${series.deviceName}${series.band ? `, batas ${series.band.min} sampai ${series.band.max}${unit}` : ''}${series.outOfBandMs ? `, di luar batas selama ${fmtSpan(series.outOfBandMs)}` : ''}. Tekan panah kiri atau kanan untuk membaca nilainya.`} onPointerMove={onMove} onPointerLeave={() => setActive(null)} onKeyDown={onKey} onBlur={() => setActive(null)} className="cursor-crosshair rounded outline-none focus-visible:ring-1 focus-visible:ring-[#38BDF8]">
      <svg width={width} height={HEIGHT} className="block">
        {yTicks.map((tick) => <g key={tick}><line x1={MARGIN.left} x2={width - MARGIN.right} y1={y(tick)} y2={y(tick)} stroke={GRID} /><text x={MARGIN.left - 8} y={y(tick) + 3} textAnchor="end" fontSize={10} fill="#657080" fontFamily="ui-monospace,monospace">{tick}</text></g>)}
        {timeTicks(domain[0], domain[1], width).map((t) => <text key={t} x={x(t)} y={HEIGHT - 8} textAnchor="middle" fontSize={10} fill="#657080" fontFamily="ui-monospace,monospace">{fmtTime(t, false).slice(0, 5)}</text>)}
        {series.band && <rect x={MARGIN.left} width={width - MARGIN.left - MARGIN.right} y={y(series.band.max)} height={Math.max(1, y(series.band.min) - y(series.band.max))} fill={GOOD} opacity={0.08} />}
        {series.episodes.map((ep) => <rect key={ep.from} x={x(ep.from)} width={Math.max(2, x(ep.to) - x(ep.from))} y={MARGIN.top} height={inner} fill={BAD} opacity={0.1} />)}
        <path d={path} fill="none" stroke={LINE} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {own.map((w) => w.trusted
          ? <circle key={w.eventId} cx={x(w.ts)} cy={y(w.value)} r={4} fill={GOOD} stroke={SURFACE} strokeWidth={2} />
          : <path key={w.eventId} d={`M${x(w.ts)} ${y(w.value) - 6}l6 6l-6 6l-6-6Z`} fill={BAD} stroke={SURFACE} strokeWidth={2} />)}
        {firstBad && <text x={x(firstBad.ts) + (x(firstBad.ts) > width * 0.72 ? -10 : 10)} y={y(firstBad.value) - 8} textAnchor={x(firstBad.ts) > width * 0.72 ? 'end' : 'start'} fontSize={11} fill="#F3F5F7">{firstBad.value}{unit} · {firstBad.srcName}</text>}
        {point && <line x1={x(point[0])} x2={x(point[0])} y1={MARGIN.top} y2={MARGIN.top + inner} stroke="#657080" />}
        {point && <circle cx={x(point[0])} cy={y(point[1])} r={4} fill={LINE} stroke={SURFACE} strokeWidth={2} />}
      </svg>
    </div>
    {point && <div role="status" className="pointer-events-none absolute top-2 z-10 rounded-lg border border-[#374151] bg-[#0D1016] px-3 py-2 text-[11px] shadow-xl" style={x(point[0]) > width * 0.6 ? { right: width - x(point[0]) + 10 } : { left: x(point[0]) + 10 }}>
      <div className="font-mono text-sm font-semibold text-white">{point[1]}{unit}</div>
      <div className="font-mono text-[10px] text-[#8D97A6]">{fmtTime(point[0], false)} WIB</div>
      {nearWrite && <div className="mt-1 max-w-[220px] text-[10px] text-[#AEB6C1]">Ditulis oleh {nearWrite.srcName}{nearWrite.trusted ? '' : ' (tidak berwenang)'}</div>}
    </div>}
  </div>
}

/** Running or stopped, along the same time axis as the charts. */
export function RunStrip({ run, domain }: { run: OtRun; domain: [number, number] }) {
  const total = domain[1] - domain[0] || 1
  return <div data-testid="run-strip">
    <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded">{run.spans.map((s) => <div key={s.from} title={`${s.running ? 'Menyala' : 'Berhenti'} · ${fmtTime(s.from, false)}–${fmtTime(s.to, false)} WIB · ${fmtSpan(s.to - s.from)}`} className={s.running ? 'bg-[#2A3341]' : 'bg-[#EF4444]'} style={{ flexGrow: Math.max((s.to - s.from) / total, 0.004), flexBasis: 0 }} />)}</div>
    <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-[#8D97A6]"><span><i className="mr-1 inline-block size-2 rounded-sm bg-[#2A3341]" />Menyala</span><span><i className="mr-1 inline-block size-2 rounded-sm bg-[#EF4444]" />Berhenti{run.stoppedMs ? ` · total ${fmtSpan(run.stoppedMs)}` : ''}</span></div>
  </div>
}
