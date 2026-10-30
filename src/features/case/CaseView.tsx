import { useEffect, useRef, useState } from 'react'
import { Activity, ArrowRight, ClipboardList, FileSearch, FileText, GitBranch, History, ShieldAlert, StickyNote, Upload, UserRound } from 'lucide-react'
import { ScoreBreakdown } from '@/components/ScoreBreakdown'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import type { Case, CaseStatus, Detection, FollowUpStatus } from '@/core/model'
import { incidentStory, incidentSummary, scorePercent } from '@/core/report/narrative'
import { setAssignee, setCaseStatus, setNotes } from '@/db/cases'
import { orderedCases, type Investigation } from '@/db/hooks'
import { RULES } from '@/data/rules/catalog'
import { fmtDate, fmtDateTime, fmtNumber, fmtTime } from '@/lib/format'
import { CASE_STATUS_LABEL, KIND_LABEL, LEVEL_LABEL, LEVEL_RANK, caseStatusStyle, levelStyle } from '@/lib/styles'

type Props = {
  data: Investigation
  caseId: string | null
  selectCase: (id: string) => void
  actor: string
  notify: (message: string) => void
  changeFollowUp: (caseId: string, detection: Detection, status: FollowUpStatus) => void
  openDetail: (detectionId: string) => void
  openGraph: (incidentId: string) => void
  openReport: (caseId: string) => void
  openImport: () => void
}

const STATUSES: CaseStatus[] = ['Open', 'Investigating', 'Resolved']
const FOLLOW_UPS: FollowUpStatus[] = ['Baru', 'Berjalan', 'Selesai']

export function CaseView({ data, caseId, selectCase, actor, notify, changeFollowUp, openDetail, openGraph, openReport, openImport }: Props) {
  const list = orderedCases(data)
  const current = list.find((x) => x.c.id === caseId) ?? list[0]

  if (!current) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]"><Upload size={22} /></div><h1 className="text-lg font-semibold">Belum ada kasus</h1><p className="mt-2 text-sm text-[#7E8998]">Kasus dibuat otomatis untuk setiap insiden yang terdeteksi. Impor log atau muat skenario contoh.</p><button onClick={openImport} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Impor Data</button></div></div>
  }

  const { c, incident } = current
  const incidents = data.incidents.filter((i) => i.caseId === c.id)
  const dets = incidents.flatMap((i) => i.detectionIds).map((id) => data.detectionsById.get(id)).filter((d): d is Detection => !!d).sort((a, b) => a.ts - b.ts)
  const steps = incident ? incidentStory(incident, data.detectionsById, data.eventsById) : []
  const done = dets.filter((d) => c.followUps[d.id] === 'Selesai').length
  const stepsTotal = dets.reduce((n, d) => n + (RULES.get(d.ruleId)?.respons.length ?? 0), 0)
  const stepsDone = Object.entries(c.playbookProgress).filter(([key, v]) => v && dets.some((d) => key.startsWith(`${d.id}#`))).length
  const name = (key: string) => incident?.entities.find((e) => e.key === key)?.value ?? key
  const users = incident?.entities.filter((e) => e.type === 'user').map((e) => e.value) ?? []
  const shared = incident?.entities.filter((e) => e.type !== 'file' && e.detectionIds.length > 1 && (!e.common || e.actor)).sort((a, b) => b.detectionIds.length - a.detectionIds.length).slice(0, 4) ?? []
  const files = new Set(dets.flatMap((d) => d.eventIds).map((id) => data.eventsById.get(id)?.importId).filter(Boolean)).size

  return <div className="mx-auto max-w-[1600px]">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow={`Kasus / ${c.id}`} title={c.title} text={incident ? incident.path.map(name).join(' → ') || 'Satu aset' : 'Insiden tidak ditemukan'} /><div className="flex flex-wrap gap-2">{incident && <Badge className={levelStyle[incident.level]}>{LEVEL_LABEL[incident.level].toUpperCase()} · {scorePercent(incident.score)}%</Badge>}<Badge className={caseStatusStyle[c.status]}>{CASE_STATUS_LABEL[c.status].toUpperCase()}</Badge></div></div>

    <div className={`grid grid-cols-1 gap-4 ${list.length > 1 ? 'xl:grid-cols-[260px_minmax(0,1fr)]' : ''}`}>
      {list.length > 1 && <aside className="space-y-2 xl:sticky xl:top-20 xl:self-start"><Label>Antrean kasus ({list.length})</Label>{list.map(({ c: x, incident: inc }) => <button key={x.id} onClick={() => selectCase(x.id)} className={`w-full rounded-lg border p-3 text-left transition ${x.id === c.id ? 'border-[#38BDF8]/50 bg-[#38BDF8]/5' : 'border-[#272E3A] bg-[#131720] hover:border-[#3A4554]'}`}><div className="flex items-center justify-between gap-2"><span className="font-mono text-[11px] text-[#7DD3FC]">{x.id}</span><Badge className={caseStatusStyle[x.status]}>{CASE_STATUS_LABEL[x.status]}</Badge></div><div className="mt-1.5 line-clamp-2 text-xs font-medium">{x.title}</div><div className="mt-1 font-mono text-[10px] text-[#657080]">{inc ? `${scorePercent(inc.score)}% · ${inc.detectionIds.length} temuan · ${fmtTime(inc.firstSeen, false)}` : '—'}</div></button>)}</aside>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.2fr_.8fr]">
        <div className="space-y-4">
          <Card title="Detail Kasus" icon={<ClipboardList size={16} className="text-[#38BDF8]" />}>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">{[
              ['ID kasus', c.id],
              ['Dibuat', fmtDateTime(c.createdAt)],
              ['Rentang kejadian', incident ? `${fmtDate(incident.firstSeen)} · ${fmtTime(incident.firstSeen, false)}–${fmtTime(incident.lastSeen, false)} WIB` : '—'],
              ['Sumber log', incident?.sourceKinds.map((k) => KIND_LABEL[k]).join(', ') || '—'],
              ['Aset', incident?.path.map(name).join(', ') || '—'],
              ['Akun terlibat', users.join(', ') || '—'],
            ].map(([a, b]) => <div key={a} className="min-w-0"><Label>{a}</Label><div className="break-words font-mono text-xs text-[#D1D6DD]">{b}</div></div>)}</div>
            {incident && <div className="mt-5"><Label>Ringkasan</Label><p className="text-sm leading-6 text-[#AEB6C1]">{incidentSummary(incident, steps)}</p></div>}
          </Card>
          <NotesCard key={c.id} c={c} actor={actor} />
          {incident && <Card title="Batas Kesimpulan" icon={<ShieldAlert size={16} className="text-[#F59E0B]" />}><div className="grid grid-cols-1 gap-3 md:grid-cols-3">{[
            ['FAKTA', `${fmtNumber(dets.reduce((n, d) => n + d.eventIds.length, 0))} event dari ${files} berkas log memicu ${incident.ruleIds.length} aturan deteksi pada ${incident.path.map(name).join(', ') || 'aset terkait'}.`, '#22C55E'],
            ['INDIKASI', shared.length ? `Temuan saling terhubung melalui ${shared.map((e) => `${e.value} (${e.detectionIds.length} temuan)`).join(', ')} dalam rentang 24 jam.` : 'Temuan berdiri sendiri; belum ada entitas bersama.', '#F59E0B'],
            ['HIPOTESIS', steps.length > 1 ? `Rangkaian kemungkinan berawal dari "${steps[0].detections[0].title}" dan berlanjut hingga tahap ${steps.at(-1)!.label.toLowerCase()}. Perlu konfirmasi forensik.` : 'Perlu pemeriksaan manual untuk menentukan penyebab.', '#38BDF8'],
          ].map(([a, b, color]) => <div key={a} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><div className="mb-2 text-[10px] font-bold" style={{ color }}>{a}</div><p className="text-xs leading-5 text-[#8D97A6]">{b}</p></div>)}</div></Card>}
          <Card title={`Temuan dalam Kasus (${dets.length})`} icon={<FileSearch size={16} className="text-[#EF4444]" />}>
            <div className="overflow-x-auto"><table className="w-full min-w-[560px] text-left text-xs"><thead className="text-[9px] uppercase tracking-wider text-[#657080]"><tr className="border-b border-[#272E3A]">{['Waktu', 'Temuan', 'Tingkat', 'Tindak lanjut'].map((h) => <th key={h} className="pb-2 pr-3">{h}</th>)}</tr></thead>
              <tbody>{[...dets].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts).map((d) => <tr key={d.id} className="border-b border-[#1D232D] last:border-0"><td className="py-2 pr-3 font-mono text-[11px] text-[#AEB6C1]">{fmtTime(d.ts, false)}</td><td className="max-w-[320px] pr-3"><button onClick={() => openDetail(d.id)} className="truncate text-left hover:text-[#7DD3FC]">{d.title}</button></td><td className="pr-3"><Badge className={levelStyle[d.level]}>{LEVEL_LABEL[d.level]}</Badge></td><td><select aria-label={`Tindak lanjut ${d.title}`} value={c.followUps[d.id] ?? 'Baru'} onChange={(e) => changeFollowUp(c.id, d, e.target.value as FollowUpStatus)} className="rounded border border-[#272E3A] bg-[#0D1016] px-2 py-1 text-[11px]">{FOLLOW_UPS.map((s) => <option key={s}>{s}</option>)}</select></td></tr>)}</tbody></table></div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="Status Kasus" icon={<Activity size={16} className="text-[#22C55E]" />}>
            <Label>Tahap penanganan</Label>
            <div className="grid grid-cols-3 gap-2">{STATUSES.map((s) => <button key={s} onClick={() => { void setCaseStatus(c.id, s, actor); notify(`${c.id}: status ${CASE_STATUS_LABEL[s]}`) }} className={`rounded-lg border px-2 py-2 text-[11px] font-semibold ${c.status === s ? 'border-[#38BDF8] bg-[#38BDF8]/10 text-[#7DD3FC]' : 'border-[#272E3A] text-[#7E8998] hover:text-white'}`}>{CASE_STATUS_LABEL[s]}</button>)}</div>
            <AssigneeField key={c.id} c={c} actor={actor} notify={notify} />
            <div className="mt-4 grid grid-cols-2 gap-2">{[['Tindak lanjut selesai', `${done}/${dets.length}`], ['Langkah respons', `${stepsDone}/${stepsTotal}`]].map(([a, b]) => <div key={a} className="rounded-lg bg-[#0D1016] p-3"><div className="text-[9px] uppercase text-[#657080]">{a}</div><div className="mt-1 font-mono text-lg">{b}</div></div>)}</div>
            <div className="mt-4 grid grid-cols-2 gap-2">{incident && <button onClick={() => openGraph(incident.id)} className="flex items-center justify-center gap-2 rounded-lg border border-[#272E3A] bg-[#191F2A] py-2 text-xs font-semibold hover:border-[#38BDF8]/40"><GitBranch size={13} />Graf</button>}<button onClick={() => openReport(c.id)} className="flex items-center justify-center gap-2 rounded-lg bg-[#38BDF8] py-2 text-xs font-bold text-[#071018]"><FileText size={13} />Laporan</button></div>
            <p className="mt-3 text-[10px] leading-4 text-[#657080]">Tersimpan di IndexedDB browser ini dan tetap ada setelah impor log tambahan.</p>
          </Card>
          {incident && <Card title="Mengapa skor ini?" icon={<ShieldAlert size={16} className="text-[#F59E0B]" />}><ScoreBreakdown incident={incident} limit={5} /></Card>}
          <Card title="Riwayat Penanganan" icon={<History size={16} className="text-[#38BDF8]" />}>
            <ol className="max-h-80 space-y-2 overflow-y-auto">{[...c.history].reverse().map((h, i) => <li key={i} className="flex gap-3 text-xs"><span className="w-[70px] shrink-0 font-mono text-[10px] text-[#657080]">{fmtTime(h.ts, false)}<br />{fmtDate(h.ts)}</span><span className="min-w-0 flex-1"><span className="text-[#C3CAD3]">{h.text}</span><span className="mt-0.5 flex items-center gap-1 text-[10px] text-[#657080]"><UserRound size={10} />{h.actor}</span></span></li>)}</ol>
          </Card>
          {incidents.length > 1 && <p className="flex items-center gap-1 text-[10px] text-[#657080]"><ArrowRight size={11} />Kasus ini mencakup {incidents.length} insiden.</p>}
        </div>
      </div>
    </div>
  </div>
}

function NotesCard({ c, actor }: { c: Case; actor: string }) {
  const [text, setText] = useState(c.notes)
  const [saved, setSaved] = useState(true)
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => () => window.clearTimeout(timer.current), [])
  const change = (value: string) => {
    setText(value)
    setSaved(false)
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => void setNotes(c.id, value, actor).then(() => setSaved(true)), 500)
  }
  return <Card title="Catatan Analis" icon={<StickyNote size={16} className="text-[#F59E0B]" />}><textarea value={text} maxLength={2000} onChange={(e) => change(e.target.value)} className="min-h-32 w-full resize-y rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-sm leading-6 outline-none focus:border-[#38BDF8]/50" placeholder="Tambahkan catatan investigasi: apa yang sudah diperiksa, siapa yang dihubungi, keputusan komandan…" /><div className="mt-2 flex items-center justify-between text-[10px] text-[#657080]"><span>{saved ? 'Tersimpan otomatis di browser ini' : 'Menyimpan…'}</span><span>{text.length}/2000</span></div></Card>
}

function AssigneeField({ c, actor, notify }: { c: Case; actor: string; notify: (m: string) => void }) {
  const [value, setValue] = useState(c.assignee)
  const save = () => {
    if (value.trim() === c.assignee) return
    void setAssignee(c.id, value, actor)
    notify(value.trim() ? `${c.id} ditugaskan kepada ${value.trim()}` : `Penugasan ${c.id} dikosongkan`)
  }
  return <div className="mt-4"><Label>Petugas penanganan</Label><input value={value} onChange={(e) => setValue(e.target.value)} onBlur={save} onKeyDown={(e) => e.key === 'Enter' && (e.target as HTMLInputElement).blur()} maxLength={80} placeholder="Nama / pangkat petugas" className="h-9 w-full rounded-lg border border-[#272E3A] bg-[#0D1016] px-3 text-xs outline-none focus:border-[#38BDF8]/60" /></div>
}
