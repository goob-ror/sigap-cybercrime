import { useEffect, useState } from 'react'
import { CircleCheck, CircleX, Download, FileCheck2, ShieldAlert, ShieldCheck, TriangleAlert, Upload } from 'lucide-react'
import { AssessmentBadge } from '@/components/AssessmentBadge'
import { entityTypeLabel, isIndicator } from '@/components/EntityIcon'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { Label } from '@/components/ui/Label'
import { PageTitle } from '@/components/ui/PageTitle'
import { Select } from '@/components/ui/Select'
import type { Detection, NormalizedEvent, UnitProfile } from '@/core/model'
import { sha256Hex } from '@/core/evidence/hash'
import { otSummaryLines } from '@/core/ot/analysis'
import { buildCustodyChain, buildEvidenceFiles, coverageLines, renderManifest, verifyEvidencePackage, type EvidenceInput, type EvidenceVerification } from '@/core/evidence/package'
import { keyFingerprint, signPackage, SIGNATURE_FILE } from '@/core/evidence/signing'
import { ASSESSMENT, assessmentOf, incidentStory, incidentSummary, priorityActions, scorePercent } from '@/core/report/narrative'
import { db, type BlobRow } from '@/db/db'
import { orderedCases, type Investigation } from '@/db/hooks'
import { signingKey } from '@/db/settings'
import { RULES } from '@/data/rules/catalog'
import { fmtDate, fmtDateTime, fmtNumber, fmtTime } from '@/lib/format'
import { CASE_STATUS_LABEL, LEVEL_LABEL, LEVEL_RANK, levelStyle } from '@/lib/styles'
import type { LogAnalysis } from '@/workers/protocol'

type Props = {
  data: Investigation
  caseId: string | null
  selectCase: (id: string) => void
  actor: string
  profile: UnitProfile
  notify: (message: string) => void
  openImport: () => void
}

const decimal = (n: number) => n.toFixed(2).replace('.', ',')

export function ReportView({ data, caseId, selectCase, actor, profile, notify, openImport }: Props) {
  const list = orderedCases(data)
  const current = list.find((x) => x.c.id === caseId) ?? list[0]
  const [verify, setVerify] = useState<EvidenceVerification | null>(null)
  const [evidenceBusy, setEvidenceBusy] = useState(false)
  const [includeProfile, setIncludeProfile] = useState(false)
  const [ownFingerprint, setOwnFingerprint] = useState<string | null>(null)
  useEffect(() => {
    signingKey().then(keyFingerprint).then(setOwnFingerprint, () => setOwnFingerprint(null))
  }, [])
  if (!current?.incident) {
    return <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center"><div><div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#272E3A] bg-[#131720] text-[#7DD3FC]"><Upload size={22} /></div><h1 className="text-lg font-semibold">Belum ada kasus untuk dilaporkan</h1><p className="mt-2 text-sm text-[#7E8998]">Laporan disusun dari data kasus. Impor log atau muat skenario contoh.</p><button onClick={openImport} className="mt-5 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Buka Impor Data</button></div></div>
  }

  const { c, incident } = current
  const dets = incident.detectionIds.map((id) => data.detectionsById.get(id)).filter((d): d is Detection => !!d)
  const steps = incidentStory(incident, data.detectionsById, data.eventsById)
  const actions = priorityActions(incident, data.detectionsById, RULES, 8)
  const ordered = [...dets].sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.ts - b.ts)
  const entities = incident.entities.filter((e) => e.type !== 'file' || e.detectionIds.length > 0)
  const importIds = new Set(dets.flatMap((d) => d.eventIds).map((id) => data.eventsById.get(id)?.importId))
  const sources = data.imports.filter((a) => importIds.has(a.id.replace(/^log-/, '')))
  const name = (key: string) => incident.entities.find((e) => e.key === key)?.value ?? key
  const options = list.map(({ c: x }) => `${x.id} · ${x.title}`)
  const generated = Date.now()

  const caseEvents = [...new Map(dets.flatMap((d) => d.eventIds).map((id) => data.eventsById.get(id)).filter((e): e is NormalizedEvent => !!e).map((e) => [e.id, e])).values()]
  const buildInput = (): EvidenceInput => ({ case: c, incident, detections: dets, events: caseEvents, sources, actor, profile, ot: data.ot, includeProfile, coverage: data.coverage, generatedAt: Date.now() })

  const exportEvidence = async () => {
    setEvidenceBusy(true)
    try {
      const input = buildInput()
      const content = buildEvidenceFiles(input)
      const importIds = [...new Set(sources.map((a) => a.id.replace(/^log-/, '')))]
      const originals = (await db.blobs.bulkGet(importIds)).filter((b): b is BlobRow => !!b).map((b) => ({ name: `asli/${b.name}`, bytes: b.bytes }))
      const entries = [
        ...(await Promise.all(content.map(async (f) => ({ name: f.name, hash: await sha256Hex(f.text) })))),
        ...(await Promise.all(originals.map(async (o) => ({ name: o.name, hash: await sha256Hex(o.bytes) })))),
      ]
      const manifest = renderManifest(entries)
      const total = content.length + originals.length + 3
      const log = await db.custody.orderBy('seq').toArray()
      const chain = await buildCustodyChain({ ...input, custodyLog: log }, await sha256Hex(manifest), total)
      const chainText = JSON.stringify(chain, null, 2)
      const signature = await signPackage(await signingKey(), manifest, chainText, new Date(input.generatedAt).toISOString())
      const { default: JSZip } = await import('jszip')
      const zip = new JSZip()
      for (const f of content) zip.file(f.name, f.text)
      for (const o of originals) zip.file(o.name, o.bytes)
      zip.file('rantai-bukti.json', chainText)
      zip.file('MANIFEST-SHA256.txt', manifest)
      zip.file(SIGNATURE_FILE, JSON.stringify(signature, null, 2))
      const url = URL.createObjectURL(await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' }))
      const a = Object.assign(document.createElement('a'), { href: url, download: `sigap-bukti-${c.id}.zip` })
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 10_000)
      // The export is part of the record from here on, so the next package shows this one.
      await db.custody.bulkPut(chain.slice(log.length))
      notify(`Paket bukti ${c.id} diekspor (${total} berkas, ${originals.length} berkas asli). ZIP tidak terenkripsi: simpan pada media terenkripsi.`)
    } catch (err) {
      notify(`Gagal mengekspor paket bukti: ${(err as Error).message}`)
    } finally {
      setEvidenceBusy(false)
    }
  }

  const verifyPackage = async (file: File) => {
    setVerify(null)
    setEvidenceBusy(true)
    try {
      const { default: JSZip } = await import('jszip')
      const zip = await JSZip.loadAsync(await file.arrayBuffer())
      const files = await Promise.all(Object.values(zip.files).filter((f) => !f.dir).map(async (f) => ({ name: f.name, bytes: await f.async('uint8array') })))
      setVerify(await verifyEvidencePackage(files))
    } catch (err) {
      notify(`Gagal memverifikasi paket: ${(err as Error).message}`)
    } finally {
      setEvidenceBusy(false)
    }
  }

  return <div className="mx-auto max-w-6xl">
    <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end"><PageTitle eyebrow={`Kasus ${c.id}`} title="Laporan Insiden" text="Disusun otomatis dari data kasus: temuan, korelasi, skor, tindak lanjut, dan catatan. Cetak atau simpan sebagai PDF untuk eskalasi." /><div className="flex flex-wrap gap-2">{list.length > 1 && <Select value={options[list.indexOf(current)]} setValue={(v) => { const i = options.indexOf(v); if (i >= 0) selectCase(list[i].c.id) }} options={options} />}<button onClick={() => void exportEvidence()} disabled={evidenceBusy} className="flex items-center justify-center gap-2 rounded-lg border border-[#272E3A] bg-[#191F2A] px-4 py-2.5 text-xs font-semibold hover:border-[#38BDF8]/40 disabled:opacity-50"><ShieldCheck size={15} />Paket Bukti</button><button onClick={() => { notify('Dialog cetak dibuka — pilih "Simpan sebagai PDF"'); window.setTimeout(() => window.print(), 300) }} className="flex items-center justify-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2.5 text-xs font-bold text-[#071018]"><Download size={15} />Ekspor PDF</button></div></div>
    <div className="mb-3 flex justify-end print:hidden"><label className="flex items-center gap-2 text-[11px] text-[#8D97A6]"><input type="checkbox" checked={includeProfile} onChange={(e) => setIncludeProfile(e.target.checked)} />Sertakan profil jaringan satuan dalam paket bukti (berisi peta jaringan; ZIP tidak terenkripsi)</label></div>
    <article className="report overflow-hidden rounded-xl border border-[#272E3A] bg-[#131720]">
      {profile.reportMarking && <div className="border-b border-[#272E3A] py-2 text-center text-xs font-bold tracking-widest">{profile.reportMarking}</div>}
      <div className="border-b border-[#272E3A] bg-[#191F2A] p-6 md:p-8">
        <div className="mb-8 flex items-start justify-between gap-4"><div className="flex items-center gap-3"><div className="grid size-10 place-items-center rounded-lg bg-[#38BDF8] text-[#071018]"><ShieldAlert /></div><div><div className="font-bold tracking-[0.18em]">SIGAP</div><div className="text-[10px] text-[#7E8998]">LAPORAN ANALISIS INSIDEN SIBER</div></div></div>{data.check && <Badge className="border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]">MEMUAT DATA SKENARIO FIKTIF</Badge>}</div>
        <h1 className="text-2xl font-semibold">{c.title}</h1>
        <div className="mt-3"><AssessmentBadge incident={incident} /></div>
        <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11px] text-[#7E8998]"><span>{c.id}</span><span>{fmtDate(incident.firstSeen).toUpperCase()}</span><span>STATUS: {CASE_STATUS_LABEL[c.status].toUpperCase()}</span><span>TINGKAT: {LEVEL_LABEL[incident.level].toUpperCase()}</span><span>SKOR PRIORITAS: {scorePercent(incident.score)}%</span><span>PETUGAS: {c.assignee || '—'}</span></div>
      </div>
      <div className="space-y-8 p-6 md:p-8">
        <section><Label>01 / Ringkasan eksekutif</Label><p className="max-w-4xl text-sm leading-7 text-[#C3CAD3]">{incidentSummary(incident, steps)}</p>{incident.path.length > 1 && <p className="mt-2 font-mono text-xs text-[#7DD3FC]">{incident.path.map(name).join('  →  ')}</p>}</section>
        <section><Label>02 / Kronologi (WIB)</Label><div className="mt-3 grid gap-2">{steps.map((s, i) => <div key={i} className="grid grid-cols-[70px_150px_1fr] items-start gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] px-3 py-2.5 text-xs"><span className="font-mono text-[11px] text-[#7E8998]">{fmtTime(s.first, false)}</span><span className="font-semibold">{s.label}</span><span className="min-w-0"><span className="block">{s.detections.map((d) => d.title).join('; ')}</span>{s.places.length > 0 && <span className="mt-0.5 block font-mono text-[10px] text-[#7E8998]">{s.places.join(', ')}</span>}</span></div>)}</div></section>
        <section><Label>03 / Temuan dan tindak lanjut</Label><div className="mt-3 overflow-x-auto"><table className="w-full min-w-[720px] text-left text-xs"><thead className="text-[10px] uppercase tracking-wider text-[#657080]"><tr className="border-b border-[#272E3A]"><th className="pb-3 pr-3">Waktu</th><th className="pb-3 pr-3">Temuan</th><th className="pb-3 pr-3">Bukti utama</th><th className="pb-3 pr-3">Tingkat</th><th className="pb-3">Tindak lanjut</th></tr></thead><tbody>{ordered.map((d) => { const evidence = Object.entries(d.matched)[0]; return <tr key={d.id} className="border-b border-[#272E3A] last:border-0"><td className="py-2.5 pr-3 font-mono text-[11px] text-[#7E8998]">{fmtTime(d.ts, false)}</td><td className="py-2.5 pr-3">{d.title}<div className="font-mono text-[10px] text-[#657080]">{d.attack.join(', ')}</div></td><td className="max-w-[280px] break-words py-2.5 pr-3 font-mono text-[10px] text-[#8D97A6]">{evidence ? `${evidence[0]} = ${evidence[1].length > 90 ? `${evidence[1].slice(0, 89)}…` : evidence[1]}` : '—'}</td><td className="py-2.5 pr-3"><Badge className={levelStyle[d.level]}>{LEVEL_LABEL[d.level]}</Badge></td><td className="py-2.5">{c.followUps[d.id] ?? 'Baru'}</td></tr> })}</tbody></table></div></section>
        <section><Label>04 / Aset dan indikator</Label><div className="mt-3 overflow-x-auto"><table className="w-full min-w-[620px] text-left text-xs"><thead className="text-[10px] uppercase tracking-wider text-[#657080]"><tr className="border-b border-[#272E3A]"><th className="pb-3 pr-3">Jenis</th><th className="pb-3 pr-3">Nilai</th><th className="pb-3 pr-3">Alias</th><th className="pb-3 pr-3">Temuan</th><th className="pb-3">Keterangan</th></tr></thead><tbody>{entities.map((e) => <tr key={e.key} className="border-b border-[#272E3A] last:border-0"><td className="py-2 pr-3 text-[#AEB6C1]">{entityTypeLabel(e)}</td><td className="break-all py-2 pr-3 font-mono text-[11px]">{e.value}</td><td className="py-2 pr-3 font-mono text-[10px] text-[#8D97A6]">{e.aliases.join(', ') || '—'}</td><td className="py-2 pr-3 font-mono">{e.detectionIds.length}</td><td className="py-2 text-[11px] text-[#8D97A6]">{[isIndicator(e) && 'Indikator — tinjau sebelum memblokir', e.common && 'Infrastruktur umum', e.actor && (e.type === 'host' || e.type === 'device') && 'Aset terkait'].filter(Boolean).join('; ') || '—'}</td></tr>)}</tbody></table></div></section>
        <section><Label>05 / Rekomendasi prioritas</Label>{actions.length === 0 ? <p className="text-sm text-[#8D97A6]">Tidak ada temuan kritis atau tinggi.</p> : <ol className="mt-3 grid gap-2 md:grid-cols-2">{actions.map((a, i) => <li key={a.detectionId} className="rounded-lg border border-[#272E3A] bg-[#0D1016] p-3"><div className="flex items-center gap-2"><span className="font-mono text-xs text-[#38BDF8]">P{i + 1}</span><Badge className={levelStyle[a.level]}>{LEVEL_LABEL[a.level]}</Badge></div><div className="mt-2 text-sm">{a.text}</div><div className="mt-1 text-[10px] text-[#7E8998]">Dasar: {a.ruleTitle}</div></li>)}</ol>}<p className="mt-2 text-[10px] text-[#657080]">Tindakan pada sistem operasional wajib diverifikasi, mendapat otorisasi komandan, dan dicatat.</p></section>
        <section><Label>06 / Penilaian dan skor prioritas</Label><p className="mb-2 text-xs leading-5 text-[#C3CAD3]"><b>{ASSESSMENT[assessmentOf(incident)].label}.</b> {ASSESSMENT[assessmentOf(incident)].text}</p><p className="text-xs leading-5 text-[#8D97A6]">Skor mengurutkan mana yang ditangani dahulu; angka ini bukan peluang bahwa serangan benar-benar terjadi. Skor = 1 − Π(1 − bobot) atas {incident.scoreBreakdown.length} unsur (Kritis 0,60 · Tinggi 0,40 · Sedang 0,20 · Rendah 0,10; ×0,5 bila juga wajar pada pekerjaan admin; ×0,25 bila hanya percobaan; satu aturan dihitung sekali). Hasil: {scorePercent(incident.score)}%.</p><ol className="mt-2 columns-1 gap-6 text-xs md:columns-2">{incident.scoreBreakdown.map((t, i) => <li key={i} className="mb-1 break-inside-avoid"><span className="mr-2 font-mono text-[#7DD3FC]">{decimal(t.weight)}</span>{t.label}{t.count && t.count > 1 ? ` (×${t.count})` : ''}</li>)}</ol></section>
        <section><Label>07 / Catatan analis</Label><p className="whitespace-pre-wrap rounded-lg border border-[#272E3A] bg-[#0D1016] p-4 text-sm leading-6 text-[#AEB6C1]">{c.notes || 'Belum ada catatan analis.'}</p></section>
        <section><Label>08 / Riwayat penanganan</Label><ol className="mt-2 space-y-1 text-xs">{c.history.map((h, i) => <li key={i} className="grid grid-cols-[150px_1fr] gap-3"><span className="font-mono text-[10px] text-[#7E8998]">{fmtDateTime(h.ts)}</span><span>{h.text} <span className="text-[#657080]">— {h.actor}</span></span></li>)}</ol></section>
        <section><Label>09 / Sumber data</Label><div className="mt-2 overflow-x-auto"><table className="w-full min-w-[620px] text-left text-xs"><thead className="text-[10px] uppercase tracking-wider text-[#657080]"><tr className="border-b border-[#272E3A]"><th className="pb-2 pr-3">Berkas</th><th className="pb-2 pr-3">Format</th><th className="pb-2 pr-3">Event</th><th className="pb-2">SHA-256</th></tr></thead><tbody>{sources.map((a) => { const info = a.analysis as LogAnalysis | undefined; return <tr key={a.id} className="border-b border-[#272E3A] last:border-0"><td className="py-2 pr-3 font-mono text-[11px]">{a.filename}</td><td className="py-2 pr-3 text-[#AEB6C1]">{info?.formatLabel ?? '—'}</td><td className="py-2 pr-3 font-mono">{fmtNumber(info?.eventCount ?? 0)}</td><td className="break-all py-2 font-mono text-[10px] text-[#8D97A6]">{a.sha256}</td></tr> })}</tbody></table></div></section>
        {data.coverage && <section><Label>10 / Cakupan analisis</Label><ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-[#AEB6C1]">{coverageLines(data.coverage).map((line) => <li key={line}>{line}</li>)}</ul></section>}
        {data.ot?.incidentId === incident.id && otSummaryLines(data.ot).length > 0 && <section data-testid="report-ot"><Label>11 / Dampak pada proses OT</Label><ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-[#AEB6C1]">{otSummaryLines(data.ot).map((line) => <li key={line}>{line}</li>)}</ul></section>}
        <footer className="border-t border-[#272E3A] pt-4 text-[10px] leading-5 text-[#657080]">Dibuat oleh SIGAP pada {fmtDateTime(generated)} untuk {actor}. Laporan ini disusun dari data lokal di perangkat operator; keterkaitan antar-temuan adalah hasil korelasi otomatis dan perlu diverifikasi sebelum menjadi kesimpulan. Ini bahan tanggap awal, bukan hasil pemeriksaan forensik.</footer>
      </div>
      {profile.reportMarking && <div className="border-t border-[#272E3A] py-2 text-center text-xs font-bold tracking-widest">{profile.reportMarking}</div>}
    </article>
    <div className="mt-4 print:hidden"><Card title="Verifikasi Paket Bukti" icon={<FileCheck2 size={16} className="text-[#38BDF8]" />}>
      <p className="text-xs text-[#8D97A6]">Periksa apakah isi ZIP masih sama seperti saat diekspor, dan perangkat mana yang menandatanganinya.</p>
      <label className="mt-3 inline-flex cursor-pointer items-center gap-2 rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]"><Upload size={14} />Pilih berkas ZIP<input type="file" accept=".zip,application/zip" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) void verifyPackage(f) }} /></label>
      {verify && <div className="mt-3">
        <div className={`rounded-lg border p-3 text-xs ${verify.ok ? 'border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]' : 'border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]'}`}>{verify.ok ? <><CircleCheck size={13} className="mr-1 inline" />Isi cocok dengan manifest dan catatan penanganan.</> : <><CircleX size={13} className="mr-1 inline" />Paket TIDAK utuh: ada yang berubah sejak diekspor.</>}</div>
        <div className={`mt-2 rounded-lg border p-3 text-xs leading-5 ${verify.signature.status === 'sah' && verify.signature.fingerprint === ownFingerprint ? 'border-[#22C55E]/30 bg-[#22C55E]/10 text-[#86EFAC]' : verify.signature.status === 'tidak-sah' ? 'border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]' : 'border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#FCD34D]'}`}>
          {verify.signature.status === 'tidak-ada' && <><TriangleAlert size={13} className="mr-1 inline" />Paket ini tidak ditandatangani, jadi asalnya tidak dapat dipastikan: siapa pun bisa menyusun paket yang lolos pemeriksaan di atas.</>}
          {verify.signature.status === 'tidak-sah' && <><CircleX size={13} className="mr-1 inline" />Tanda tangan tidak sah: {verify.signature.reason}.</>}
          {verify.signature.status === 'sah' && <><div className="font-semibold">{verify.signature.fingerprint === ownFingerprint ? 'Ditandatangani oleh kunci perangkat ini.' : 'Ditandatangani oleh kunci lain. Cocokkan dengan sidik jari yang didaftarkan pengirim.'}</div><div className="mt-1 break-all font-mono">{verify.signature.fingerprint}</div><div className="mt-1 text-[11px] opacity-80">Tanda tangan yang sah hanya berarti paket dibuat oleh pemegang kunci ini. Bila sidik jarinya tidak sama dengan yang didaftarkan lewat jalur lain, jangan percaya isi paket.</div></>}
        </div>
        {verify.unlisted.length > 0 && <div className="mt-2 rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 p-3 text-xs text-[#FCA5A5]">Berkas tambahan yang tidak tercatat di manifest: {verify.unlisted.join(', ')}</div>}
        {verify.files.length > 0 && <div className="mt-2 grid gap-1 text-[11px]">{verify.files.map((f) => <div key={f.name} className="flex items-center justify-between gap-2 rounded border border-[#272E3A] bg-[#0D1016] px-2.5 py-1.5"><span className="truncate font-mono text-[#AEB6C1]">{f.name}</span>{f.ok ? <span className="shrink-0 text-[#86EFAC]">cocok</span> : <span className="shrink-0 text-[#FCA5A5]">{f.reason ?? 'gagal'}</span>}</div>)}</div>}
        <div className="mt-2 flex flex-wrap gap-x-4 text-[10px] text-[#8D97A6]"><span>Rantai bukti: {verify.chain.ok ? 'sah' : `rusak${'reason' in verify.chain ? ` (${verify.chain.reason})` : ''}`}</span><span>Ikatan manifest: {verify.manifestBound ? 'ok' : 'gagal'}</span></div>
      </div>}
    </Card></div>
  </div>
}
