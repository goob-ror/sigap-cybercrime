import type { Artifact, Case, CustodyEntry, Detection, Incident, NormalizedEvent } from '@/core/model'
import { appendCustody, verifyCustodyChain, type ChainCheck } from '@/core/evidence/custody'
import { sha256Hex } from '@/core/evidence/hash'
import { isIndicator } from '@/core/report/ioc'
import { incidentStory, incidentSummary, priorityActions, scorePercent } from '@/core/report/narrative'
import { LEVEL_LABEL } from '@/core/labels'
import { RULES } from '@/data/rules/catalog'
import { fmtDate, fmtDateTime, fmtNumber, fmtTime } from '@/lib/format'

/**
 * Assembles a tamper-evident evidence package (a set of files to zip) for escalating a case, plus
 * a verifier. Integrity is hash-based, not signed: a MANIFEST lists the SHA-256 of every content
 * file, and a hash-linked chain of custody records the source files and binds the manifest. All
 * offline and deterministic (the caller passes `generatedAt`).
 */

export type EvidenceInput = {
  case: Case
  incident: Incident
  detections: Detection[]
  /** Events referenced by the case's detections. */
  events: NormalizedEvent[]
  /** Source log files (metadata + original SHA-256 from import). */
  sources: Artifact[]
  actor: string
  generatedAt: number
}

export type EvidenceFile = { name: string; text: string }

const MANIFEST = 'MANIFEST-SHA256.txt'
const CHAIN = 'rantai-bukti.json'
const ENTITY_LABEL: Record<string, string> = { ip: 'IP eksternal', domain: 'Domain', hash: 'Hash berkas', host: 'Host', device: 'Perangkat OT', user: 'Akun', file: 'Berkas' }

const esc = (s: unknown): string => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!))

/** A self-contained, offline HTML report (inline CSS, no external references). */
export function reportHtml(input: EvidenceInput): string {
  const { case: c, incident, detections } = input
  const byId = new Map(detections.map((d) => [d.id, d]))
  const eventsById = new Map(input.events.map((e) => [e.id, e]))
  const steps = incidentStory(incident, byId, eventsById)
  const actions = priorityActions(incident, byId, RULES, 8)
  const name = (key: string) => incident.entities.find((e) => e.key === key)?.value ?? key
  const indicators = incident.entities.filter(isIndicator)
  const ordered = [...detections].sort((a, b) => a.ts - b.ts)

  const row = (cells: string[]) => `<tr>${cells.map((x) => `<td>${x}</td>`).join('')}</tr>`
  const section = (title: string, body: string) => `<section><h2>${esc(title)}</h2>${body}</section>`

  return `<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Laporan Insiden ${esc(c.id)}</title><style>
:root{color-scheme:light}body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#f5f6f8;color:#1a2230}
.wrap{max-width:900px;margin:0 auto;padding:24px}.head{background:#0d1016;color:#fff;border-radius:12px;padding:24px;margin-bottom:16px}
.head h1{margin:.2em 0;font-size:1.4rem}.meta{font-family:ui-monospace,Consolas,monospace;font-size:.72rem;color:#9bb;display:flex;flex-wrap:wrap;gap:4px 16px}
section{background:#fff;border:1px solid #e2e6ec;border-radius:10px;padding:18px;margin-bottom:12px}
h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin:0 0 10px}
table{width:100%;border-collapse:collapse;font-size:.8rem}td,th{border-bottom:1px solid #eef1f5;padding:6px 8px;text-align:left;vertical-align:top}
th{font-size:.68rem;text-transform:uppercase;color:#94a3b8}code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:.76rem}
.path{font-family:ui-monospace,Consolas,monospace;color:#0369a1;font-size:.8rem}ol,ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}
.foot{font-size:.68rem;color:#94a3b8;padding:8px 4px}.tag{display:inline-block;border:1px solid #cbd5e1;border-radius:4px;padding:0 5px;font-size:.66rem}
</style></head><body><div class="wrap">
<div class="head"><div class="tag" style="border-color:#334155;color:#93c5fd">SIGAP · LAPORAN ANALISIS INSIDEN SIBER</div>
<h1>${esc(c.title)}</h1><div class="meta"><span>${esc(c.id)}</span><span>${esc(fmtDate(incident.firstSeen))}</span><span>TINGKAT: ${esc(LEVEL_LABEL[incident.level].toUpperCase())}</span><span>KEYAKINAN: ${scorePercent(incident.score)}%</span><span>PETUGAS: ${esc(c.assignee || '—')}</span></div></div>
${section('01 / Ringkasan eksekutif', `<p>${esc(incidentSummary(incident, steps))}</p>${incident.path.length > 1 ? `<p class="path">${incident.path.map((k) => esc(name(k))).join(' → ')}</p>` : ''}`)}
${section('02 / Kronologi (WIB)', `<table><thead><tr><th>Waktu</th><th>Tahap</th><th>Temuan</th></tr></thead><tbody>${steps.map((s) => row([esc(fmtTime(s.first, false)), esc(s.label), esc(s.detections.map((d) => d.title).join('; ')) + (s.places.length ? `<br><span class="mono" style="color:#94a3b8">${esc(s.places.join(', '))}</span>` : '')])).join('')}</tbody></table>`)}
${section('03 / Temuan', `<table><thead><tr><th>Waktu</th><th>Temuan</th><th>ATT&CK</th><th>Tingkat</th></tr></thead><tbody>${ordered.map((d) => row([esc(fmtTime(d.ts, false)), esc(d.title), `<span class="mono">${esc(d.attack.join(', '))}</span>`, esc(LEVEL_LABEL[d.level])])).join('')}</tbody></table>`)}
${section('04 / Indikator (usulkan blokir)', indicators.length ? `<table><thead><tr><th>Jenis</th><th>Nilai</th><th>Temuan</th></tr></thead><tbody>${indicators.map((e) => row([esc(ENTITY_LABEL[e.type] ?? e.type), `<span class="mono">${esc(e.value)}</span>`, String(e.detectionIds.length)])).join('')}</tbody></table>` : '<p>Tidak ada indikator eksternal.</p>')}
${section('05 / Rekomendasi prioritas', actions.length ? `<ol>${actions.map((a) => `<li><b>[${esc(LEVEL_LABEL[a.level])}]</b> ${esc(a.text)} <span class="mono" style="color:#94a3b8">(${esc(a.ruleTitle)})</span></li>`).join('')}</ol>` : '<p>Tidak ada temuan kritis/tinggi.</p>')}
${section('06 / Catatan analis', `<p>${esc(c.notes || 'Belum ada catatan.')}</p>`)}
${section('07 / Sumber data', `<table><thead><tr><th>Berkas</th><th>Event</th><th>SHA-256</th></tr></thead><tbody>${input.sources.map((a) => row([esc(a.filename), fmtNumber((a.analysis as { eventCount?: number } | undefined)?.eventCount ?? 0), `<span class="mono" style="font-size:.66rem">${esc(a.sha256)}</span>`])).join('')}</tbody></table>`)}
<div class="foot">Dibuat oleh SIGAP pada ${esc(fmtDateTime(input.generatedAt))} untuk ${esc(input.actor)}. Keterkaitan antar-temuan adalah hasil korelasi otomatis dan perlu diverifikasi. Integritas paket: lihat ${MANIFEST} dan ${CHAIN}.</div>
</div></body></html>
`
}

/** The content files of the package (deterministic, pure). MANIFEST and the chain are added later. */
export function buildEvidenceFiles(input: EvidenceInput): EvidenceFile[] {
  const dets = [...input.detections].sort((a, b) => a.ts - b.ts)
  const events = [...input.events].sort((a, b) => a.ts - b.ts)
  const readme = [
    'SIGAP — Paket Bukti Insiden',
    '===========================',
    `Kasus    : ${input.case.id} — ${input.case.title}`,
    `Dibuat   : ${fmtDateTime(input.generatedAt)}`,
    `Oleh     : ${input.actor}`,
    '',
    'Isi paket:',
    '- laporan.html         Laporan insiden mandiri (buka di peramban mana pun).',
    '- insiden.json         Insiden: entitas, relasi, skor, tahap.',
    '- temuan.json          Daftar temuan (deteksi).',
    '- kasus.json           Kasus: status, catatan, tindak lanjut, riwayat.',
    '- events.jsonl         Event yang memicu temuan (satu JSON per baris).',
    '- sumber.json          Berkas log sumber + SHA-256 saat diimpor.',
    '- asli/                Berkas log asli (bila tersimpan), untuk verifikasi & urai ulang.',
    `- ${CHAIN}    Rantai bukti berantai-hash (chain of custody).`,
    `- ${MANIFEST}   SHA-256 setiap berkas isi untuk verifikasi.`,
    '',
    'Verifikasi:',
    '- Di SIGAP: halaman Laporan → "Verifikasi paket bukti" → pilih berkas ZIP ini.',
    `- Manual: hitung SHA-256 tiap berkas dan cocokkan dengan ${MANIFEST}.`,
    '',
    'Catatan: integritas bersifat tamper-evident (berantai-hash), bukan tanda tangan digital.',
    'Berkas log asli disertakan di folder asli/ bila tersimpan; SHA-256-nya tercatat di MANIFEST.',
  ].join('\n') + '\n'

  return [
    { name: 'README.txt', text: readme },
    { name: 'laporan.html', text: reportHtml(input) },
    { name: 'insiden.json', text: JSON.stringify(input.incident, null, 2) },
    { name: 'temuan.json', text: JSON.stringify(dets, null, 2) },
    { name: 'kasus.json', text: JSON.stringify(input.case, null, 2) },
    { name: 'events.jsonl', text: events.map((e) => JSON.stringify(e)).join('\n') + '\n' },
    { name: 'sumber.json', text: JSON.stringify(input.sources.map((a) => ({ filename: a.filename, sha256: a.sha256, size: a.size, kind: a.kind, addedAt: a.addedAt })), null, 2) },
  ]
}

export function renderManifest(entries: { name: string; hash: string }[]): string {
  return ['# SIGAP — SHA-256 berkas paket bukti', ...entries.map((e) => `${e.hash}  ${e.name}`)].join('\n') + '\n'
}

export function parseManifest(text: string): { name: string; hash: string }[] {
  return text.split(/\r?\n/).map((l) => /^([0-9a-f]{64})\s+(.+)$/i.exec(l.trim())).filter((m): m is RegExpExecArray => !!m).map((m) => ({ hash: m[1].toLowerCase(), name: m[2] }))
}

/** Chain of custody: one entry per source import, an 'analyzed' entry, then an 'exported' entry that binds the manifest. */
export async function buildCustodyChain(input: EvidenceInput, manifestHash: string, fileCount: number): Promise<CustodyEntry[]> {
  let chain: CustodyEntry[] = []
  for (const a of [...input.sources].sort((x, y) => x.addedAt - y.addedAt)) {
    chain = await appendCustody(chain, { ts: a.addedAt, actor: a.addedBy || input.actor, action: 'imported', artifactId: a.id, artifactSha256: a.sha256, detail: `Impor ${a.filename}` })
  }
  chain = await appendCustody(chain, { ts: input.generatedAt, actor: input.actor, action: 'analyzed', detail: `Analisis ${input.case.id}: ${input.detections.length} temuan, skor ${scorePercent(input.incident.score)}%` })
  chain = await appendCustody(chain, { ts: input.generatedAt, actor: input.actor, action: 'exported', artifactSha256: manifestHash, detail: `Ekspor paket bukti (${fileCount} berkas)` })
  return chain
}

export type EvidenceVerification = {
  ok: boolean
  manifestFound: boolean
  files: { name: string; ok: boolean; reason?: string }[]
  chain: ChainCheck | { ok: false; reason: string }
  manifestBound: boolean
}

/** Re-check an unzipped package: every content file's hash vs MANIFEST, the custody chain, and the manifest↔chain binding. */
export async function verifyEvidencePackage(files: { name: string; bytes: Uint8Array }[]): Promise<EvidenceVerification> {
  const byName = new Map(files.map((f) => [f.name, f.bytes]))
  const manifestBytes = byName.get(MANIFEST)
  if (!manifestBytes) return { ok: false, manifestFound: false, files: [], chain: { ok: false, reason: `${MANIFEST} tidak ditemukan` }, manifestBound: false }
  const manifestText = new TextDecoder().decode(manifestBytes)
  const entries = parseManifest(manifestText)

  const fileResults: EvidenceVerification['files'] = []
  for (const e of entries) {
    const bytes = byName.get(e.name)
    if (!bytes) fileResults.push({ name: e.name, ok: false, reason: 'Berkas hilang' })
    else {
      const actual = await sha256Hex(bytes)
      fileResults.push({ name: e.name, ok: actual === e.hash, reason: actual === e.hash ? undefined : 'SHA-256 tidak cocok' })
    }
  }

  let chain: EvidenceVerification['chain'] = { ok: false, reason: `${CHAIN} tidak ditemukan` }
  let bound = false
  const chainBytes = byName.get(CHAIN)
  if (chainBytes) {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(chainBytes)) as CustodyEntry[]
      chain = await verifyCustodyChain(parsed)
      const last = parsed.at(-1)
      bound = !!last && last.action === 'exported' && last.artifactSha256 === (await sha256Hex(manifestText))
    } catch {
      chain = { ok: false, reason: `${CHAIN} tidak dapat dibaca` }
    }
  }

  const ok = fileResults.every((f) => f.ok) && chain.ok && bound
  return { ok, manifestFound: true, files: fileResults, chain, manifestBound: bound }
}
