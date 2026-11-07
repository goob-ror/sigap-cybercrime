import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { hostname } from 'node:os'
import { basename, join, resolve } from 'node:path'
import { ingestText } from '@/core/ingest'
import { hostFromFilename, clfTime, parseAccessLine } from '@/core/ingest/weblog'
import { parseSyslogLine, syslogTime } from '@/core/ingest/syslog'
import { LEVEL_LABEL, LEVEL_RANK } from '@/core/labels'
import type { Level, NormalizedEvent, UnitProfile } from '@/core/model'
import { ASSESSMENT, assessmentOf, priorityActions, scorePercent } from '@/core/report/narrative'
import { TACTIC_LABEL } from '@/data/attack'
import { parseUnitProfile } from '@/core/profile'
import { loadRulePack } from '@/data/rules'
import { RULE_PACK, RULES } from '@/data/rules/catalog'
import { generateScenario } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import { fmtDate, fmtTime } from '@/lib/format'
import { Penjaga, type Alert, type IncidentUpdate } from '@/agent/penjaga'
import { Tailer, type TailState } from '@/agent/tail'

const HELP = `SIGAP Pos Jaga (PoC) — membaca log server terus-menerus dengan mesin deteksi SIGAP.

Pemakaian:
  pos-jaga jaga <berkas|folder>... [opsi]   Berjaga: ikuti log, tampilkan peringatan
  pos-jaga periksa <berkas|folder>... [opsi] Periksa sekali lalu keluar (untuk cron/jadwal)
  pos-jaga putar-ulang <folder> [opsi]      Demo: tulis log serangan web fiktif ke <folder> secara bertahap

Opsi jaga/periksa:
  --data <folder>     Tempat posisi baca, jendela event, dan peringatan (bawaan: ./sigap-pos-jaga)
  --host <nama>       Nama server untuk access log yang namanya tidak memuat host (bawaan: hostname)
  --tingkat <level>   Tingkat minimum peringatan: critical, high, medium, low (bawaan: high)
  --interval <detik>  Jeda antarpembacaan (bawaan: 2)
  --dari-akhir        Berkas yang baru terlihat dibaca dari akhir (abaikan isi lama)
  --profil <json>     Profil jaringan satuan (format UnitProfile); bawaan: profil contoh

Opsi putar-ulang:
  --kecepatan <n>     Kelipatan waktu (bawaan: 60, satu menit log = satu detik)
  --dari <JJ:MM>      Jam log mulai diputar; baris sebelumnya ditulis sekaligus (bawaan: 12:55)
  --sampai <JJ:MM>    Jam log berhenti (bawaan: 13:35)
  --timpa             Timpa berkas yang sudah ada

Pos Jaga hanya MEMBACA log. Tidak mengubah server, tidak memblokir, tidak mengirim data keluar.`

type Args = { command: string; paths: string[]; flags: Map<string, string | true> }

function parseArgs(argv: string[]): Args {
  const [command = 'bantuan', ...rest] = argv
  const paths: string[] = []
  const flags = new Map<string, string | true>()
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (!a.startsWith('--')) paths.push(a)
    else if (rest[i + 1] && !rest[i + 1].startsWith('--') && !['--dari-akhir', '--timpa'].includes(a)) flags.set(a.slice(2), rest[++i])
    else flags.set(a.slice(2), true)
  }
  return { command, paths, flags }
}

const str = (args: Args, name: string, fallback: string) => {
  const v = args.flags.get(name)
  return typeof v === 'string' ? v : fallback
}

const COLOR: Record<Level, string> = { critical: '\x1b[1;31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', informational: '\x1b[2m' }
const RESET = '\x1b[0m'
const color = process.stdout.isTTY ? (level: Level, text: string) => `${COLOR[level]}${text}${RESET}` : (_: Level, text: string) => text
const stamp = (ts: number) => `${fmtDate(ts)} ${fmtTime(ts, false)} WIB`

// ---- jaga / periksa ----------------------------------------------------------------------------

type Saved = { tail: TailState }

async function readJson<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T
  } catch {
    return undefined
  }
}

async function writeAtomic(path: string, text: string) {
  await writeFile(`${path}.tmp`, text)
  await rename(`${path}.tmp`, path)
}

function describeAlert(a: Alert): string {
  const d = a.detection
  const e = a.event
  const where = [e?.host, e?.srcIp && e.srcIp !== e.host ? `← ${e.srcIp}` : undefined, e?.user ? `akun ${e.user}` : undefined].filter(Boolean).join(' ')
  const attempt = d.signal === 'percobaan' ? ' (percobaan)' : d.signal === 'ambigu' ? ' (perlu konfirmasi)' : ''
  return `${color(d.level, `[${stamp(d.ts)}] ${LEVEL_LABEL[d.level].toUpperCase().padEnd(6)}`)} ${d.title}${attempt}${where ? ` · ${where}` : ''}`
}

function describeIncident(u: IncidentUpdate, detectionsById: Map<string, import('@/core/model').Detection>): string[] {
  const i = u.incident
  const tactics = i.tactics.map((t) => TACTIC_LABEL[t] ?? t).join(' → ')
  // Same stages, more evidence: one line is enough.
  if (!u.isNew && !u.newTactics.length) return [`   ↳ ${i.title}: ${i.detectionIds.length} temuan, skor prioritas ${scorePercent(i.score)}%`]
  const head = u.isNew ? '▲ INSIDEN BARU' : `▲ INSIDEN BERKEMBANG (tahap baru: ${u.newTactics.map((t) => TACTIC_LABEL[t] ?? t).join(', ')})`
  const lines = [
    color(i.level, `${head}  ${i.title}`),
    `   penilaian: ${ASSESSMENT[assessmentOf(i)].label} · skor prioritas ${scorePercent(i.score)}% · ${i.detectionIds.length} temuan · ${stamp(i.firstSeen)} – ${fmtTime(i.lastSeen, false)} WIB`,
    `   tahap: ${tactics}`,
  ]
  const first = priorityActions(i, detectionsById, RULES, 1)[0]
  if (first) lines.push(`   langkah pertama: ${first.text}`)
  return lines
}

async function watch(args: Args, once: boolean) {
  if (!args.paths.length) throw new Error('Sebutkan berkas atau folder log yang dijaga. Lihat: pos-jaga bantuan')
  const dataDir = resolve(str(args, 'data', 'sigap-pos-jaga'))
  await mkdir(dataDir, { recursive: true })
  const host = str(args, 'host', hostname()).toUpperCase()
  const minLevel = str(args, 'tingkat', 'high') as Level
  if (!(minLevel in LEVEL_RANK)) throw new Error(`Tingkat tidak dikenal: ${minLevel}`)
  const intervalMs = Math.max(0.2, Number(str(args, 'interval', '2'))) * 1000
  const profilePath = args.flags.get('profil')
  let profile: UnitProfile = DEFAULT_UNIT_PROFILE
  if (typeof profilePath === 'string') {
    const content = await readJson<unknown>(profilePath)
    if (content === undefined) throw new Error(`Profil tidak dapat dibaca sebagai JSON: ${profilePath}`)
    const parsed = parseUnitProfile(content)
    if (!parsed.ok) throw new Error(`Profil tidak valid (${profilePath}):\n- ${parsed.errors.join('\n- ')}`)
    profile = parsed.profile
  }

  const files = { state: join(dataDir, 'posisi.json'), window: join(dataDir, 'jendela.jsonl'), alerts: join(dataDir, 'peringatan.jsonl'), summary: join(dataDir, 'ringkasan.json') }
  const saved = await readJson<Saved>(files.state)
  const tailer = new Tailer(saved?.tail ?? { files: {} }, !args.flags.has('dari-akhir'))
  const penjaga = new Penjaga({ pack: loadRulePack(profile), profile, minLevel })

  if (saved && existsSync(files.window)) {
    const restored = (await readFile(files.window, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l) as NormalizedEvent)
    penjaga.restore(restored)
    console.log(`Melanjutkan: ${restored.length} event dari sesi sebelumnya, ${penjaga.incidents.length} insiden aktif.`)
  }

  console.log(`SIGAP Pos Jaga · ${RULE_PACK.sigma.length + RULE_PACK.native.length} aturan · peringatan mulai tingkat ${LEVEL_LABEL[minLevel]}`)
  console.log(`Menjaga: ${args.paths.map((p) => resolve(p)).join(', ')}`)
  console.log(`Data: ${dataDir}${once ? '' : ' · tekan Ctrl+C untuk berhenti'}\n`)

  let dirty = false
  let lastSave = Date.now()
  const save = async () => {
    if (!dirty) return
    await writeAtomic(files.window, penjaga.windowEvents().map((e) => JSON.stringify(e)).join('\n') + '\n')
    await writeAtomic(files.state, JSON.stringify({ tail: tailer.state } satisfies Saved, null, 2))
    const summary = {
      diperbarui: new Date().toISOString(),
      event: penjaga.eventCount,
      temuan: penjaga.detections.length,
      insiden: penjaga.incidents.map((i) => ({ id: i.id, judul: i.title, tingkat: i.level, skor: scorePercent(i.score), temuan: i.detectionIds.length, mulai: new Date(i.firstSeen).toISOString(), akhir: new Date(i.lastSeen).toISOString(), tahap: i.tactics, entitas: i.entities.map((e) => e.key) })),
    }
    await writeAtomic(files.summary, JSON.stringify(summary, null, 2))
    dirty = false
    lastSave = Date.now()
  }

  const tick = async () => {
    const chunks = await tailer.poll(args.paths)
    if (!chunks.length) return
    const events: NormalizedEvent[] = []
    for (const c of chunks) {
      const name = basename(c.path)
      // Access logs carry no server name; give it one through the file name SIGAP reads.
      const label = hostFromFilename(name) ? name : `${host}-${name}`
      const result = ingestText(c.text, label, `pj-${c.id}-${c.offset}`)
      if (result.format === 'unknown') continue
      events.push(...result.events)
    }
    if (!events.length) return
    const { alerts, updates } = penjaga.push(events)
    dirty = true
    const byId = new Map(penjaga.detections.map((d) => [d.id, d]))
    for (const a of alerts) {
      console.log(describeAlert(a))
      const e = a.event
      await appendFile(files.alerts, JSON.stringify({ jenis: 'temuan', waktu: new Date(a.detection.ts).toISOString(), tingkat: a.detection.level, aturan: a.detection.ruleId, judul: a.detection.title, host: e?.host, sumber: e?.srcIp, akun: e?.user, pesan: e?.message, attack: a.detection.attack }) + '\n')
    }
    for (const u of updates) {
      const text = describeIncident(u, byId)
      console.log(text.length > 1 ? `\n${text.join('\n')}\n` : text[0])
      await appendFile(files.alerts, JSON.stringify({ jenis: u.isNew ? 'insiden-baru' : 'insiden-berkembang', id: u.incident.id, judul: u.incident.title, tingkat: u.incident.level, skor: scorePercent(u.incident.score), temuan: u.incident.detectionIds.length }) + '\n')
    }
    if (Date.now() - lastSave > 30_000) await save()
  }

  if (once) {
    await tick()
    await save()
    console.log(`Selesai: ${penjaga.eventCount} event, ${penjaga.detections.length} temuan, ${penjaga.incidents.length} insiden. Ringkasan: ${files.summary}`)
    return
  }

  let stopping = false
  const stop = async () => {
    if (stopping) return
    stopping = true
    await save()
    console.log(`\nBerhenti. ${penjaga.eventCount} event dalam jendela, ${penjaga.incidents.length} insiden. Posisi baca tersimpan.`)
    process.exit(0)
  }
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
  for (;;) {
    try {
      await tick()
    } catch (err) {
      console.error(`Gagal membaca log: ${(err as Error).message}`)
    }
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}

// ---- putar-ulang (demo) ------------------------------------------------------------------------

const DEMO_FILES = ['web-satuan-01-nginx-access.log', 'web-satuan-01-auth.log']

function lineTime(name: string, line: string): number | undefined {
  if (name.endsWith('auth.log')) {
    const s = parseSyslogLine(line)
    return s ? syslogTime(s, 2026, '+07:00') : undefined
  }
  const a = parseAccessLine(line)
  return a ? clfTime(a.time) : undefined
}

async function replay(args: Args) {
  const folder = args.paths[0]
  if (!folder) throw new Error('Sebutkan folder tujuan. Contoh: pos-jaga putar-ulang ./log-demo')
  await mkdir(folder, { recursive: true })
  const targets = DEMO_FILES.map((n) => join(folder, n))
  if (!args.flags.has('timpa') && targets.some((t) => existsSync(t))) throw new Error(`Berkas demo sudah ada di ${folder}. Pakai --timpa untuk menimpanya.`)
  const speed = Math.max(1, Number(str(args, 'kecepatan', '60')))
  const hm = (text: string) => {
    const [h, m] = text.split(':').map(Number)
    return Date.UTC(2026, 10, 2, h - 7, m)
  }
  const from = hm(str(args, 'dari', '12:55'))
  const until = hm(str(args, 'sampai', '13:35'))

  const scenario = generateScenario()
  const lines = DEMO_FILES.flatMap((name, f) =>
    scenario.files
      .find((s) => s.name === name)!
      .text.split('\n')
      .filter(Boolean)
      .map((line) => ({ target: targets[f], line, t: lineTime(name, line) ?? 0 })),
  ).sort((a, b) => a.t - b.t)

  for (const t of targets) await writeFile(t, '')
  const backlog = lines.filter((l) => l.t < from)
  for (const t of targets) await appendFile(t, backlog.filter((l) => l.target === t).map((l) => l.line + '\n').join(''))
  console.log(`Putar ulang log fiktif portal web ke ${resolve(folder)}`)
  console.log(`${backlog.length} baris sebelum ${fmtTime(from, false)} WIB ditulis sekaligus; sisanya diputar ${speed}× lebih cepat.\n`)

  const start = Date.now()
  let lastMinute = -1
  for (const l of lines.filter((x) => x.t >= from && x.t <= until)) {
    const wait = start + (l.t - from) / speed - Date.now()
    if (wait > 0) await new Promise((r) => setTimeout(r, wait))
    await appendFile(l.target, l.line + '\n')
    const minute = Math.floor(l.t / 60_000)
    if (minute !== lastMinute && minute % 5 === 0) {
      console.log(`  jam log ${fmtTime(l.t, false).slice(0, 5)} WIB`)
      lastMinute = minute
    }
  }
  console.log('\nSelesai diputar.')
}

// ---- main --------------------------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv.slice(2))
  switch (args.command) {
    case 'jaga':
      return watch(args, false)
    case 'periksa':
      return watch(args, true)
    case 'putar-ulang':
      return replay(args)
    default:
      console.log(HELP)
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})
