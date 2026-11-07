import { activeProfile, db, type MetaRow } from '@/db/db'
import { computeCoverage, type CollectionInfo } from '@/core/coverage'
import { FORMAT_LABEL, ingestText } from '@/core/ingest'
import { expandZip, isZip } from '@/core/ingest/archive'
import { readLogFile } from '@/core/ingest/util'
import { runDetections } from '@/core/detect/engine'
import { correlate } from '@/core/correlate/correlate'
import { reconcileCases } from '@/core/correlate/cases'
import { sha256Hex } from '@/core/evidence/hash'
import { addCustody as custody } from '@/db/custodyLog'
import type { Artifact, Detection, NormalizedEvent } from '@/core/model'
import { analyzeOt } from '@/core/ot/analysis'
import { computeStats } from '@/core/stats'
import { loadRulePack } from '@/data/rules'
import { generateScenario, scenarioKey } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import { ENGINE_VERSION, type IngestRequest, type IngestResponse, type ImportSummary, type LogAnalysis, type ScenarioCheck } from '@/workers/protocol'

// Typed as Worker so postMessage has the worker signature (the project compiles with the DOM lib).
const scope = self as unknown as Worker
const post = (message: IngestResponse) => scope.postMessage(message)
const CHUNK = 2000

/**
 * `bytes` are the file as received; they are what is hashed for the chain of custody. A file that
 * came out of a ZIP also names that ZIP, so its record ties back to what the operator was handed.
 */
type Input = { name: string; bytes: Uint8Array; archive?: { name: string; sha256: string }; collection?: CollectionInfo }

/** The selected files, with each ZIP replaced by the logs inside it. */
async function openInputs(files: readonly File[]): Promise<Input[]> {
  const inputs: Input[] = []
  for (const file of files) {
    const bytes = new Uint8Array(await file.arrayBuffer())
    if (!isZip(bytes)) {
      inputs.push({ name: file.name, bytes })
      continue
    }
    post({ type: 'progress', message: `Membuka arsip ${file.name}`, done: 0, total: 1 })
    const archive = { name: file.name, sha256: await sha256Hex(bytes) }
    const { logs, collection } = await expandZip(bytes)
    for (const entry of logs) inputs.push({ ...entry, archive, collection })
  }
  return inputs
}

const importIdOf = (sha256: string) => sha256.slice(0, 12)

async function ingestFiles(inputs: Input[], actor: string, steps: number, tzOffset?: string) {
  let events = 0
  const files: ImportSummary['files'] = []
  for (const [i, input] of inputs.entries()) {
    post({ type: 'progress', message: `Membaca ${input.name}`, done: i, total: steps })
    const sha256 = await sha256Hex(input.bytes)
    // Same content -> same import id -> same event ids, so re-importing a file does not duplicate it.
    const importId = importIdOf(sha256)
    // gzip (cPanel Raw Access, rotated logs) is unpacked; the hash above stays that of the file as received.
    const file = await readLogFile(input.bytes, input.name)
    const result = ingestText(file.text, file.name, importId, { defaultTzOffset: tzOffset })
    const errorCount = result.errorCount + (file.damaged ?? 0)
    for (let start = 0; start < result.events.length; start += CHUNK) {
      await db.events.bulkPut(result.events.slice(start, start + CHUNK))
    }
    const analysis: LogAnalysis = { format: result.format, formatLabel: FORMAT_LABEL[result.format], eventCount: result.events.length, errorCount, errors: result.errors.slice(0, 10), assumedOffset: result.assumedOffset, collection: input.collection }
    const artifact: Artifact = { id: `log-${importId}`, filename: input.name, sha256, size: input.bytes.byteLength, mime: 'text/plain', kind: 'log', addedAt: Date.now(), addedBy: actor, analysis }
    await db.artifacts.put(artifact)
    // Keep the original bytes so the evidence package can bundle them and the engine can re-parse.
    await db.blobs.put({ id: importId, name: input.name, bytes: input.bytes, tzOffset })
    const notes = [
      input.archive && `dari arsip ${input.archive.name} (SHA-256 ${input.archive.sha256})`,
      result.assumedOffset && `waktu tanpa zona dianggap UTC${result.assumedOffset}`,
      input.collection?.unread.length && `tidak terbaca saat dikumpulkan: ${input.collection.unread.join(', ')}`,
    ].filter(Boolean)
    await custody({ ts: Date.now(), actor, action: 'imported', artifactId: artifact.id, artifactSha256: sha256, detail: `Impor ${input.name} (${analysis.formatLabel}, ${result.events.length} event)${notes.length ? `, ${notes.join(', ')}` : ''}` })
    events += result.events.length
    files.push({ name: input.name, format: analysis.formatLabel, events: result.events.length, errors: result.errorCount })
  }
  return { events, files }
}

/** Import ids and attack event keys of the built-in scenario (generated once per worker). */
let scenarioTruth: Promise<{ importIds: Set<string>; attackKeys: Set<string> }> | undefined
function getScenarioTruth() {
  scenarioTruth ??= (async () => {
    const scenario = generateScenario()
    const hashes = await Promise.all(scenario.files.map((f) => sha256Hex(f.text)))
    return { importIds: new Set(hashes.map(importIdOf)), attackKeys: scenario.attackKeys }
  })()
  return scenarioTruth
}

async function scenarioCheck(events: readonly NormalizedEvent[], detections: readonly Detection[]): Promise<ScenarioCheck | null> {
  const truth = await getScenarioTruth()
  const files = new Set(events.filter((e) => truth.importIds.has(e.importId)).map((e) => e.importId))
  if (!files.size) return null
  const flagged = new Set(detections.flatMap((d) => d.eventIds))
  const check: ScenarioCheck = { files: files.size, totalFiles: truth.importIds.size, attackEvents: 0, attackFlagged: 0, benignEvents: 0, benignFlagged: 0 }
  for (const e of events) {
    if (!truth.importIds.has(e.importId)) continue
    const key = scenarioKey(e)
    if (key && truth.attackKeys.has(key)) {
      check.attackEvents++
      if (flagged.has(e.id)) check.attackFlagged++
    } else {
      check.benignEvents++
      if (flagged.has(e.id)) check.benignFlagged++
    }
  }
  return check
}

/** Re-parses every stored original file (parser may have changed), replacing that file's events. */
async function reparseFromBlobs(): Promise<number> {
  const blobs = await db.blobs.toArray()
  for (const b of blobs) {
    const file = await readLogFile(b.bytes, b.name)
    const result = ingestText(file.text, file.name, b.id, { defaultTzOffset: b.tzOffset })
    await db.events.where('importId').equals(b.id).delete()
    for (let start = 0; start < result.events.length; start += CHUNK) {
      await db.events.bulkPut(result.events.slice(start, start + CHUNK))
    }
  }
  return blobs.length
}

/** Re-runs detection and correlation over every stored event, then stores the results. */
async function analyze(steps: number) {
  post({ type: 'progress', message: 'Menjalankan aturan deteksi', done: steps - 2, total: steps })
  const all = await db.events.toArray()
  // Read on every run, so a profile saved in Pengaturan applies from the next analysis on.
  const profile = await activeProfile()
  const pack = loadRulePack(profile, await db.indicatorLists.toArray())
  const detections = runDetections(all, pack)
  post({ type: 'progress', message: 'Mengorelasikan temuan menjadi insiden', done: steps - 1, total: steps })
  const { incidents } = correlate(detections, all, profile)
  const stats = computeStats(all)
  const check = await scenarioCheck(all, detections)
  const imports = await db.artifacts.where('kind').equals('log').toArray()
  const collections = [...new Map(imports.flatMap((a) => (a.analysis as LogAnalysis | undefined)?.collection ?? []).map((c) => [`${c.computer}|${c.unread}|${c.truncated}`, c])).values()]
  const coverage = computeCoverage(all, [...pack.sigma, ...pack.native].map((r) => r.meta), collections)
  const ot = analyzeOt(all, detections, incidents, profile)

  await db.transaction('rw', [db.detections, db.incidents, db.cases, db.meta], async () => {
    // Reconcile inside the transaction so a case edited in the UI meanwhile is not overwritten.
    const reconciled = reconcileCases(incidents, await db.incidents.toArray(), await db.cases.toArray(), Date.now())
    await db.detections.clear()
    await db.detections.bulkAdd(detections)
    await db.incidents.clear()
    await db.incidents.bulkAdd(reconciled.incidents)
    await db.cases.bulkDelete(reconciled.remove)
    await db.cases.bulkPut(reconciled.put)
    const meta: MetaRow[] = [{ key: 'engine', value: ENGINE_VERSION }, { key: 'coverage', value: coverage }]
    if (stats) meta.push({ key: 'stats', value: stats })
    if (check) meta.push({ key: 'check', value: check })
    if (ot) meta.push({ key: 'ot', value: ot })
    await db.meta.clear()
    await db.meta.bulkPut(meta)
  })
  return { totalEvents: all.length, detections: detections.length, incidents: incidents.length, rules: pack.sigma.length + pack.native.length }
}

async function importAndAnalyze(inputs: Input[], actor: string, tzOffset?: string): Promise<ImportSummary> {
  const steps = inputs.length + 2
  const ingested = await ingestFiles(inputs, actor, steps, tzOffset)
  return { ...ingested, ...(await analyze(steps)) }
}

async function handle(request: IngestRequest): Promise<IngestResponse> {
  switch (request.type) {
    case 'import': {
      return { type: 'done', summary: await importAndAnalyze(await openInputs(request.files), request.actor, request.tzOffset) }
    }
    case 'scenario': {
      post({ type: 'progress', message: 'Membangkitkan skenario contoh', done: 0, total: 1 })
      const scenario = generateScenario()
      const inputs = scenario.files.map((f) => ({ name: f.name, bytes: new TextEncoder().encode(f.text) }))
      return { type: 'done', summary: await importAndAnalyze(inputs, request.actor) }
    }
    case 'reanalyze': {
      // On an engine upgrade, re-parse originals first (parser may have changed), then re-analyze.
      const reparsed = await reparseFromBlobs()
      if (reparsed) post({ type: 'progress', message: `Mengurai ulang ${reparsed} berkas asli`, done: 0, total: 2 })
      return { type: 'done', summary: { files: [], events: 0, ...(await analyze(2)) } }
    }
    case 'profile': {
      if (request.profile) await db.settings.put({ key: 'profile', value: request.profile })
      else await db.settings.delete('profile')
      const name = (request.profile ?? DEFAULT_UNIT_PROFILE).name
      // The same logs can give different findings under another profile, so the change is on record.
      await custody({ ts: Date.now(), actor: request.actor, action: 'note', detail: `Profil jaringan diganti menjadi "${name}"; temuan dihitung ulang` })
      return { type: 'done', summary: { files: [], events: 0, ...(await analyze(2)) } }
    }
    case 'indicators': {
      return { type: 'done', summary: { files: [], events: 0, ...(await analyze(2)) } }
    }
    case 'clear': {
      // db.settings and the indicator lists are left alone: they are configuration, not case data.
      await db.transaction('rw', [db.events, db.detections, db.incidents, db.cases, db.artifacts, db.custody, db.meta, db.blobs], async () => {
        await Promise.all([db.events.clear(), db.detections.clear(), db.incidents.clear(), db.cases.clear(), db.artifacts.clear(), db.custody.clear(), db.meta.clear(), db.blobs.clear()])
      })
      const pack = loadRulePack(await activeProfile())
      return { type: 'done', summary: { files: [], events: 0, totalEvents: 0, detections: 0, incidents: 0, rules: pack.sigma.length + pack.native.length } }
    }
  }
}

// Requests are handled one at a time, in order.
let queue = Promise.resolve()
scope.onmessage = (e: MessageEvent<IngestRequest>) => {
  queue = queue.then(() => handle(e.data).then(post, (err: unknown) => post({ type: 'error', message: err instanceof Error ? err.message : String(err) })))
}
