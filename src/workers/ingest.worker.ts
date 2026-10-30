import { db, type MetaRow } from '@/db/db'
import { FORMAT_LABEL, ingestText } from '@/core/ingest'
import { decodeText } from '@/core/ingest/util'
import { runDetections } from '@/core/detect/engine'
import { correlate } from '@/core/correlate/correlate'
import { reconcileCases } from '@/core/correlate/cases'
import { sha256Hex } from '@/core/evidence/hash'
import { appendCustody } from '@/core/evidence/custody'
import type { Artifact, Detection, NormalizedEvent } from '@/core/model'
import { computeStats } from '@/core/stats'
import { loadRulePack } from '@/data/rules'
import { generateScenario, scenarioKey } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import { ENGINE_VERSION, type IngestRequest, type IngestResponse, type ImportSummary, type LogAnalysis, type ScenarioCheck } from '@/workers/protocol'

const pack = loadRulePack()
// Typed as Worker so postMessage has the worker signature (the project compiles with the DOM lib).
const scope = self as unknown as Worker
const post = (message: IngestResponse) => scope.postMessage(message)
const CHUNK = 2000

/** `bytes` are the file as received; they are what is hashed for the chain of custody. */
type Input = { name: string; bytes: Uint8Array }

async function custody(entry: Parameters<typeof appendCustody>[1]) {
  const last = await db.custody.orderBy('seq').last()
  const chain = await appendCustody(last ? [last] : [], entry)
  await db.custody.add(chain.at(-1)!)
}

const importIdOf = (sha256: string) => sha256.slice(0, 12)

async function ingestFiles(inputs: Input[], actor: string, steps: number) {
  let events = 0
  const files: ImportSummary['files'] = []
  for (const [i, input] of inputs.entries()) {
    post({ type: 'progress', message: `Membaca ${input.name}`, done: i, total: steps })
    const sha256 = await sha256Hex(input.bytes)
    // Same content -> same import id -> same event ids, so re-importing a file does not duplicate it.
    const importId = importIdOf(sha256)
    const result = ingestText(decodeText(input.bytes), input.name, importId)
    for (let start = 0; start < result.events.length; start += CHUNK) {
      await db.events.bulkPut(result.events.slice(start, start + CHUNK))
    }
    const analysis: LogAnalysis = { format: result.format, formatLabel: FORMAT_LABEL[result.format], eventCount: result.events.length, errorCount: result.errorCount, errors: result.errors.slice(0, 10) }
    const artifact: Artifact = { id: `log-${importId}`, filename: input.name, sha256, size: input.bytes.byteLength, mime: 'text/plain', kind: 'log', addedAt: Date.now(), addedBy: actor, analysis }
    await db.artifacts.put(artifact)
    await custody({ ts: Date.now(), actor, action: 'imported', artifactId: artifact.id, artifactSha256: sha256, detail: `Impor ${input.name} (${analysis.formatLabel}, ${result.events.length} event)` })
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

/** Re-runs detection and correlation over every stored event, then stores the results. */
async function analyze(steps: number) {
  post({ type: 'progress', message: 'Menjalankan aturan deteksi', done: steps - 2, total: steps })
  const all = await db.events.toArray()
  const detections = runDetections(all, pack)
  post({ type: 'progress', message: 'Mengorelasikan temuan menjadi insiden', done: steps - 1, total: steps })
  const { incidents } = correlate(detections, all, DEFAULT_UNIT_PROFILE)
  const stats = computeStats(all)
  const check = await scenarioCheck(all, detections)

  await db.transaction('rw', [db.detections, db.incidents, db.cases, db.meta], async () => {
    // Reconcile inside the transaction so a case edited in the UI meanwhile is not overwritten.
    const reconciled = reconcileCases(incidents, await db.incidents.toArray(), await db.cases.toArray(), Date.now())
    await db.detections.clear()
    await db.detections.bulkAdd(detections)
    await db.incidents.clear()
    await db.incidents.bulkAdd(reconciled.incidents)
    await db.cases.bulkDelete(reconciled.remove)
    await db.cases.bulkPut(reconciled.put)
    const meta: MetaRow[] = [{ key: 'engine', value: ENGINE_VERSION }]
    if (stats) meta.push({ key: 'stats', value: stats })
    if (check) meta.push({ key: 'check', value: check })
    await db.meta.clear()
    await db.meta.bulkPut(meta)
  })
  return { totalEvents: all.length, detections: detections.length, incidents: incidents.length, rules: pack.sigma.length + pack.native.length }
}

async function importAndAnalyze(inputs: Input[], actor: string): Promise<ImportSummary> {
  const steps = inputs.length + 2
  const ingested = await ingestFiles(inputs, actor, steps)
  return { ...ingested, ...(await analyze(steps)) }
}

async function handle(request: IngestRequest): Promise<IngestResponse> {
  switch (request.type) {
    case 'import': {
      const inputs = await Promise.all(request.files.map(async (f) => ({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) })))
      return { type: 'done', summary: await importAndAnalyze(inputs, request.actor) }
    }
    case 'scenario': {
      post({ type: 'progress', message: 'Membangkitkan skenario contoh', done: 0, total: 1 })
      const scenario = generateScenario()
      const inputs = scenario.files.map((f) => ({ name: f.name, bytes: new TextEncoder().encode(f.text) }))
      return { type: 'done', summary: await importAndAnalyze(inputs, request.actor) }
    }
    case 'reanalyze':
      return { type: 'done', summary: { files: [], events: 0, ...(await analyze(2)) } }
    case 'clear':
      await db.transaction('rw', [db.events, db.detections, db.incidents, db.cases, db.artifacts, db.custody, db.meta], async () => {
        await Promise.all([db.events.clear(), db.detections.clear(), db.incidents.clear(), db.cases.clear(), db.artifacts.clear(), db.custody.clear(), db.meta.clear()])
      })
      return { type: 'done', summary: { files: [], events: 0, totalEvents: 0, detections: 0, incidents: 0, rules: pack.sigma.length + pack.native.length } }
  }
}

// Requests are handled one at a time, in order.
let queue = Promise.resolve()
scope.onmessage = (e: MessageEvent<IngestRequest>) => {
  queue = queue.then(() => handle(e.data).then(post, (err: unknown) => post({ type: 'error', message: err instanceof Error ? err.message : String(err) })))
}
