import { db } from '@/db/db'
import { FORMAT_LABEL, ingestText } from '@/core/ingest'
import { runDetections } from '@/core/detect/engine'
import { sha256Hex } from '@/core/evidence/hash'
import { appendCustody } from '@/core/evidence/custody'
import type { Artifact } from '@/core/model'
import { loadRulePack } from '@/data/rules'
import { generateScenario } from '@/data/scenario/generate'
import type { IngestRequest, IngestResponse, ImportSummary, LogAnalysis } from '@/workers/protocol'

const pack = loadRulePack()
// Typed as Worker so postMessage has the worker signature (the project compiles with the DOM lib).
const scope = self as unknown as Worker
const post = (message: IngestResponse) => scope.postMessage(message)
const CHUNK = 2000

async function custody(entry: Parameters<typeof appendCustody>[1]) {
  const last = await db.custody.orderBy('seq').last()
  const chain = await appendCustody(last ? [last] : [], entry)
  await db.custody.add(chain.at(-1)!)
}

async function importTexts(inputs: { name: string; text: string; size: number }[], actor: string): Promise<ImportSummary> {
  let events = 0
  const files: ImportSummary['files'] = []
  for (const [i, input] of inputs.entries()) {
    post({ type: 'progress', message: `Membaca ${input.name}`, done: i, total: inputs.length + 1 })
    const sha256 = await sha256Hex(input.text)
    // Same content -> same import id -> same event ids, so re-importing a file does not duplicate it.
    const importId = sha256.slice(0, 12)
    const result = ingestText(input.text, input.name, importId)
    for (let start = 0; start < result.events.length; start += CHUNK) {
      await db.events.bulkPut(result.events.slice(start, start + CHUNK))
    }
    const analysis: LogAnalysis = { format: result.format, formatLabel: FORMAT_LABEL[result.format], eventCount: result.events.length, errorCount: result.errorCount, errors: result.errors.slice(0, 10) }
    const artifact: Artifact = { id: `log-${importId}`, filename: input.name, sha256, size: input.size, mime: 'text/plain', kind: 'log', addedAt: Date.now(), addedBy: actor, analysis }
    await db.artifacts.put(artifact)
    await custody({ ts: Date.now(), actor, action: 'imported', artifactId: artifact.id, artifactSha256: sha256, detail: `Impor ${input.name} (${analysis.formatLabel}, ${result.events.length} event)` })
    events += result.events.length
    files.push({ name: input.name, format: analysis.formatLabel, events: result.events.length, errors: result.errorCount })
  }

  post({ type: 'progress', message: 'Menjalankan aturan deteksi', done: inputs.length, total: inputs.length + 1 })
  const all = await db.events.toArray()
  const detections = runDetections(all, pack)
  await db.transaction('rw', db.detections, async () => {
    await db.detections.clear()
    await db.detections.bulkAdd(detections)
  })
  return { files, events, totalEvents: all.length, detections: detections.length, rules: pack.sigma.length + pack.native.length }
}

async function handle(request: IngestRequest): Promise<IngestResponse> {
  switch (request.type) {
    case 'import': {
      const inputs = await Promise.all(request.files.map(async (f) => ({ name: f.name, text: await f.text(), size: f.size })))
      return { type: 'done', summary: await importTexts(inputs, request.actor) }
    }
    case 'scenario': {
      post({ type: 'progress', message: 'Membangkitkan skenario contoh', done: 0, total: 1 })
      const scenario = generateScenario()
      const inputs = scenario.files.map((f) => ({ name: f.name, text: f.text, size: new TextEncoder().encode(f.text).length }))
      return { type: 'done', summary: await importTexts(inputs, request.actor) }
    }
    case 'clear':
      await db.transaction('rw', [db.events, db.detections, db.incidents, db.cases, db.artifacts, db.custody], async () => {
        await Promise.all([db.events.clear(), db.detections.clear(), db.incidents.clear(), db.cases.clear(), db.artifacts.clear(), db.custody.clear()])
      })
      return { type: 'done', summary: { files: [], events: 0, totalEvents: 0, detections: 0, rules: pack.sigma.length + pack.native.length } }
  }
}

// Requests are handled one at a time, in order.
let queue = Promise.resolve()
scope.onmessage = (e: MessageEvent<IngestRequest>) => {
  queue = queue.then(() => handle(e.data).then(post, (err: unknown) => post({ type: 'error', message: err instanceof Error ? err.message : String(err) })))
}
