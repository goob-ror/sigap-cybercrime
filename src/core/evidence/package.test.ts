import { describe, expect, it } from 'vitest'
import type { Artifact, Case, CustodyEntry, Detection, Incident, NormalizedEvent } from '@/core/model'
import { sha256Hex } from '@/core/evidence/hash'
import { buildCustodyChain, buildEvidenceFiles, renderManifest, verifyEvidencePackage, type EvidenceInput } from '@/core/evidence/package'

const T0 = Date.UTC(2026, 10, 2, 2, 0, 0)
const enc = (s: string) => new TextEncoder().encode(s)

function makeInput(): EvidenceInput {
  const det: Detection = { id: 'd1', ruleId: 'r1', title: 'Koneksi C2', level: 'high', attack: ['T1071'], eventIds: ['e1'], matched: {}, ts: T0 }
  const event: NormalizedEvent = { id: 'e1', ts: T0, dataset: 'winevent', sourceKind: 'endpoint', logsource: {}, message: 'e1', importId: 'imp1', fields: {}, dstIp: '203.0.113.66' }
  const incident: Incident = {
    id: 'inc1', caseId: 'KSS-0001', title: 'Insiden uji', path: [], level: 'high', detectionIds: ['d1'], ruleIds: ['r1'],
    entities: [{ type: 'ip', value: '203.0.113.66', key: 'ip:203.0.113.66', aliases: [], detectionIds: ['d1'], firstSeen: T0, actor: false, common: false }],
    relations: [], tactics: [], sourceKinds: ['endpoint'], score: 0.4, scoreBreakdown: [], firstSeen: T0, lastSeen: T0,
  }
  const c: Case = { id: 'KSS-0001', title: 'Insiden uji', status: 'Open', assignee: '', notes: 'catatan', createdAt: T0, updatedAt: T0, incidentIds: ['inc1'], playbookProgress: {}, followUps: {}, history: [] }
  const source: Artifact = { id: 'imp1', filename: 'log.json', sha256: 'aa'.repeat(32), size: 100, mime: 'application/json', kind: 'log', addedAt: T0, addedBy: 'operator', analysis: { eventCount: 1 } }
  return { case: c, incident, detections: [det], events: [event], sources: [source], actor: 'operator', generatedAt: T0 }
}

async function buildPackage(input: EvidenceInput): Promise<{ name: string; bytes: Uint8Array }[]> {
  const content = buildEvidenceFiles(input)
  const entries = await Promise.all(content.map(async (f) => ({ name: f.name, hash: await sha256Hex(f.text) })))
  const manifest = renderManifest(entries)
  const chain = await buildCustodyChain(input, await sha256Hex(manifest), content.length + 2)
  const files = [...content, { name: 'rantai-bukti.json', text: JSON.stringify(chain, null, 2) }, { name: 'MANIFEST-SHA256.txt', text: manifest }]
  return files.map((f) => ({ name: f.name, bytes: enc(f.text) }))
}

describe('evidence package', () => {
  it('builds a self-contained package that verifies as intact', async () => {
    const files = await buildPackage(makeInput())
    expect(files.find((f) => f.name === 'laporan.html')).toBeTruthy()
    const r = await verifyEvidencePackage(files)
    expect(r.ok).toBe(true)
    expect(r.manifestBound).toBe(true)
    expect(r.chain.ok).toBe(true)
    expect(r.files.every((f) => f.ok)).toBe(true)
  })

  it('detects a tampered content file', async () => {
    const files = await buildPackage(makeInput())
    files[files.findIndex((f) => f.name === 'kasus.json')] = { name: 'kasus.json', bytes: enc('{"tampered":true}') }
    const r = await verifyEvidencePackage(files)
    expect(r.ok).toBe(false)
    expect(r.files.find((f) => f.name === 'kasus.json')!.ok).toBe(false)
  })

  it('detects a tampered custody chain', async () => {
    const files = await buildPackage(makeInput())
    const i = files.findIndex((f) => f.name === 'rantai-bukti.json')
    const chain = JSON.parse(new TextDecoder().decode(files[i].bytes)) as CustodyEntry[]
    chain[0].detail = 'diubah'
    files[i] = { name: 'rantai-bukti.json', bytes: enc(JSON.stringify(chain, null, 2)) }
    const r = await verifyEvidencePackage(files)
    expect(r.ok).toBe(false)
    expect(r.chain.ok).toBe(false)
  })

  it('fails when the manifest is missing', async () => {
    const files = (await buildPackage(makeInput())).filter((f) => f.name !== 'MANIFEST-SHA256.txt')
    const r = await verifyEvidencePackage(files)
    expect(r.ok).toBe(false)
    expect(r.manifestFound).toBe(false)
  })

  it('includes and verifies bundled original (binary) files', async () => {
    const input = makeInput()
    const content = buildEvidenceFiles(input)
    const original = { name: 'asli/log.json', bytes: new Uint8Array([10, 20, 30, 40, 50, 60]) }
    const entries = [
      ...(await Promise.all(content.map(async (f) => ({ name: f.name, hash: await sha256Hex(f.text) })))),
      { name: original.name, hash: await sha256Hex(original.bytes) },
    ]
    const manifest = renderManifest(entries)
    const chain = await buildCustodyChain(input, await sha256Hex(manifest), content.length + 3)
    const assemble = () => [
      ...content.map((f) => ({ name: f.name, bytes: enc(f.text) })),
      { name: original.name, bytes: original.bytes },
      { name: 'rantai-bukti.json', bytes: enc(JSON.stringify(chain, null, 2)) },
      { name: 'MANIFEST-SHA256.txt', bytes: enc(manifest) },
    ]
    const intact = await verifyEvidencePackage(assemble())
    expect(intact.ok).toBe(true)
    expect(intact.files.find((f) => f.name === 'asli/log.json')!.ok).toBe(true)

    const tampered = assemble()
    tampered[tampered.findIndex((f) => f.name === 'asli/log.json')] = { name: 'asli/log.json', bytes: new Uint8Array([99]) }
    const after = await verifyEvidencePackage(tampered)
    expect(after.ok).toBe(false)
    expect(after.files.find((f) => f.name === 'asli/log.json')!.ok).toBe(false)
  })
})
