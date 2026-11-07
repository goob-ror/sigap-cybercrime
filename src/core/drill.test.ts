import { describe, expect, it } from 'vitest'
import { correlate } from '@/core/correlate/correlate'
import { runDetections } from '@/core/detect/engine'
import { localDrill } from '@/core/drill'
import { ingestText } from '@/core/ingest'
import type { Detection, NormalizedEvent } from '@/core/model'
import { analyzeOt } from '@/core/ot/analysis'
import { RULE_PACK, RULES } from '@/data/rules/catalog'
import { generateScenario } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const events: NormalizedEvent[] = generateScenario().files.flatMap((f, i) => ingestText(f.text, f.name, `i${i}`).events)
const detections = runDetections(events, RULE_PACK)
const { incidents } = correlate(detections, events, DEFAULT_UNIT_PROFILE)
const byId = new Map<string, Detection>(detections.map((d) => [d.id, d]))

describe('localDrill', () => {
  it('gives one question per phase with a key that matches the data, for the demo incident', () => {
    const incident = incidents[0]
    const questions = localDrill(incident, byId, RULES)
    expect(questions.map((q) => q.phase)).toEqual(['Deteksi', 'Analisis', 'Containment', 'Recovery'])
    const first = incident.detectionIds.map((id) => byId.get(id)!).sort((a, b) => a.ts - b.ts)[0]
    expect(questions[0].options[questions[0].answer]).toBe(first.title)
    for (const q of questions) {
      expect(q.answer).toBeGreaterThanOrEqual(0)
      expect(new Set(q.options).size).toBe(q.options.length)
      expect(q.options.length).toBeGreaterThanOrEqual(2)
      expect(q.explanation).toBeTruthy()
      for (const ref of q.refs) expect(byId.has(ref)).toBe(true)
    }
  })

  it('is the same every time, but does not always put the answer first', () => {
    const answers = incidents.flatMap((i) => localDrill(i, byId, RULES))
    expect(localDrill(incidents[0], byId, RULES)).toEqual(localDrill(incidents[0], byId, RULES))
    expect(new Set(answers.map((q) => q.answer)).size).toBeGreaterThan(1)
  })

  it('never offers a dangerous move as the right answer', () => {
    for (const incident of incidents) {
      const containment = localDrill(incident, byId, RULES).find((q) => q.phase === 'Containment')
      if (containment) expect(containment.options[containment.answer]).not.toMatch(/Matikan komputer itu|Hapus log/)
    }
  })

  it('has nothing to ask about an incident without findings', () => {
    expect(localDrill({ ...incidents[0], detectionIds: [] }, byId, RULES)).toEqual([])
  })
})

describe('questions from the IT-OT link', () => {
  const ot = analyzeOt(events, detections, incidents, DEFAULT_UNIT_PROFILE)!
  const incident = incidents.find((i) => i.id === ot.incidentId)!
  const questions = localDrill(incident, byId, RULES, ot)
  const added = questions.filter((q) => !localDrill(incident, byId, RULES).some((base) => base.question === q.question))
  const right = (q: { options: string[]; answer: number }) => q.options[q.answer]

  it('adds three, in phase order', () => {
    expect(added.map((q) => q.phase)).toEqual(['Analisis', 'Containment', 'Recovery'])
    const order = ['Deteksi', 'Analisis', 'Containment', 'Recovery']
    const ranks = questions.map((q) => order.indexOf(q.phase))
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
  })

  it('knows a restart did not fix the setpoint', () => {
    expect(right(added[0])).toBe('Belum. Setpoint tegangan masih 265 V, di luar batas')
  })

  it('answers with a cut that really protects OT', () => {
    expect(right(added[1])).toBe('Blokir SRV-SATUAN-01 → PLC-GENSET-01')
    expect(added[1].options).toContain('Matikan PLC-GENSET-01 agar tidak dapat diperintah')
  })

  it('answers with the last normal value', () => {
    expect(right(added[2])).toBe('230 V')
    expect(added[2].options).toContain('265 V')
  })

  it('links each to evidence, and every option is distinct', () => {
    for (const q of added) {
      expect(new Set(q.options).size).toBe(4)
      for (const ref of q.refs) expect(byId.has(ref)).toBe(true)
    }
  })

  it('asks none of them about another incident', () => {
    const other = incidents.find((i) => i.id !== ot.incidentId)!
    expect(localDrill(other, byId, RULES, ot)).toEqual(localDrill(other, byId, RULES))
  })
})
