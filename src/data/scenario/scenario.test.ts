import { beforeAll, describe, expect, it } from 'vitest'
import { ingestText } from '@/core/ingest'
import { runDetections } from '@/core/detect/engine'
import type { Detection, NormalizedEvent } from '@/core/model'
import { loadRulePack } from '@/data/rules'
import { generateScenario, scenarioKey, type Scenario } from '@/data/scenario/generate'

describe('demo scenario end to end', () => {
  let scenario: Scenario
  let events: NormalizedEvent[]
  let detections: Detection[]
  const pack = loadRulePack()

  beforeAll(() => {
    scenario = generateScenario()
    events = []
    scenario.files.forEach((file, i) => {
      const result = ingestText(file.text, file.name, `demo-${i}`)
      expect(result.errorCount, `${file.name}: ${JSON.stringify(result.errors.slice(0, 3))}`).toBe(0)
      events.push(...result.events)
    })
    detections = runDetections(events, pack)
  })

  it('loads every rule in the pack', () => {
    expect(pack.skipped).toEqual([])
    expect(pack.sigma.length + pack.native.length).toBeGreaterThanOrEqual(24)
  })

  it('is deterministic', () => {
    expect(generateScenario().files.map((f) => f.text)).toEqual(scenario.files.map((f) => f.text))
  })

  it('produces about five thousand events in every supported format', () => {
    expect(events.length).toBeGreaterThan(4500)
    expect(new Set(events.map((e) => e.dataset))).toEqual(new Set(['winevent', 'zeek.conn', 'zeek.dns', 'zeek.modbus_detailed', 'kv-syslog']))
  })

  it('flags only attack events (no false positives on the background)', () => {
    const byId = new Map(events.map((e) => [e.id, e]))
    const falsePositives = detections.filter((d) => d.eventIds.some((id) => !scenario.attackKeys.has(scenarioKey(byId.get(id)!) ?? '')))
    expect(falsePositives.map((d) => `${d.ruleId} @ ${byId.get(d.eventIds[0])!.message}`)).toEqual([])
  })

  it('fires the rules that cover each step of the attack chain', () => {
    const fired = new Set(detections.map((d) => d.ruleId))
    for (const id of [
      'sigap-win-macro-doc-from-messaging',
      'sigap-win-office-spawn-shell',
      'sigap-win-ps-encoded',
      'sigap-win-ps-download-cradle',
      'sigap-win-script-host-dns',
      'sigap-win-script-host-network',
      'sigap-win-defender-tamper',
      'sigap-win-lsass-dump-comsvcs',
      'sigap-win-schtask-create',
      'sigap-native-failed-logon-burst',
      'sigap-win-admin-share',
      'sigap-win-psexec-service',
      'sigap-win-account-created',
      'sigap-net-it-to-modbus',
      'sigap-fw-it-to-modbus',
      'sigap-native-modbus-discovery',
      'sigap-ot-modbus-write-unauthorized',
      'sigap-ot-setpoint-out-of-range',
      'sigap-ot-genset-stop-coil',
      'sigap-win-archive-password',
      'sigap-native-large-upload',
      'sigap-win-log-cleared',
    ]) {
      expect(fired, id).toContain(id)
    }
  })
})
