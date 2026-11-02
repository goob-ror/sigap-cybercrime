import { describe, expect, it } from 'vitest'
import { PLAYBOOKS, playbookSteps, recommendPlaybooks } from '@/data/playbooks'

describe('recommendPlaybooks', () => {
  it('ranks rule-hint matches above tactic-only matches', () => {
    const recs = recommendPlaybooks({ tactics: ['Lateral Movement', 'Credential Access'], ruleIds: ['sigap-win-admin-share', 'sigap-win-psexec-service'] })
    expect(recs[0].id).toBe('lateral-movement')
  })

  it('recommends the OT playbook for OT tactics', () => {
    const recs = recommendPlaybooks({ tactics: ['Impair Process Control', 'Impact'], ruleIds: ['sigap-native-modbus-discovery'] })
    expect(recs[0].id).toBe('ot-disruption')
  })

  it('returns nothing when no tactic or rule matches', () => {
    expect(recommendPlaybooks({ tactics: ['Reconnaissance'], ruleIds: [] })).toHaveLength(0)
  })

  it('covers a multi-tactic incident with several playbooks', () => {
    const recs = recommendPlaybooks({
      tactics: ['Initial Access', 'Execution', 'Lateral Movement', 'Impair Process Control', 'Exfiltration'],
      ruleIds: ['sigap-win-ps-encoded', 'sigap-win-admin-share', 'sigap-native-modbus-discovery', 'sigap-native-large-upload'],
    })
    expect(recs.length).toBeGreaterThanOrEqual(4)
  })
})

describe('playbookSteps', () => {
  it('gives every playbook unique, stable, prefixed step ids', () => {
    expect(PLAYBOOKS.length).toBeGreaterThanOrEqual(4)
    for (const pb of PLAYBOOKS) {
      const steps = playbookSteps(pb)
      expect(steps.length).toBeGreaterThan(0)
      expect(new Set(steps.map((s) => s.id)).size).toBe(steps.length)
      expect(steps.every((s) => s.id.startsWith(`pb:${pb.id}#`))).toBe(true)
    }
  })

  it('each playbook has three phases (pra / saat / pasca)', () => {
    for (const pb of PLAYBOOKS) expect(pb.phases).toHaveLength(3)
  })
})
