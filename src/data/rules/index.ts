import { loadSigmaRules } from '@/core/detect/sigma'
import { createNativeRules } from '@/core/detect/native'
import type { RulePack } from '@/core/detect/engine'
import type { IndicatorList } from '@/core/indicators'
import type { UnitProfile } from '@/core/model'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const sources = import.meta.glob<string>('./*.yml', { query: '?raw', import: 'default', eager: true })

const text = (values: readonly number[] | undefined) => (values ?? []).map(String)
const one = (value: number | undefined) => (value === undefined ? [] : [String(value)])

/** The built-in rule pack for a unit: every `*.yml` Sigma file in this folder plus the native rules. */
export function loadRulePack(profile: UnitProfile = DEFAULT_UNIT_PROFILE, lists: readonly IndicatorList[] = []): RulePack {
  const { rules, skipped } = loadSigmaRules(sources, {
    otSubnets: profile.otSubnets,
    engineeringHosts: profile.engineeringHosts,
    otHostNames: profile.assets.filter((a) => a.kind === 'ot').map((a) => a.name),
    runCoils: text(profile.ot?.runCoils),
    setpointRegisters: text(profile.ot?.setpointRegisters),
    setpointMin: one(profile.ot?.setpointMin),
    setpointMax: one(profile.ot?.setpointMax),
  })
  return { sigma: rules, native: createNativeRules(profile, lists), skipped }
}
