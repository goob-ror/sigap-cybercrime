import { loadSigmaRules } from '@/core/detect/sigma'
import { createNativeRules } from '@/core/detect/native'
import type { RulePack } from '@/core/detect/engine'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const sources = import.meta.glob<string>('./*.yml', { query: '?raw', import: 'default', eager: true })

/** The built-in rule pack: every `*.yml` Sigma file in this folder plus the native rules. */
export function loadRulePack(): RulePack {
  const { rules, skipped } = loadSigmaRules(sources)
  return { sigma: rules, native: createNativeRules(DEFAULT_UNIT_PROFILE), skipped }
}
