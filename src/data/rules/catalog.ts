import { ruleCatalog } from '@/core/detect/engine'
import { indicatorListRule } from '@/core/detect/native'
import { loadRulePack } from '@/data/rules'

/** Rule metadata for the UI (titles, descriptions, response steps), keyed by rule id. */
export const RULE_PACK = loadRulePack()
/** Also knows the rule that runs only once a unit has imported an indicator list. */
export const RULES = ruleCatalog({ ...RULE_PACK, native: [...RULE_PACK.native, indicatorListRule([])] })
