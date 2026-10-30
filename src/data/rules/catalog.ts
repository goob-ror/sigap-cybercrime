import { ruleCatalog } from '@/core/detect/engine'
import { loadRulePack } from '@/data/rules'

/** Rule metadata for the UI (titles, descriptions, response steps), keyed by rule id. */
export const RULE_PACK = loadRulePack()
export const RULES = ruleCatalog(RULE_PACK)
