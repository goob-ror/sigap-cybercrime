import { loadAll } from 'js-yaml'
import type { FieldValue, Level, Logsource, NormalizedEvent } from '@/core/model'
import { ipInCidr } from '@/core/net'

/**
 * Sigma rule support (subset). Supported:
 * - logsource matching on product / category / service
 * - selections as maps (AND), lists of maps (OR), keyword lists
 * - modifiers: contains, startswith, endswith, all, re (+ i), cidr, windash, gt, gte, lt, lte
 * - wildcards `*` / `?` in values, `null` for "field absent"
 * - conditions with and / or / not / parentheses, `1 of x*`, `all of x*`, `1 of them`
 * Not supported (rule is skipped with a reason): aggregations (`| count()`), base64 modifiers.
 */

export type RuleMeta = {
  id: string
  kind: 'sigma' | 'native'
  title: string
  description: string
  level: Level
  status?: string
  author?: string
  tags: string[]
  references: string[]
  falsepositives: string[]
  /** SIGAP extension: first-response steps in Bahasa Indonesia. */
  respons: string[]
  logsource: Logsource
}

type Expected = string | number | boolean | null
type FieldTest = { field: string; mods: Set<string>; values: Expected[]; patterns: (RegExp | null)[] }
type Selection = { kind: 'map'; tests: FieldTest[] } | { kind: 'any'; maps: Selection[] } | { kind: 'keywords'; patterns: RegExp[] }

type Node =
  | { op: 'ref'; name: string }
  | { op: 'of'; quantifier: 'one' | 'all'; pattern: string }
  | { op: 'not'; arg: Node }
  | { op: 'and' | 'or'; args: Node[] }

export type CompiledRule = {
  meta: RuleMeta
  /** Field values that satisfied the rule, or null when the event does not match. */
  match(event: NormalizedEvent): Record<string, string> | null
}

export class RuleError extends Error {}

const SUPPORTED_MODS = new Set(['contains', 'startswith', 'endswith', 'all', 're', 'i', 'cidr', 'windash', 'gt', 'gte', 'lt', 'lte'])
const LEVELS: Level[] = ['informational', 'low', 'medium', 'high', 'critical']

function escapeRegex(text: string): string {
  return text.replace(/[.+^${}()|[\]\\*?]/g, '\\$&')
}

/** Sigma glob -> anchored, case-insensitive RegExp. `\*`, `\?` and `\\` are literal. */
export function globToRegex(glob: string): RegExp {
  let out = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    const next = glob[i + 1]
    if (c === '\\' && (next === '*' || next === '?' || next === '\\')) {
      out += escapeRegex(next)
      i++
    } else if (c === '*') out += '.*'
    else if (c === '?') out += '.'
    else out += escapeRegex(c)
  }
  return new RegExp(`^${out}$`, 'is')
}

function windashVariants(value: string): string[] {
  if (!/(^|\s)-/.test(value)) return [value]
  return ['-', '/', '–', '—'].map((dash) => value.replace(/(^|\s)-/g, `$1${dash}`))
}

function compileFieldTest(key: string, raw: unknown): FieldTest {
  const [field, ...modList] = key.split('|')
  const mods = new Set(modList)
  for (const mod of mods) if (!SUPPORTED_MODS.has(mod)) throw new RuleError(`Modifier tidak didukung: ${mod}`)
  let values: Expected[] = (Array.isArray(raw) ? raw : [raw]).map((v) => (v === undefined ? null : (v as Expected)))
  if (mods.has('windash')) values = values.flatMap((v): Expected[] => (typeof v === 'string' ? windashVariants(v) : [v]))
  const numeric = mods.has('gt') || mods.has('gte') || mods.has('lt') || mods.has('lte')
  const patterns = values.map((v) => {
    if (v === null || numeric || mods.has('cidr')) return null
    if (mods.has('re')) return new RegExp(String(v), mods.has('i') ? 'i' : '')
    const text = String(v)
    const glob = mods.has('contains') ? `*${text}*` : mods.has('startswith') ? `${text}*` : mods.has('endswith') ? `*${text}` : text
    return globToRegex(glob)
  })
  return { field, mods, values, patterns }
}

function compileSelection(name: string, raw: unknown): Selection {
  if (Array.isArray(raw)) {
    if (raw.every((item) => typeof item === 'string' || typeof item === 'number')) {
      return { kind: 'keywords', patterns: raw.map((k) => globToRegex(`*${k}*`)) }
    }
    return { kind: 'any', maps: raw.map((item, i) => compileSelection(`${name}[${i}]`, item)) }
  }
  if (raw && typeof raw === 'object') {
    return { kind: 'map', tests: Object.entries(raw as Record<string, unknown>).map(([k, v]) => compileFieldTest(k, v)) }
  }
  throw new RuleError(`Selection "${name}" tidak valid`)
}

function testValue(actual: FieldValue | undefined, test: FieldTest, i: number): boolean {
  const expected = test.values[i]
  if (expected === null) return actual === undefined || actual === null || actual === ''
  if (actual === undefined || actual === null) return false
  if (test.mods.has('cidr')) return ipInCidr(String(actual), String(expected))
  if (test.mods.has('gt') || test.mods.has('gte') || test.mods.has('lt') || test.mods.has('lte')) {
    const a = Number(actual)
    const e = Number(expected)
    if (!Number.isFinite(a) || !Number.isFinite(e)) return false
    return test.mods.has('gt') ? a > e : test.mods.has('gte') ? a >= e : test.mods.has('lt') ? a < e : a <= e
  }
  return test.patterns[i]!.test(String(actual))
}

function evalSelection(sel: Selection, fields: Record<string, FieldValue>, matched: Record<string, string>): boolean {
  switch (sel.kind) {
    case 'map':
      for (const test of sel.tests) {
        const actual = fields[test.field]
        const hits = test.values.map((_, i) => testValue(actual, test, i))
        const ok = test.mods.has('all') ? hits.every(Boolean) : hits.some(Boolean)
        if (!ok) return false
      }
      for (const test of sel.tests) {
        const actual = fields[test.field]
        if (actual !== undefined && actual !== null) matched[test.field] = String(actual)
      }
      return true
    case 'any':
      return sel.maps.some((m) => evalSelection(m, fields, matched))
    case 'keywords':
      for (const [field, value] of Object.entries(fields)) {
        if (typeof value !== 'string') continue
        if (sel.patterns.some((p) => p.test(value))) {
          matched[field] = value
          return true
        }
      }
      return false
  }
}

// ---- condition parser -------------------------------------------------------------------

function tokenize(condition: string): string[] {
  if (condition.includes('|')) throw new RuleError('Agregasi (|) belum didukung')
  return condition.match(/\(|\)|[^\s()]+/g) ?? []
}

export function parseCondition(condition: string): Node {
  const tokens = tokenize(condition)
  let pos = 0
  const peek = () => tokens[pos]?.toLowerCase()
  const next = () => tokens[pos++]

  function parseOr(): Node {
    const args = [parseAnd()]
    while (peek() === 'or') {
      next()
      args.push(parseAnd())
    }
    return args.length === 1 ? args[0] : { op: 'or', args }
  }
  function parseAnd(): Node {
    const args = [parseNot()]
    while (peek() === 'and') {
      next()
      args.push(parseNot())
    }
    return args.length === 1 ? args[0] : { op: 'and', args }
  }
  function parseNot(): Node {
    if (peek() === 'not') {
      next()
      return { op: 'not', arg: parseNot() }
    }
    return parsePrimary()
  }
  function parsePrimary(): Node {
    const token = next()
    if (token === undefined) throw new RuleError('Kondisi tidak lengkap')
    if (token === '(') {
      const inner = parseOr()
      if (next() !== ')') throw new RuleError('Kurung tidak seimbang')
      return inner
    }
    const lower = token.toLowerCase()
    if ((lower === '1' || lower === 'any' || lower === 'all') && peek() === 'of') {
      next()
      const pattern = next()
      if (!pattern) throw new RuleError('"of" tanpa target')
      return { op: 'of', quantifier: lower === 'all' ? 'all' : 'one', pattern }
    }
    return { op: 'ref', name: token }
  }

  const node = parseOr()
  if (pos !== tokens.length) throw new RuleError(`Token tak terduga: ${tokens[pos]}`)
  return node
}

function resolveNames(pattern: string, names: string[]): string[] {
  if (pattern === 'them') return names.filter((n) => !n.startsWith('_'))
  const re = globToRegex(pattern)
  return names.filter((n) => re.test(n))
}

/** Names referenced under an even number of `not`s; only these contribute "matched" fields. */
function positiveNames(node: Node, names: string[], positive = true, out = new Set<string>()): Set<string> {
  switch (node.op) {
    case 'ref':
      if (positive) out.add(node.name)
      break
    case 'of':
      if (positive) resolveNames(node.pattern, names).forEach((n) => out.add(n))
      break
    case 'not':
      positiveNames(node.arg, names, !positive, out)
      break
    default:
      node.args.forEach((a) => positiveNames(a, names, positive, out))
  }
  return out
}

// ---- rule compilation -------------------------------------------------------------------

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String)
  return value === undefined || value === null ? [] : [String(value)]
}

export function parseRuleMeta(doc: Record<string, unknown>, kind: RuleMeta['kind']): RuleMeta {
  if (typeof doc.id !== 'string' || typeof doc.title !== 'string') throw new RuleError('Aturan wajib memiliki id dan title')
  const level = LEVELS.includes(doc.level as Level) ? (doc.level as Level) : 'medium'
  const logsource = (doc.logsource ?? {}) as Logsource
  return {
    id: doc.id,
    kind,
    title: doc.title,
    description: typeof doc.description === 'string' ? doc.description.trim() : '',
    level,
    status: typeof doc.status === 'string' ? doc.status : undefined,
    author: typeof doc.author === 'string' ? doc.author : undefined,
    tags: asStringList(doc.tags).map((t) => t.toLowerCase()),
    references: asStringList(doc.references),
    falsepositives: asStringList(doc.falsepositives),
    respons: asStringList(doc.respons),
    logsource: { product: logsource.product, category: logsource.category, service: logsource.service },
  }
}

function logsourceMatches(rule: Logsource, event: Logsource): boolean {
  return (['product', 'category', 'service'] as const).every((key) => !rule[key] || rule[key]!.toLowerCase() === event[key]?.toLowerCase())
}

export function compileSigma(doc: Record<string, unknown>): CompiledRule {
  const meta = parseRuleMeta(doc, 'sigma')
  const detection = doc.detection as Record<string, unknown> | undefined
  if (!detection || typeof detection !== 'object') throw new RuleError('Bagian detection tidak ada')
  const { condition, timeframe, ...rawSelections } = detection
  if (timeframe) throw new RuleError('timeframe belum didukung')
  const conditions = asStringList(condition)
  if (!conditions.length) throw new RuleError('condition tidak ada')

  const names = Object.keys(rawSelections)
  const selections = new Map(names.map((name) => [name, compileSelection(name, rawSelections[name])]))
  const tree: Node = conditions.length === 1 ? parseCondition(conditions[0]) : { op: 'or', args: conditions.map(parseCondition) }
  const positive = positiveNames(tree, names)
  const negated = positiveNames(tree, names, false)
  for (const name of [...positive, ...negated]) if (!selections.has(name)) throw new RuleError(`Selection "${name}" tidak didefinisikan`)

  return {
    meta,
    match(event) {
      if (!logsourceMatches(meta.logsource, event.logsource)) return null
      const cache = new Map<string, boolean>()
      const matchedBy = new Map<string, Record<string, string>>()
      const evalName = (name: string): boolean => {
        let hit = cache.get(name)
        if (hit === undefined) {
          const sel = selections.get(name)
          if (!sel) throw new RuleError(`Selection "${name}" tidak didefinisikan`)
          const matched: Record<string, string> = {}
          hit = evalSelection(sel, event.fields, matched)
          cache.set(name, hit)
          if (hit) matchedBy.set(name, matched)
        }
        return hit
      }
      const evalNode = (node: Node): boolean => {
        switch (node.op) {
          case 'ref':
            return evalName(node.name)
          case 'of': {
            const targets = resolveNames(node.pattern, names)
            return node.quantifier === 'all' ? targets.length > 0 && targets.every(evalName) : targets.some(evalName)
          }
          case 'not':
            return !evalNode(node.arg)
          case 'and':
            return node.args.every(evalNode)
          case 'or':
            return node.args.some(evalNode)
        }
      }
      if (!evalNode(tree)) return null
      const matched: Record<string, string> = {}
      for (const [name, fields] of matchedBy) if (positive.has(name)) Object.assign(matched, fields)
      return matched
    },
  }
}

export type LoadResult = { rules: CompiledRule[]; skipped: { source: string; reason: string }[] }

/** Parses YAML rule documents (several per file allowed, separated by `---`). */
export function loadSigmaRules(sources: Record<string, string>): LoadResult {
  const rules: CompiledRule[] = []
  const skipped: LoadResult['skipped'] = []
  for (const [source, text] of Object.entries(sources)) {
    let docs: unknown[]
    try {
      docs = loadAll(text)
    } catch (err) {
      skipped.push({ source, reason: `YAML tidak valid: ${(err as Error).message}` })
      continue
    }
    for (const doc of docs) {
      if (!doc || typeof doc !== 'object') continue
      try {
        rules.push(compileSigma(doc as Record<string, unknown>))
      } catch (err) {
        skipped.push({ source: `${source}#${(doc as { id?: string }).id ?? '?'}`, reason: (err as Error).message })
      }
    }
  }
  return { rules, skipped }
}
