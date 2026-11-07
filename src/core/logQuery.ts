import type { NormalizedEvent, SourceKind } from '@/core/model'

/**
 * Log Explorer search. Several parts must all match. A part is free text, or `column:value`, where
 * the column is a shortcut below or any original log field (`EventID:4688`, `id.orig_h:10.0.0.5`).
 * A `name:value` whose name is not a column stays free text, so `C:\Windows` and `10.0.0.5:443` work.
 */

export type LogTerm = { raw: string; field?: string; value: string }

export type LogFilter = {
  terms: LogTerm[]
  kind: SourceKind | null
  dataset: string | null
  host: string | null
  /** Epoch ms, inclusive. */
  from: number | null
  to: number | null
  /** When set, only these event ids (the ones that triggered a rule). */
  only: ReadonlySet<string> | null
}

const SHORTCUTS: Record<string, (e: NormalizedEvent) => unknown[]> = {
  host: (e) => [e.host],
  user: (e) => [e.user],
  akun: (e) => [e.user],
  ip: (e) => [e.srcIp, e.dstIp],
  src: (e) => [e.srcIp],
  sumber: (e) => [e.srcIp],
  dst: (e) => [e.dstIp],
  tujuan: (e) => [e.dstIp],
  port: (e) => [e.dstPort],
  dataset: (e) => [e.dataset],
  domain: (e) => [e.domain],
  url: (e) => [e.url],
  proses: (e) => [e.process?.name, e.process?.cmdline],
  berkas: (e) => [e.file?.name, e.file?.path],
}

/** `host:"WS 03" gagal "logon gagal"` -> three terms. Quotes keep a phrase together. */
export function parseLogQuery(text: string): LogTerm[] {
  const terms: LogTerm[] = []
  for (const m of text.matchAll(/([^\s:"]+):"([^"]*)"|"([^"]*)"|(\S+)/g)) {
    if (m[1] !== undefined) {
      if (m[2]) terms.push({ raw: m[0].toLowerCase(), field: m[1].toLowerCase(), value: m[2].toLowerCase() })
    } else if (m[3] !== undefined) {
      if (m[3]) terms.push({ raw: m[3].toLowerCase(), value: m[3].toLowerCase() })
    } else {
      const raw = m[4].toLowerCase()
      const pair = /^([\w.@-]+):(.+)$/.exec(raw)
      terms.push(pair ? { raw, field: pair[1], value: pair[2] } : { raw, value: raw })
    }
  }
  return terms
}

/** Numbers match exactly (`EventID:46` is not 4688); text matches anywhere in the value. */
function valueMatches(value: unknown, needle: string): boolean {
  if (value === null || value === undefined) return false
  if (typeof value === 'number') return String(value) === needle
  return String(value).toLowerCase().includes(needle)
}

function searchableText(e: NormalizedEvent): string {
  return [e.message, e.host, e.user, e.srcIp, e.dstIp, e.dstPort, e.domain, e.url, e.dataset, e.process?.name, e.process?.cmdline, e.process?.parent, e.process?.sha256, e.file?.path, e.file?.sha256, ...Object.values(e.fields)]
    .filter((v) => v !== null && v !== undefined)
    .join('\n')
    .toLowerCase()
}

export function matchesLogTerms(event: NormalizedEvent, terms: readonly LogTerm[]): boolean {
  let text: string | undefined
  for (const term of terms) {
    if (term.field !== undefined) {
      const shortcut = SHORTCUTS[term.field]
      const fieldKey = Object.keys(event.fields).find((k) => k.toLowerCase() === term.field)
      if (shortcut || fieldKey !== undefined) {
        const hit = (shortcut?.(event) ?? []).some((v) => valueMatches(v, term.value)) || (fieldKey !== undefined && valueMatches(event.fields[fieldKey], term.value))
        if (!hit) return false
        continue
      }
    }
    text ??= searchableText(event)
    if (!text.includes(term.raw)) return false
  }
  return true
}

/** The check every event must pass, or null when only the time range (or nothing) applies. */
export function logPredicate(filter: LogFilter): ((event: NormalizedEvent) => boolean) | null {
  const { terms, kind, dataset, host, only } = filter
  if (!terms.length && !kind && !dataset && !host && !only) return null
  return (e) => (!kind || e.sourceKind === kind) && (!dataset || e.dataset === dataset) && (!host || e.host === host) && (!only || only.has(e.id)) && matchesLogTerms(e, terms)
}

/**
 * `<input type="datetime-local">` value, read as WIB like every time the app shows, to epoch ms.
 * With `endOfMinute`, a minute-precision value covers that whole minute (for an inclusive end).
 */
export function wibInputToMs(value: string, endOfMinute = false): number | null {
  if (!value) return null
  const minutePrecision = value.length === 16
  const t = Date.parse(`${value}${minutePrecision ? ':00' : ''}+07:00`)
  if (Number.isNaN(t)) return null
  return endOfMinute && minutePrecision ? t + 59_999 : t
}
