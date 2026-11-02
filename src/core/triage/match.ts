import type { NormalizedEvent } from '@/core/model'
import type { IocKind } from '@/core/report/ioc'
import { ipv4ToInt } from '@/core/net'

/**
 * Offline IOC matching: parse indicators out of pasted text (or take them from an incident) and
 * find where they appear in the imported logs. Answers "are these known-bad indicators already in
 * our environment?" — purely over data already in memory, no network.
 */

export type Indicator = { kind: IocKind; value: string }

export type IocMatch = {
  kind: IocKind
  value: string
  /** Events in which the indicator appears. */
  events: NormalizedEvent[]
}

const SHA256_RE = /\b[a-f0-9]{64}\b/gi
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi
// Common file extensions a domain regex would otherwise mistake for a TLD (e.g. "laporan.docx").
const FILE_LABELS = new Set(['exe', 'dll', 'docx', 'xlsx', 'pptx', 'pdf', 'zip', 'rar', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'js', 'vbs', 'ps1', 'bat', 'apk', 'docm', 'xlsm', 'iso', 'img', 'lnk'])

/** Undo common IOC "defanging" so pasted indicators parse: hxxp, [.], (dot), [:]. */
function refang(text: string): string {
  return text
    .replace(/h\s*x\s*x\s*p/gi, 'http')
    .replace(/\[\.\]|\(\.\)|\(dot\)|\s+dot\s+/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[\/\]/g, '/')
}

/** Extract unique IPv4 / domain / sha256 indicators from free text. */
export function parseIndicators(text: string): Indicator[] {
  const refanged = refang(text)
  const out = new Map<string, Indicator>()
  const add = (kind: IocKind, raw: string) => {
    const value = raw.toLowerCase()
    out.set(`${kind}|${value}`, { kind, value })
  }

  // sha256 first, then IPs, then domains — so earlier, more specific matches win their substrings.
  let masked = refanged
  for (const m of refanged.match(SHA256_RE) ?? []) add('sha256', m)
  masked = masked.replace(SHA256_RE, ' ')

  for (const m of masked.match(IPV4_RE) ?? []) {
    if (ipv4ToInt(m) !== null) add('ip', m)
  }
  masked = masked.replace(IPV4_RE, ' ')

  for (const m of masked.match(DOMAIN_RE) ?? []) {
    const tld = m.split('.').at(-1)!.toLowerCase()
    if (!FILE_LABELS.has(tld)) add('domain', m)
  }
  return [...out.values()]
}

function hits(ind: Indicator, e: NormalizedEvent): boolean {
  const v = ind.value
  if (ind.kind === 'ip') return e.srcIp === v || e.dstIp === v
  if (ind.kind === 'domain') return e.domain?.toLowerCase() === v
  return e.process?.sha256?.toLowerCase() === v || e.file?.sha256?.toLowerCase() === v
}

/** For each indicator, the events (time-sorted) in which it appears. */
export function matchIocs(indicators: Indicator[], events: readonly NormalizedEvent[]): IocMatch[] {
  return indicators.map((ind) => ({
    kind: ind.kind,
    value: ind.value,
    events: events.filter((e) => hits(ind, e)).sort((a, b) => a.ts - b.ts),
  }))
}
