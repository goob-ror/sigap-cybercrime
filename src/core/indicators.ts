import { ipv4ToInt } from '@/core/net'

/**
 * Threat lists a unit brings in itself, such as a URLhaus host file downloaded with its own account and
 * carried over on USB. They are matched here, offline, so an air-gapped unit gets reputation data and no
 * lookup ever leaves the browser. SIGAP ships no lists: their licences do not clearly allow bundling them.
 */

export type IndicatorList = {
  id: string
  name: string
  importedAt: number
  importedBy: string
  sha256: string
  domains: string[]
  ips: string[]
  hashes: string[]
  /** Lines that were not recognizable as an indicator. */
  skipped: number
}

export type ParsedList = Pick<IndicatorList, 'domains' | 'ips' | 'hashes' | 'skipped'>

/** The rule that reads these lists looks at addresses in any log, so it has this in place of a log source. */
export const INDICATOR_LOGSOURCE = 'daftar-indikator'

const MAX_INDICATORS = 500_000
const SHA256_RE = /^[a-f0-9]{64}$/i
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,23}$/i
const URL_RE = /\bhttps?:\/\/[^\s"',<>]+/i
const COMMENT_RE = /^\s*(#|;|\/\/|!|\$|@\s)/
const HOSTS_RE = /^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)/

const cleanHost = (raw: string) => raw.trim().replace(/\.+$/, '').toLowerCase()

/** Reads host files, DNS zone (RPZ) lines, CSV feeds with a URL column, and plain lists. */
export function parseIndicatorList(text: string): ParsedList {
  const domains = new Set<string>()
  const ips = new Set<string>()
  const hashes = new Set<string>()
  let skipped = 0
  const addHost = (raw: string) => {
    const host = cleanHost(raw)
    if (ipv4ToInt(host) !== null) ips.add(host)
    else if (DOMAIN_RE.test(host)) domains.add(host)
    else return false
    return true
  }
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || COMMENT_RE.test(line)) continue
    if (domains.size + ips.size + hashes.size >= MAX_INDICATORS) break
    const hosts = HOSTS_RE.exec(line)
    if (hosts) {
      if (!addHost(hosts[1])) skipped++
      continue
    }
    const url = URL_RE.exec(line)
    if (url) {
      try {
        if (addHost(new URL(url[0]).hostname)) continue
      } catch {
        // Falls through to being counted as skipped.
      }
      skipped++
      continue
    }
    const first = line.split(/[\s,;]+/)[0].replace(/^["']|["']$/g, '')
    if (SHA256_RE.test(first)) hashes.add(first.toLowerCase())
    else if (!addHost(first)) skipped++
  }
  return { domains: [...domains], ips: [...ips], hashes: [...hashes], skipped }
}

export type IndicatorIndex = { domains: Map<string, string>; ips: Map<string, string>; hashes: Map<string, string> }

/** Indicator -> the name of the first list holding it, for matching many events quickly. */
export function indexLists(lists: readonly IndicatorList[]): IndicatorIndex {
  const index: IndicatorIndex = { domains: new Map(), ips: new Map(), hashes: new Map() }
  for (const list of lists) {
    for (const v of list.domains) if (!index.domains.has(v)) index.domains.set(v, list.name)
    for (const v of list.ips) if (!index.ips.has(v)) index.ips.set(v, list.name)
    for (const v of list.hashes) if (!index.hashes.has(v)) index.hashes.set(v, list.name)
  }
  return index
}

/** The list that names this host or one of its parent domains. A listed domain covers its subdomains. */
export function matchHost(host: string, index: IndicatorIndex): { indicator: string; list: string } | null {
  const clean = cleanHost(host)
  const ip = index.ips.get(clean)
  if (ip) return { indicator: clean, list: ip }
  const labels = clean.split('.')
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join('.')
    const list = index.domains.get(candidate)
    if (list) return { indicator: candidate, list }
  }
  return null
}
