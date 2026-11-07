import type { RuleMeta } from '@/core/detect/sigma'
import { INDICATOR_LOGSOURCE } from '@/core/indicators'
import type { Logsource, NormalizedEvent } from '@/core/model'

/**
 * What the imported logs let the rules see. "No findings" means something only next to this: on a
 * Windows PC without Sysmon, most of the Windows rules have nothing to read, and an operator without
 * an analyst must not take that silence for a clean bill of health.
 */

/** What the SIGAP collector recorded about one collection (`info-pengumpulan.json`). */
export type CollectionInfo = {
  computer?: string
  administrator?: boolean
  /** Logs the collector could not read. */
  unread: string[]
  /** Logs that hit the event limit, so older events are missing. */
  truncated: string[]
}

export type Family = 'windows' | 'linux' | 'web' | 'network'
export type SourceStatus = 'ada' | 'sebagian' | 'tidak-ada'

export type CoverageSource = {
  id: string
  label: string
  family: Family
  /** Rules that read this source. */
  rules: number
  rulesWithData: number
  status: SourceStatus
  /** How to get this data. Only useful before the next incident: logs that were not kept cannot be recovered. */
  fix: string
}

export type Coverage = {
  rulesTotal: number
  rulesWithData: number
  sources: CoverageSource[]
  /** Sources missing from a kind of log the operator did import: the gaps that are easy to overlook. */
  gaps: CoverageSource[]
  warnings: string[]
  /** Nothing was left out of the kinds of log imported. */
  complete: boolean
}

type SourceDef = { id: string; label: string; family: Family; fix: string; covers: (ls: Logsource) => boolean }

const SOURCES: SourceDef[] = [
  { id: 'win-process', label: 'Pembuatan proses Windows', family: 'windows', fix: 'Pasang Sysmon, atau aktifkan "Audit Process Creation" dan "Include command line in process creation events" lewat Group Policy.', covers: (ls) => ls.category === 'process_creation' },
  { id: 'win-network', label: 'Koneksi dan DNS per proses', family: 'windows', fix: 'Pasang Sysmon.', covers: (ls) => ls.category === 'network_connection' || ls.category === 'dns_query' },
  { id: 'win-file', label: 'Berkas dan registry', family: 'windows', fix: 'Pasang Sysmon.', covers: (ls) => ls.category === 'file_event' || ls.category === 'registry_set' },
  { id: 'win-script', label: 'Blok skrip PowerShell', family: 'windows', fix: 'Aktifkan "Turn on PowerShell Script Block Logging" lewat Group Policy.', covers: (ls) => ls.category === 'ps_script' },
  { id: 'win-security', label: 'Log Security Windows', family: 'windows', fix: 'Jalankan pengumpul sebagai Administrator.', covers: (ls) => ls.product === 'windows' && (ls.service === 'security' || (!ls.service && !ls.category)) },
  { id: 'win-system', label: 'Log System Windows', family: 'windows', fix: 'Sertakan log System saat mengumpulkan.', covers: (ls) => ls.service === 'system' },
  { id: 'win-defender', label: 'Log Microsoft Defender', family: 'windows', fix: 'Sertakan log Windows Defender saat mengumpulkan. Pengumpul SIGAP sudah melakukannya.', covers: (ls) => !!ls.service?.includes('defender') },
  { id: 'web', label: 'Access log server web', family: 'web', fix: 'Impor access log dari server web.', covers: (ls) => ls.category === 'webserver' },
  { id: 'linux-auth', label: 'Log auth Linux', family: 'linux', fix: 'Impor /var/log/auth.log atau /var/log/secure.', covers: (ls) => ls.product === 'linux' && ls.service === 'auth' },
  { id: 'linux-commands', label: 'Perintah yang dijalankan di Linux', family: 'linux', fix: 'Aktifkan auditd dengan aturan execve, lalu impor /var/log/audit/audit.log.', covers: (ls) => ls.product === 'linux' && ls.service !== 'auth' },
  { id: 'firewall', label: 'Log firewall', family: 'network', fix: 'Kirim log firewall atau router ke syslog, lalu impor.', covers: (ls) => ls.category === 'firewall' },
  { id: 'zeek', label: 'Sensor jaringan Zeek', family: 'network', fix: 'Pasang sensor Zeek pada port mirror, lalu impor lognya.', covers: (ls) => ls.product === 'zeek' },
]

type Seen = { logsource: Logsource; commandLine: boolean; command: boolean }

function matches(rule: Logsource, event: Logsource): boolean {
  return (['product', 'category', 'service'] as const).every((key) => !rule[key] || rule[key]!.toLowerCase() === event[key]?.toLowerCase())
}

function hasData(rule: RuleMeta, seen: readonly Seen[]): boolean {
  if (rule.logsource.category === INDICATOR_LOGSOURCE) return seen.length > 0
  // These rules name no service, yet read only the Security and System logs (`Channel`).
  const channelOnly = rule.logsource.product === 'windows' && !rule.logsource.service && !rule.logsource.category
  return seen.some((s) => {
    if (!matches(rule.logsource, s.logsource)) return false
    if (channelOnly && s.logsource.service !== 'security' && s.logsource.service !== 'system') return false
    // Security 4688 without the command-line policy has processes but not what they were told to do.
    if (rule.fields?.includes('CommandLine') && !s.commandLine) return false
    if (rule.fields?.includes('command') && !s.command) return false
    return true
  })
}

export function computeCoverage(events: readonly NormalizedEvent[], rules: readonly RuleMeta[], collections: readonly CollectionInfo[] = []): Coverage {
  const seen = new Map<string, Seen>()
  for (const e of events) {
    const key = `${e.logsource.product}|${e.logsource.service}|${e.logsource.category}`
    let s = seen.get(key)
    if (!s) seen.set(key, (s = { logsource: e.logsource, commandLine: false, command: false }))
    if (!s.commandLine && e.fields.CommandLine) s.commandLine = true
    if (!s.command && e.fields.command) s.command = true
  }
  const seenList = [...seen.values()]

  const counted = rules.map((rule) => ({ rule, source: SOURCES.find((d) => d.covers(rule.logsource)), data: hasData(rule, seenList) }))
  const sources: CoverageSource[] = SOURCES.flatMap((def) => {
    const own = counted.filter((c) => c.source === def)
    if (!own.length) return []
    const withData = own.filter((c) => c.data).length
    const status: SourceStatus = withData === own.length ? 'ada' : withData ? 'sebagian' : 'tidak-ada'
    return [{ id: def.id, label: def.label, family: def.family, fix: def.fix, rules: own.length, rulesWithData: withData, status }]
  })

  const imported = new Set(sources.filter((s) => s.status !== 'tidak-ada').map((s) => s.family))
  if (collections.length) imported.add('windows')
  const gaps = sources.filter((s) => imported.has(s.family) && s.status !== 'ada')

  const warnings: string[] = []
  for (const c of collections) {
    const where = c.computer ? ` di ${c.computer}` : ''
    if (c.unread.length) warnings.push(`Tidak terbaca saat dikumpulkan${where}: ${c.unread.join(', ')}.${c.administrator === false ? ' Pengumpul tidak dijalankan sebagai Administrator.' : ''}`)
    if (c.truncated.length) warnings.push(`Batas jumlah event tercapai${where}, event yang lebih lama tidak ikut: ${c.truncated.join(', ')}.`)
  }

  return {
    rulesTotal: rules.length,
    rulesWithData: counted.filter((c) => c.data).length,
    sources,
    gaps,
    warnings,
    complete: gaps.length === 0 && warnings.length === 0,
  }
}

/** Reads the collector's `info-pengumpulan.json`. Anything unexpected in it is ignored rather than trusted. */
export function parseCollectionInfo(text: string): CollectionInfo | undefined {
  let raw: unknown
  try {
    raw = JSON.parse(text.replace(/^﻿/, ''))
  } catch {
    return undefined
  }
  if (!raw || typeof raw !== 'object') return undefined
  const info = raw as Record<string, unknown>
  const logs = Array.isArray(info.log) ? (info.log as Record<string, unknown>[]) : info.log && typeof info.log === 'object' ? [info.log as Record<string, unknown>] : []
  const status = (l: Record<string, unknown>) => String(l.status ?? '')
  return {
    computer: typeof info.komputer === 'string' ? info.komputer : undefined,
    administrator: typeof info.administrator === 'boolean' ? info.administrator : undefined,
    unread: logs.filter((l) => status(l) === 'perlu-administrator' || status(l).startsWith('gagal')).map((l) => String(l.channel)),
    truncated: logs.filter((l) => l.terpotong === true).map((l) => String(l.channel)),
  }
}
