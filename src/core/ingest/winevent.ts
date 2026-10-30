import type { FieldValue, Logsource, NormalizedEvent } from '@/core/model'
import { basename, cleanIp, flatten, normalizeUser, parseTimestamp, toNumber, truncate } from '@/core/ingest/util'

/**
 * Windows Event Log records exported as JSON (one object per line), as produced by
 * `collector/sigap-collect.ps1` or `Get-WinEvent | ConvertTo-Json`. Accepts both nested
 * `EventData` and flat records.
 */
export type WinEventRecord = Record<string, unknown>

const SYSMON = 'microsoft-windows-sysmon/operational'
const POWERSHELL = 'microsoft-windows-powershell/operational'

const SYSMON_CATEGORY: Record<number, string> = {
  1: 'process_creation',
  3: 'network_connection',
  7: 'image_load',
  11: 'file_event',
  13: 'registry_set',
  22: 'dns_query',
}

function logsourceFor(channel: string, eventId: number): Logsource {
  const ch = channel.toLowerCase()
  if (ch === 'security') return { product: 'windows', service: 'security', category: eventId === 4688 ? 'process_creation' : undefined }
  if (ch === SYSMON) return { product: 'windows', service: 'sysmon', category: SYSMON_CATEGORY[eventId] }
  if (ch === POWERSHELL) return { product: 'windows', service: 'powershell', category: eventId === 4104 ? 'ps_script' : undefined }
  if (ch === 'system') return { product: 'windows', service: 'system' }
  if (ch === 'windows powershell') return { product: 'windows', service: 'powershell-classic' }
  return { product: 'windows', service: ch || undefined }
}

function str(value: FieldValue | undefined): string | undefined {
  return value === null || value === undefined || value === '' ? undefined : String(value)
}

function describe(eventId: number, logsource: Logsource, f: Record<string, FieldValue>): string {
  const proc = basename(str(f.Image))
  switch (logsource.category) {
    case 'process_creation':
      return truncate(`${basename(str(f.ParentImage)) ?? '?'} → ${proc ?? '?'}: ${str(f.CommandLine) ?? ''}`)
    case 'network_connection':
      return `${proc ?? '?'} terhubung ke ${str(f.DestinationIp) ?? '?'}:${str(f.DestinationPort) ?? '?'}`
    case 'file_event':
      return truncate(`${proc ?? '?'} membuat berkas ${str(f.TargetFilename) ?? '?'}`)
    case 'dns_query':
      return `${proc ?? '?'} meminta DNS ${str(f.QueryName) ?? '?'}`
    case 'ps_script':
      return truncate(`Script PowerShell: ${str(f.ScriptBlockText) ?? ''}`)
  }
  switch (eventId) {
    case 4624:
      return `Logon berhasil (tipe ${str(f.LogonType) ?? '?'}) ${str(f.TargetUserName) ?? '?'} dari ${str(f.IpAddress) ?? 'lokal'}`
    case 4625:
      return `Logon gagal ${str(f.TargetUserName) ?? '?'} dari ${str(f.IpAddress) ?? 'lokal'}`
    case 4634:
      return `Logoff ${str(f.TargetUserName) ?? '?'}`
    case 5140:
      return `Akses share ${str(f.ShareName) ?? '?'} oleh ${str(f.SubjectUserName) ?? '?'} dari ${str(f.IpAddress) ?? '?'}`
    case 7045:
      return `Layanan baru dipasang: ${str(f.ServiceName) ?? '?'} (${str(f.ImagePath) ?? '?'})`
    case 1102:
      return 'Log keamanan dihapus'
    case 4720:
      return `Akun baru dibuat: ${str(f.TargetUserName) ?? '?'}`
  }
  return `EventID ${eventId} (${str(f.Channel) ?? 'Windows'})`
}

export function normalizeWinEvent(record: WinEventRecord, id: string, importId: string): NormalizedEvent | null {
  const data = { ...((record.EventData as object) ?? {}), ...((record.UserData as object) ?? {}) } as Record<string, unknown>
  const flat = { ...record }
  delete flat.EventData
  delete flat.UserData

  const eventId = toNumber(record.EventID ?? record.Id ?? record.EventId)
  const ts = parseTimestamp(record.TimeCreated ?? record['@timestamp'] ?? record.TimeGenerated ?? data.UtcTime)
  if (eventId === undefined || ts === undefined) return null

  const channel = String(record.Channel ?? record.LogName ?? '')
  const computer = String(record.Computer ?? record.MachineName ?? record.Hostname ?? '') || undefined

  const fields: Record<string, FieldValue> = {
    ...flatten(flat),
    ...flatten(data),
    EventID: eventId,
    Channel: channel,
    Provider_Name: String(record.ProviderName ?? record.Provider_Name ?? record.Provider ?? ''),
    Computer: computer ?? null,
  }
  delete fields.Id
  delete fields.ProviderName
  // Security 4688 uses different names than Sysmon 1; alias them so one rule covers both.
  if (eventId === 4688) {
    fields.Image ??= fields.NewProcessName ?? null
    fields.ParentImage ??= fields.ParentProcessName ?? null
  }

  const logsource = logsourceFor(channel, eventId)
  const sha256 = /SHA256=([0-9a-f]{64})/i.exec(str(fields.Hashes) ?? '')?.[1]?.toLowerCase()
  const targetFile = str(fields.TargetFilename)

  return {
    id,
    ts,
    dataset: 'winevent',
    sourceKind: 'endpoint',
    logsource,
    // `WS-MIN-03.satuan.local` -> `WS-MIN-03`, so the same machine matches across log sources.
    host: computer?.split('.')[0].toUpperCase(),
    user: normalizeUser(fields.User ?? fields.TargetUserName ?? fields.SubjectUserName),
    srcIp: cleanIp(fields.IpAddress ?? fields.SourceIp),
    dstIp: cleanIp(fields.DestinationIp),
    dstPort: toNumber(fields.DestinationPort),
    process: fields.Image || fields.CommandLine
      ? { name: basename(str(fields.Image)), cmdline: str(fields.CommandLine), parent: basename(str(fields.ParentImage)), pid: toNumber(fields.ProcessId) }
      : undefined,
    file: targetFile || sha256 ? { name: basename(targetFile), path: targetFile, sha256 } : undefined,
    domain: str(fields.QueryName),
    message: describe(eventId, logsource, fields),
    importId,
    fields,
  }
}
