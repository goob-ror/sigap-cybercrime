/**
 * Adapters for the common ways Windows event logs get exported to JSON, so an operator can bring
 * whatever they have. Each one is brought to the shape `normalizeWinEvent` reads:
 * `{ EventID, Channel, Computer, TimeCreated, ProviderName, EventRecordID, EventData }`.
 *
 * - SIGAP collector / NXLog / generic: `EventData` already present (left as is)
 * - PowerShell `Get-WinEvent | ConvertTo-Json`: `Id`, `LogName`, `MachineName`, `Message`. At the
 *   default depth `Properties` are only type names, so fields are read from the message text.
 * - PowerShell `Get-EventLog | ConvertTo-Json`: `EventID`, `Source`, `MachineName`, `Message`
 * - Winlogbeat / Elastic (ECS): `winlog.event_id`, `winlog.event_data`, `@timestamp`
 * - evtx_dump (Rust): `Event.System`, `Event.EventData`
 * - EvtxECmd (Eric Zimmerman): `EventId`, `Payload` (JSON text of the event data)
 */

type Rec = Record<string, unknown>

const isObject = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v)

/** Channel for exports that only name the provider (e.g. `Get-EventLog`). */
const CHANNEL_BY_PROVIDER: Record<string, string> = {
  'microsoft-windows-security-auditing': 'Security',
  'microsoft-windows-eventlog': 'Security',
  'service control manager': 'System',
  'microsoft-windows-sysmon': 'Microsoft-Windows-Sysmon/Operational',
  'microsoft-windows-powershell': 'Microsoft-Windows-PowerShell/Operational',
}

/** True when a JSON record looks like a Windows event in any supported export. */
export function isWinEventRecord(r: Rec): boolean {
  if ('EventData' in r || 'winlog' in r) return true
  if (isObject(r.Event) && isObject(r.Event.System)) return true
  if ('Payload' in r && 'EventId' in r) return true
  return ('EventID' in r || 'Id' in r || 'EventId' in r) && ('Channel' in r || 'Computer' in r || 'LogName' in r || 'MachineName' in r)
}

/** Labels in Windows Security/System event messages -> EventData field names. `section|label` wins over `label`. */
const MESSAGE_FIELDS: Record<string, string> = {
  'subject|account name': 'SubjectUserName',
  'subject|account domain': 'SubjectDomainName',
  'creator subject|account name': 'SubjectUserName',
  'creator subject|account domain': 'SubjectDomainName',
  'target subject|account name': 'TargetUserName',
  'new logon|account name': 'TargetUserName',
  'new logon|account domain': 'TargetDomainName',
  'account for which logon failed|account name': 'TargetUserName',
  'account for which logon failed|account domain': 'TargetDomainName',
  'new account|account name': 'TargetUserName',
  'new account|account domain': 'TargetDomainName',
  'logon type': 'LogonType',
  'workstation name': 'WorkstationName',
  'source network address': 'IpAddress',
  'source address': 'IpAddress',
  'source port': 'IpPort',
  'logon process': 'LogonProcessName',
  'authentication package': 'AuthenticationPackageName',
  'new process name': 'NewProcessName',
  'process command line': 'CommandLine',
  'creator process name': 'ParentProcessName',
  'share name': 'ShareName',
  'share path': 'ShareLocalPath',
  'service name': 'ServiceName',
  'service file name': 'ImagePath',
  'service type': 'ServiceType',
  'service start type': 'StartType',
  'service account': 'AccountName',
  'failure reason': 'FailureReason',
  status: 'Status',
  'sub status': 'SubStatus',
}

/**
 * Reads event fields from the rendered message text. Sysmon messages are `Name: value` lines that
 * use the EventData names directly; Security and System messages use English labels grouped in
 * sections ("New Logon:", "Network Information:"), mapped by `MESSAGE_FIELDS`.
 */
export function parseEventMessage(eventId: number | undefined, message: string): Rec {
  const lines = message.split(/\r?\n/)
  if (eventId === 4104) {
    // "Creating Scriptblock text (1 of 1):", the script itself, then "ScriptBlock ID: …".
    const end = lines.findIndex((l) => /^ScriptBlock ID:/i.test(l.trim()))
    const script = lines.slice(1, end === -1 ? undefined : end).join('\n').trim()
    const id = end === -1 ? undefined : lines[end].split(':').slice(1).join(':').trim()
    return { ScriptBlockText: script, ...(id ? { ScriptBlockId: id } : {}) }
  }
  const out: Rec = {}
  let section = ''
  for (const raw of lines) {
    const m = /^\s*([^:\t]+?):[ \t]*(.*)$/.exec(raw)
    if (!m) continue
    const label = m[1].trim()
    const value = m[2].trim()
    if (!value) {
      section = label.toLowerCase()
      continue
    }
    const key = label.toLowerCase()
    const field = MESSAGE_FIELDS[`${section}|${key}`] ?? MESSAGE_FIELDS[key] ?? (/^[A-Za-z]+$/.test(label) ? label : undefined)
    if (field && !(field in out)) out[field] = value
  }
  return out
}

/** `[{ "@Name": "SubjectUserSid", "#text": "S-1-5-18" }, …]` -> `{ SubjectUserSid: "S-1-5-18" }`. */
function namedData(data: unknown): Rec {
  const items = Array.isArray(data) ? data : data ? [data] : []
  const out: Rec = {}
  for (const item of items) if (isObject(item) && typeof item['@Name'] === 'string') out[item['@Name']] = item['#text'] ?? null
  return out
}

function textOf(v: unknown): unknown {
  return isObject(v) && '#text' in v ? v['#text'] : v
}

/** Brings any supported export to the shape `normalizeWinEvent` reads. */
export function unwrapWinRecord(r: Rec): Rec {
  // Winlogbeat / Elastic Common Schema.
  if (isObject(r.winlog)) {
    const w = r.winlog
    return {
      EventID: w.event_id,
      Channel: w.channel,
      Computer: w.computer_name ?? (isObject(r.host) ? r.host.name : undefined),
      TimeCreated: r['@timestamp'],
      ProviderName: w.provider_name,
      EventRecordID: w.record_id,
      EventData: isObject(w.event_data) ? w.event_data : {},
      ...(isObject(w.user_data) ? { UserData: w.user_data } : {}),
    }
  }
  // evtx_dump.
  if (isObject(r.Event) && isObject(r.Event.System)) {
    const s = r.Event.System
    const provider = isObject(s.Provider) && isObject(s.Provider['#attributes']) ? s.Provider['#attributes'].Name : undefined
    const created = isObject(s.TimeCreated) && isObject(s.TimeCreated['#attributes']) ? s.TimeCreated['#attributes'].SystemTime : s.TimeCreated
    return {
      EventID: textOf(s.EventID),
      Channel: s.Channel,
      Computer: s.Computer,
      TimeCreated: created,
      ProviderName: provider,
      EventRecordID: s.EventRecordID,
      EventData: isObject(r.Event.EventData) ? r.Event.EventData : {},
      ...(isObject(r.Event.UserData) ? { UserData: r.Event.UserData } : {}),
    }
  }
  // EvtxECmd.
  if (typeof r.Payload === 'string' && 'EventId' in r) {
    let data: Rec = {}
    try {
      const payload = JSON.parse(r.Payload) as Rec
      if (isObject(payload.EventData)) data = namedData(payload.EventData.Data)
    } catch {
      // Payload is optional context; the record is still usable without it.
    }
    return { EventID: r.EventId, Channel: r.Channel, Computer: r.Computer, TimeCreated: r.TimeCreated, ProviderName: r.Provider, EventRecordID: r.EventRecordId, EventData: data }
  }
  if ('EventData' in r || 'UserData' in r) return r

  // PowerShell exports: fields only in the rendered message.
  const eventId = Number(r.EventID ?? r.Id ?? r.EventId)
  const provider = String(r.ProviderName ?? r.Source ?? '')
  const channel = r.Channel ?? r.LogName ?? CHANNEL_BY_PROVIDER[provider.toLowerCase()]
  const fromMessage = typeof r.Message === 'string' ? parseEventMessage(Number.isFinite(eventId) ? eventId : undefined, r.Message) : {}
  // Get-EventLog's EventID can carry the facility bits; the low 16 bits are the event id.
  const id = 'Source' in r && Number.isFinite(eventId) ? eventId & 0xffff : r.EventID ?? r.Id ?? r.EventId
  return {
    ...r,
    EventID: id,
    Channel: channel,
    Computer: r.Computer ?? r.MachineName,
    TimeCreated: r.TimeCreated ?? r.TimeGenerated,
    ProviderName: provider || undefined,
    EventRecordID: r.EventRecordID ?? r.RecordId ?? r.Index,
    EventData: fromMessage,
  }
}
