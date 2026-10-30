import { describe, expect, it } from 'vitest'
import { ingestText, sniffFormat } from '@/core/ingest'
import { parseKvLine } from '@/core/ingest/kv'

const sysmon1 = JSON.stringify({
  TimeCreated: '2026-11-02T09:13:02.554+07:00',
  EventID: 1,
  Channel: 'Microsoft-Windows-Sysmon/Operational',
  ProviderName: 'Microsoft-Windows-Sysmon',
  Computer: 'WS-MIN-03.satuan.local',
  EventRecordID: 7,
  EventData: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -enc AAA', ParentImage: 'C:\\Office16\\WINWORD.EXE', User: 'SATUAN\\sertu.rina' },
})

const zeekTsv = [
  '#separator \\x09',
  '#set_separator\t,',
  '#empty_field\t(empty)',
  '#unset_field\t-',
  '#path\tmodbus_detailed',
  '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tunit\tfunc\taddress\tvalues',
  '1793586980.150000\tCabc\t10.20.1.5\t50200\t10.40.7.22\t502\t1\tWRITE_SINGLE_REGISTER\t10\t265',
].join('\n')

const fwLine = '<189>date=2026-11-02 time=09:44:09 devname="FW-SATUAN" tz="+0700" srcip=10.20.1.5 dstip=198.51.100.23 dstport=443 action="close" service="HTTPS" hostname="files-drop.example" sentbyte=327155712'

describe('sniffFormat', () => {
  it('recognizes each supported format', () => {
    expect(sniffFormat(sysmon1)).toBe('winevent-jsonl')
    expect(sniffFormat(zeekTsv)).toBe('zeek-tsv')
    expect(sniffFormat('{"ts":1793586980.1,"uid":"Cx","id.orig_h":"10.0.0.1"}')).toBe('zeek-json')
    expect(sniffFormat(fwLine)).toBe('kv-syslog')
    expect(sniffFormat('hello world')).toBe('unknown')
  })
})

describe('Windows events', () => {
  it('normalizes a Sysmon process creation', () => {
    const { events, errorCount } = ingestText(sysmon1, 'ws.jsonl', 'imp1')
    expect(errorCount).toBe(0)
    const e = events[0]
    expect(e).toMatchObject({ id: 'imp1:1', host: 'WS-MIN-03', user: 'sertu.rina', dataset: 'winevent', logsource: { product: 'windows', service: 'sysmon', category: 'process_creation' } })
    expect(e.process).toMatchObject({ name: 'powershell.exe', parent: 'WINWORD.EXE' })
    expect(e.ts).toBe(Date.parse('2026-11-02T02:13:02.554Z'))
    expect(e.fields.Image).toContain('powershell.exe')
  })

  it('maps Security 4688 fields onto Sysmon names', () => {
    const line = JSON.stringify({ TimeCreated: '2026-11-02T09:00:00+07:00', EventID: 4688, Channel: 'Security', Computer: 'SRV', EventData: { NewProcessName: 'C:\\x\\cmd.exe', ParentProcessName: 'C:\\x\\WINWORD.EXE', CommandLine: 'cmd /c whoami' } })
    const e = ingestText(line, 'a.jsonl', 'i').events[0]
    expect(e.logsource.category).toBe('process_creation')
    expect(e.fields.Image).toBe('C:\\x\\cmd.exe')
    expect(e.fields.ParentImage).toBe('C:\\x\\WINWORD.EXE')
  })

  it('reports broken lines without stopping', () => {
    const { events, errors } = ingestText(`${sysmon1}\nnot json\n${sysmon1}`, 'ws.jsonl', 'i')
    expect(events).toHaveLength(2)
    expect(errors).toEqual([{ line: 2, message: 'JSON tidak valid' }])
  })
})

describe('Zeek', () => {
  it('parses TSV Modbus records into OT events', () => {
    const { events } = ingestText(zeekTsv, 'zeek-modbus_detailed.log', 'z')
    expect(events[0]).toMatchObject({ dataset: 'zeek.modbus_detailed', sourceKind: 'ot', srcIp: '10.20.1.5', dstIp: '10.40.7.22', dstPort: 502, ot: { func: 'WRITE_SINGLE_REGISTER', register: 10, value: 265, unitId: 1 } })
    expect(events[0].ts).toBe(1793586980150)
  })

  it('infers the log type of JSON records from their fields', () => {
    const { events } = ingestText('{"ts":1793586980.1,"uid":"Cx","id.orig_h":"10.20.4.13","id.resp_h":"10.20.1.2","query":"cdn-tukin.example","qtype_name":"A","answers":["203.0.113.66"]}', 'x.json', 'z')
    expect(events[0]).toMatchObject({ dataset: 'zeek.dns', domain: 'cdn-tukin.example' })
  })
})

describe('firewall key=value', () => {
  it('parses quoted values and the PRI header', () => {
    expect(parseKvLine(fwLine)).toMatchObject({ devname: 'FW-SATUAN', hostname: 'files-drop.example', sentbyte: '327155712' })
  })

  it('applies the tz field when building the timestamp', () => {
    const e = ingestText(fwLine, 'fw.log', 'f').events[0]
    expect(e.ts).toBe(Date.parse('2026-11-02T02:44:09Z'))
    expect(e).toMatchObject({ host: 'FW-SATUAN', srcIp: '10.20.1.5', dstIp: '198.51.100.23', domain: 'files-drop.example', logsource: { category: 'firewall' } })
  })
})
