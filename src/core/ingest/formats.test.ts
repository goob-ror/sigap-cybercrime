import { describe, expect, it } from 'vitest'
import { ingestText, sniffFormat } from '@/core/ingest'
import { isEvtx, parseEvtx } from '@/core/ingest/evtx'
import { readLogFile } from '@/core/ingest/util'
import { runDetections } from '@/core/detect/engine'
import { loadRulePack } from '@/data/rules'

const pack = loadRulePack()
const fired = (text: string, name = 'log.txt') => new Set(runDetections(ingestText(text, name, 'i').events, pack).map((d) => d.ruleId))

describe('IIS', () => {
  const iis = [
    '#Software: Microsoft Internet Information Services 10.0',
    '#Version: 1.0',
    '#Date: 2026-11-03 01:00:00',
    '#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken',
    '2026-11-03 01:00:00 10.0.0.5 GET /a.aspx id=1%20union%20select%201 80 - 198.51.100.7 sqlmap/1.8 200 0 0 15',
    '2026-11-03 01:00:05 10.0.0.5 POST /uploads/shell.aspx - 80 - 198.51.100.7 Mozilla/5.0+(Windows+NT+10.0) 200 0 0 15',
  ].join('\n')

  it('reads the columns its header names, with times in UTC', () => {
    const { format, events, errorCount } = ingestText(iis, 'web-1-u_ex261103.log', 'i')
    expect(format).toBe('iis-w3c')
    expect(errorCount).toBe(0)
    expect(events[0]).toMatchObject({ ts: Date.UTC(2026, 10, 3, 1, 0, 0), srcIp: '198.51.100.7', dataset: 'web.access', fields: { 'cs-method': 'GET', 'sc-status': 200, 'c-uri': '/a.aspx?id=1 union select 1' } })
    expect(events[1].fields['cs-user-agent']).toBe('Mozilla/5.0 (Windows NT 10.0)')
  })

  it('runs the same web rules', () => {
    expect(fired(iis)).toEqual(new Set(['sigap-web-sqli', 'sigap-web-scanner', 'sigap-web-webshell']))
  })

  it('does not take the date in u_ex261103.log for a server name', () => {
    expect(ingestText(iis, 'u_ex261103.log', 'i').events[0].host).toBe('10.0.0.5')
  })
})

describe('firewalls and routers', () => {
  const now = Date.UTC(2026, 10, 6)
  const read = (line: string) => ingestText(line, 'fw.log', 'i', { now, defaultYear: 2026 })

  it('reads MikroTik firewall logs', () => {
    const { format, events } = read('Nov  3 08:00:00 192.168.88.1 firewall,info forward: in:ether2 out:ether1, src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 10.0.0.5:51515->198.51.100.9:502, len 60')
    expect(format).toBe('firewall-syslog')
    expect(events[0]).toMatchObject({ srcIp: '10.0.0.5', dstIp: '198.51.100.9', dstPort: 502, host: '192.168.88.1', logsource: { category: 'firewall' }, ts: Date.UTC(2026, 10, 3, 1, 0, 0) })
    expect(fired('Nov  3 08:00:00 192.168.88.1 firewall,info forward: in:ether2 out:ether1, proto TCP (SYN), 10.0.0.5:51515->10.40.7.22:502, len 60')).toContain('sigap-fw-it-to-modbus')
  })

  it('reads RouterOS exports without a syslog host', () => {
    const { events } = read('nov/03/2026 08:00:00 firewall,info input: in:ether1 out:(unknown 0), proto UDP, 198.51.100.9:1234->10.0.0.1:53, len 60')
    expect(events[0]).toMatchObject({ srcIp: '198.51.100.9', dstPort: 53, ts: Date.UTC(2026, 10, 3, 1, 0, 0) })
  })

  it('catches password guessing against a MikroTik and a login from the internet', () => {
    const lines = Array.from({ length: 5 }, (_, i) => `Nov  3 08:00:0${i} 192.168.88.1 system,error,critical login failure for user admin from 198.51.100.9 via winbox`)
    expect(fired(lines.join('\n'))).toContain('sigap-native-device-login-brute')
    expect(fired('Nov  3 08:00:00 192.168.88.1 system,info,account user admin logged in from 198.51.100.9 via ssh')).toContain('sigap-fw-admin-login-external')
    expect(fired('Nov  3 08:00:00 192.168.88.1 system,info,account user admin logged in from 192.168.88.5 via ssh')).toEqual(new Set())
  })

  it('reads pfSense filterlog, which otherwise looks like plain syslog', () => {
    const { format, events } = read('Nov  3 08:00:00 pfsense filterlog[99]: 5,,,1000000103,em0,match,block,in,4,0x0,,64,1,0,none,6,tcp,60,198.51.100.9,10.0.0.5,443,51515,0,S')
    expect(format).toBe('firewall-syslog')
    expect(events[0]).toMatchObject({ srcIp: '198.51.100.9', dstIp: '10.0.0.5', dstPort: 51515, fields: { action: 'block', proto: 'tcp' } })
  })

  it('reads Cisco ASA, with the direction of an outbound connection the right way round', () => {
    const { events } = read('<166>Nov 03 2026 08:00:00: %ASA-6-302013: Built outbound TCP connection 1 for outside:198.51.100.9/443 (198.51.100.9/443) to inside:10.0.0.5/51515 (10.0.0.5/51515)')
    expect(events[0]).toMatchObject({ srcIp: '10.0.0.5', dstIp: '198.51.100.9', dstPort: 443, fields: { action: 'accept' } })
    const denied = read('<166>Nov 03 2026 08:00:00 FW-1 : %ASA-4-106023: Deny tcp src outside:198.51.100.9/1234 dst inside:10.0.0.5/443 by access-group "x"').events[0]
    expect(denied).toMatchObject({ host: 'FW-1', srcIp: '198.51.100.9', dstPort: 443, fields: { action: 'deny' } })
  })
})

describe('modern Linux logs', () => {
  it('reads journalctl -o json, and the same SSH rules run on it', () => {
    const line = (user: string, what: string, i: number) => JSON.stringify({ __REALTIME_TIMESTAMP: String(Date.UTC(2026, 10, 3, 1, 0, i) * 1000), _HOSTNAME: 'srv-1', SYSLOG_IDENTIFIER: 'sshd', _PID: '9', MESSAGE: `${what} password for ${user} from 198.51.100.9 port 22 ssh2` })
    const text = [...Array.from({ length: 5 }, (_, i) => line('root', 'Failed', i)), line('root', 'Accepted', 9)].join('\n')
    const { format, events, assumedOffset } = ingestText(text, 'journal.json', 'i')
    expect(format).toBe('journald-json')
    expect(events[0]).toMatchObject({ host: 'SRV-1', ts: Date.UTC(2026, 10, 3, 1, 0, 0), dataset: 'linux.auth', fields: { outcome: 'failure' } })
    expect(assumedOffset).toBeUndefined()
    expect(fired(text)).toEqual(new Set(['sigap-native-ssh-brute-force', 'sigap-native-ssh-success-after-failures']))
  })

  it('reads auditd logins, including hex-encoded values', () => {
    const fail = `type=USER_LOGIN msg=audit(1793585100.000:100): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.9 terminal=ssh res=failed'`
    const hex = `type=USER_LOGIN msg=audit(1793585101.000:101): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=726F6F74 exe="/usr/sbin/sshd" hostname=? addr=198.51.100.9 terminal=ssh res=failed'`
    const { format, events } = ingestText(`${fail}\n${hex}\ntype=CWD msg=audit(1793585101.000:102): cwd="/"`, 'srv-1-audit.log', 'i')
    expect(format).toBe('auditd')
    expect(events).toHaveLength(2)
    expect(events[0]).toMatchObject({ srcIp: '198.51.100.9', ts: 1793585100000, host: 'SRV-1', fields: { program: 'sshd', outcome: 'failure', target_user: 'root' } })
    expect(events[1].fields.target_user).toBe('root')
  })

  it('reads hex-encoded command arguments', () => {
    const { events } = ingestText('type=EXECVE msg=audit(1793585100.000:1): argc=2 a0="ls" a1=2F686F6D652F7361747520647561', 'a.log', 'i')
    expect(events[0].fields.command).toBe('ls /home/satu dua')
  })
})

describe('format detection', () => {
  const good = '198.51.100.7 - - [03/Nov/2026:01:00:00 +0700] "GET /a?id=1%20union%20select%201 HTTP/1.1" 200 512 "-" "sqlmap"'

  it('survives a cut-off first line, reporting just that line', () => {
    const { format, events, errorCount } = ingestText(`HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n${good}\n${good}`, 'web-1-access.log', 'i')
    expect(format).toBe('web-access')
    expect(events).toHaveLength(2)
    expect(errorCount).toBe(1)
  })

  it('decides by majority in a mixed file', () => {
    const syslog = 'Nov  3 08:14:02 srv sshd[1]: Failed password for root from 10.1.1.1 port 1 ssh2'
    expect(sniffFormat(`${good}\n${syslog}\n${syslog}\n${syslog}`)).toBe('linux-syslog')
  })

  it('still reports text it cannot read at all', () => {
    expect(ingestText('hello world\nbukan log', 'x.txt', 'i').format).toBe('unknown')
  })
})

describe('time zones and years', () => {
  const line = 'Nov  3 02:00:00 vps sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2'
  const now = Date.UTC(2026, 10, 6)

  it('applies the zone the operator chose to logs that carry none, and says it did', () => {
    const utc = ingestText(line, 'a.log', 'i', { defaultTzOffset: '+00:00', now })
    expect(utc.events[0].ts).toBe(Date.UTC(2026, 10, 3, 2, 0, 0))
    expect(utc.assumedOffset).toBe('+00:00')
    const wit = ingestText(line, 'a.log', 'i', { defaultTzOffset: '+09:00', now })
    expect(wit.events[0].ts).toBe(Date.UTC(2026, 10, 2, 17, 0, 0))
  })

  it('defaults to WIB and says so', () => {
    const { events, assumedOffset } = ingestText(line, 'a.log', 'i', { now })
    expect(events[0].ts).toBe(Date.UTC(2026, 10, 2, 19, 0, 0))
    expect(assumedOffset).toBe('+07:00')
  })

  it('does not override a zone the log states', () => {
    const { events, assumedOffset } = ingestText('2026-11-03T02:00:00+09:00 srv sshd[1]: x', 'a.log', 'i', { defaultTzOffset: '+00:00', now })
    expect(events[0].ts).toBe(Date.UTC(2026, 10, 2, 17, 0, 0))
    expect(assumedOffset).toBeUndefined()
  })

  it('puts a December log read in January in last year, not next December', () => {
    const { events } = ingestText('Dec 31 23:59:00 srv sshd[1]: x', 'a.log', 'i', { now: Date.UTC(2027, 0, 5) })
    expect(new Date(events[0].ts).getUTCFullYear()).toBe(2026)
    expect(events[0].ts).toBeLessThan(Date.UTC(2027, 0, 5))
  })

  it('also applies to firewall lines without a year', () => {
    const { events, assumedOffset } = ingestText('Dec 31 23:59:00 pfsense filterlog[9]: 5,,,1,em0,match,block,in,4,0x0,,64,1,0,none,6,tcp,60,198.51.100.9,10.0.0.5,443,51515,0,S', 'a.log', 'i', { now: Date.UTC(2027, 0, 5), defaultTzOffset: '+08:00' })
    expect(events[0].ts).toBe(Date.UTC(2026, 11, 31, 15, 59, 0))
    expect(assumedOffset).toBe('+08:00')
  })
})

/** Writes just enough of the `.evtx` format to exercise the reader. No real log is stored in this repo. */
function buildEvtx(records: { eventId: number; data: Record<string, string> }[]): Uint8Array {
  const bytes = new Uint8Array(4096 + 65536)
  const dv = new DataView(bytes.buffer)
  const ascii = (at: number, s: string) => { for (let i = 0; i < s.length; i++) bytes[at + i] = s.charCodeAt(i) }
  ascii(0, 'ElfFile\0')
  const base = 4096
  ascii(base, 'ElfChnk\0')
  let pos = 512 // Relative to the chunk.

  const u8 = (v: number) => { bytes[base + pos] = v; pos += 1 }
  const u16 = (v: number) => { dv.setUint16(base + pos, v, true); pos += 2 }
  const u32 = (v: number) => { dv.setUint32(base + pos, v, true); pos += 4 }
  const utf16 = (s: string) => { for (const c of s) u16(c.charCodeAt(0)) }
  const names = new Map<string, number>()
  /** A name reference: stored in place the first time, by offset afterwards. */
  const nameRef = (name: string, spot: () => void) => {
    const known = names.get(name)
    if (known !== undefined) { u32(known); spot(); return }
    // The offset points just past itself and any field that follows, where the name is written.
    const at = pos
    u32(0)
    spot()
    dv.setUint32(base + at, pos, true)
    names.set(name, pos)
    u32(0); u16(0); u16(name.length); utf16(name); u16(0)
  }
  const open = (name: string, hasAttrs: boolean) => {
    u8(hasAttrs ? 0x41 : 0x01); u16(0); u32(0)
    nameRef(name, () => { if (hasAttrs) u32(0) })
  }
  const attr = (name: string, emitValue: () => void) => { u8(0x06); nameRef(name, () => {}); emitValue() }
  const text = (s: string) => { u8(0x05); u8(0x01); u16(s.length); utf16(s) }
  const sub = (id: number, type: number) => { u8(0x0d); u16(id); u8(type) }
  const closeStart = () => u8(0x02)
  const closeEmpty = () => u8(0x03)
  const end = () => u8(0x04)
  const element = (name: string, body: () => void) => { open(name, false); closeStart(); body(); end() }

  for (const [index, record] of records.entries()) {
    const start = pos
    dv.setUint32(base + pos, 0x00002a2a, true); pos += 4
    const sizeAt = pos; pos += 4
    dv.setBigUint64(base + pos, BigInt(index + 1), true); pos += 8
    dv.setBigUint64(base + pos, 134_062_272_000_000_000n, true); pos += 8
    u8(0x0f); u8(1); u8(1); u8(0) // Fragment header.

    // A template instance whose definition follows in place, as the first record of a chunk does.
    u8(0x0c); u8(1); u32(1)
    const definitionAt = pos
    u32(pos + 4) // Definition offset: right after this field.
    u32(0); pos += 16 // Next template, GUID.
    const bodySizeAt = pos; pos += 4
    const bodyStart = pos
    u8(0x0f); u8(1); u8(1); u8(0)
    element('Event', () => {
      element('System', () => {
        open('Provider', true); attr('Name', () => text('Uji-Provider')); closeEmpty()
        element('EventID', () => sub(0, 0x06))
        element('Level', () => sub(1, 0x04))
        open('TimeCreated', true); attr('SystemTime', () => sub(2, 0x11)); closeEmpty()
        element('EventRecordID', () => sub(3, 0x0a))
        element('Channel', () => text('Security'))
        element('Computer', () => text('WS-UJI.satuan.local'))
      })
      element('EventData', () => sub(4, 0x21))
    })
    u8(0x00)
    dv.setUint32(base + bodySizeAt, pos - bodyStart, true)
    void definitionAt

    // Substitution values, one of them nested binary XML holding the named data.
    const values: { type: number; write: () => void }[] = [
      { type: 0x06, write: () => u16(record.eventId) },
      { type: 0x04, write: () => u8(4) },
      { type: 0x11, write: () => { dv.setBigUint64(base + pos, 134_062_272_000_000_000n, true); pos += 8 } },
      { type: 0x0a, write: () => { dv.setBigUint64(base + pos, BigInt(index + 1), true); pos += 8 } },
      { type: 0x21, write: () => {
        u8(0x0f); u8(1); u8(1); u8(0)
        for (const [key, value] of Object.entries(record.data)) {
          open('Data', true); attr('Name', () => text(key)); closeStart(); text(value); end()
        }
        u8(0x00)
      } },
    ]
    u32(values.length)
    const descriptorsAt = pos
    pos += values.length * 4
    values.forEach((v, i) => {
      const at = pos
      v.write()
      dv.setUint16(base + descriptorsAt + i * 4, pos - at, true)
      dv.setUint8(base + descriptorsAt + i * 4 + 2, v.type)
    })
    u8(0x00)
    pos += 4 // Copy of the size, which readers do not need.
    dv.setUint32(base + sizeAt, pos - start, true)
    names.clear() // Each record here defines its own template, so offsets are re-stored for it.
  }
  dv.setUint32(base + 48, pos, true) // Free-space offset: where records end.
  return bytes
}

describe('.evtx', () => {
  const file = buildEvtx([
    { eventId: 4625, data: { TargetUserName: 'admin', IpAddress: '10.1.1.9', LogonType: '3' } },
    { eventId: 4720, data: { TargetUserName: 'pintu.belakang', SubjectUserName: 'admin' } },
  ])

  it('recognizes the file', () => {
    expect(isEvtx(file)).toBe(true)
    expect(isEvtx(new TextEncoder().encode('bukan evtx sama sekali'))).toBe(false)
  })

  it('reads system fields, substitutions and nested named data', () => {
    const { records, errors } = parseEvtx(file)
    expect(errors).toBe(0)
    expect(records).toHaveLength(2)
    expect(records[0]).toMatchObject({ EventID: 4625, Channel: 'Security', Computer: 'WS-UJI.satuan.local', ProviderName: 'Uji-Provider', EventRecordID: '1', Level: 4, EventData: { TargetUserName: 'admin', IpAddress: '10.1.1.9', LogonType: '3' } })
    expect(records[0].TimeCreated).toBe('2025-10-29T16:00:00.0000000Z')
    expect(records[1].EventData.TargetUserName).toBe('pintu.belakang')
  })

  it('becomes ordinary events the rules can read, without any conversion step', async () => {
    const log = await readLogFile(file, 'Security.evtx')
    const { format, events } = ingestText(log.text, log.name, 'i')
    expect(format).toBe('winevent-jsonl')
    expect(events[0]).toMatchObject({ host: 'WS-UJI', user: 'admin', logsource: { service: 'security' }, srcIp: '10.1.1.9' })
    expect(runDetections(events, pack).map((d) => d.ruleId)).toContain('sigap-win-account-created')
  })

  it('counts a damaged record and keeps the rest', () => {
    const damaged = file.slice()
    // Break the first record's body, leaving its header intact so the next one can be found.
    damaged.fill(0xff, 4096 + 512 + 24, 4096 + 512 + 60)
    const { records, errors } = parseEvtx(damaged)
    expect(errors).toBe(1)
    expect(records).toHaveLength(1)
    expect(records[0].EventID).toBe(4720)
  })

  it('reads a truncated file without throwing', () => {
    expect(parseEvtx(file.slice(0, 4096)).records).toEqual([])
  })
})
