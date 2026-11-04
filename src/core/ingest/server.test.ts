import { describe, expect, it } from 'vitest'
import { ingestText, sniffFormat } from '@/core/ingest'
import { isGzip, readLogFile } from '@/core/ingest/util'
import { decodeUri, hostFromFilename } from '@/core/ingest/weblog'
import { parseSyslogLine, syslogTime } from '@/core/ingest/syslog'
import { runDetections } from '@/core/detect/engine'
import type { NormalizedEvent } from '@/core/model'
import { loadRulePack } from '@/data/rules'

const pack = loadRulePack()
const fired = (events: NormalizedEvent[]) => new Set(runDetections(events, pack).map((d) => d.ruleId))
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0'
const access = (ip: string, sec: number, target: string, status = 200, method = 'GET', ua = UA) =>
  `${ip} - - [02/Nov/2026:13:${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')} +0700] "${method} ${target} HTTP/1.1" ${status} 512 "-" "${ua}"`
const web = (lines: string[], name = 'web-01-access.log') => ingestText(lines.join('\n'), name, 't').events

describe('web access log', () => {
  it('parses combined lines into Sigma webserver fields', () => {
    const [e] = web([access('203.0.113.45', 5, '/berita.php?id=7%27%20AND%20SLEEP(5)--+-')])
    expect(e.ts).toBe(Date.UTC(2026, 10, 2, 6, 0, 5))
    expect(e.host).toBe('WEB-01')
    expect(e.srcIp).toBe('203.0.113.45')
    expect(e.sourceKind).toBe('server')
    expect(e.fields['c-uri']).toBe("/berita.php?id=7' AND SLEEP(5)-- -")
    expect(e.fields['cs-uri-stem']).toBe('/berita.php')
    expect(e.fields['c-uri-raw']).toBe('/berita.php?id=7%27%20AND%20SLEEP(5)--+-')
    expect(e.fields['sc-status']).toBe(200)
    expect(e.domain).toBeUndefined()
  })

  it('accepts common format, vhost prefix and IPv6 clients', () => {
    const lines = [
      '198.51.100.7 - - [02/Nov/2026:08:00:00 +0700] "GET / HTTP/1.1" 200 1024',
      'satuan.example:443 198.51.100.8 - - [02/Nov/2026:08:00:01 +0700] "GET /profil HTTP/1.1" 200 99 "-" "x"',
      '2001:db8::5 - - [02/Nov/2026:08:00:02 +0700] "GET /kontak HTTP/1.1" 404 0 "-" "x"',
    ]
    const events = web(lines)
    expect(events).toHaveLength(3)
    expect(events[1].fields['cs-host']).toBe('satuan.example')
    expect(events[2].fields['c-ip']).toBe('2001:db8::5')
  })

  it('decodes twice so double-encoded payloads are readable', () => {
    expect(decodeUri('%252e%252e%252fetc%252fpasswd')).toBe('../etc/passwd')
    expect(decodeUri('a+b', true)).toBe('a b')
    expect(decodeUri('%zz%41')).toBe('%zzA')
  })

  it('derives the server name from the file name', () => {
    expect(hostFromFilename('web-satuan-01-nginx-access.log')).toBe('WEB-SATUAN-01')
    expect(hostFromFilename('satuan-contoh.example-Nov-2026.gz')).toBe('satuan-contoh.example')
    expect(hostFromFilename('logs/satuan-contoh.example-ssl_log')).toBe('satuan-contoh.example')
    expect(hostFromFilename('access.log')).toBeUndefined()
    expect(hostFromFilename('access.log.1')).toBeUndefined()
  })

  it('detects injection, traversal, scanners and web shells', () => {
    const events = web([
      access('203.0.113.9', 1, '/berita.php?id=-7%20UNION%20ALL%20SELECT%20NULL,@@version--'),
      access('203.0.113.9', 2, '/download.php?f=..%2F..%2F..%2Fetc%2Fpasswd'),
      access('203.0.113.9', 3, '/cari?q=%3Cscript%3Ealert(1)%3C/script%3E'),
      access('203.0.113.9', 4, '/', 200, 'GET', 'sqlmap/1.8.2#stable'),
      access('203.0.113.9', 5, '/.env', 404),
      access('203.0.113.9', 6, '/uploads/2026/11/foto.php?cmd=id'),
    ])
    for (const id of ['sigap-web-sqli', 'sigap-web-traversal', 'sigap-web-xss', 'sigap-web-scanner', 'sigap-web-sensitive-files', 'sigap-web-webshell']) {
      expect(fired(events), id).toContain(id)
    }
  })

  it('does not flag a missing script in the uploads folder or ordinary browsing', () => {
    const events = web([
      access('198.51.100.7', 1, '/uploads/lama.php', 404),
      access('198.51.100.7', 2, '/uploads/2026/11/apel-pagi.jpg'),
      access('198.51.100.7', 3, '/berita.php?id=12'),
      access('198.51.100.7', 4, '/cari?q=jadwal+upacara+select+tim'),
    ])
    expect([...fired(events)]).toEqual([])
  })

  it('counts login guessing and 404 sweeps per source address', () => {
    const brute = Array.from({ length: 10 }, (_, i) => access('203.0.113.9', i * 5, '/admin/login', 401, 'POST'))
    const sweep = Array.from({ length: 20 }, (_, i) => access('203.0.113.10', i * 3, `/coba-${i}/`, 404))
    const few = Array.from({ length: 9 }, (_, i) => access('198.51.100.7', i * 5, '/admin/login', 401, 'POST'))
    const result = runDetections(web([...brute, ...sweep, ...few]), pack)
    expect(result.filter((d) => d.ruleId === 'sigap-native-web-login-brute')).toHaveLength(1)
    expect(result.filter((d) => d.ruleId === 'sigap-native-web-404-scan')).toHaveLength(1)
  })
})

describe('Linux auth log', () => {
  const auth = (lines: string[]) => ingestText(lines.join('\n'), 'auth.log', 't', { defaultYear: 2026 }).events

  it('reads BSD and ISO timestamps', () => {
    const time = (line: string) => syslogTime(parseSyslogLine(line)!, 2026, '+07:00')
    expect(time('Nov  2 13:24:05 web-01 sshd[1]: x')).toBe(Date.UTC(2026, 10, 2, 6, 24, 5))
    expect(time('2026-11-02T13:24:05.120+07:00 web-01 sshd[1]: x')).toBe(Date.UTC(2026, 10, 2, 6, 24, 5, 120))
  })

  it('sniffs auth logs, even when the first line is a sudo command', () => {
    expect(sniffFormat('Nov  2 13:29:02 web-01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash')).toBe('linux-syslog')
    expect(sniffFormat(access('203.0.113.9', 1, '/'))).toBe('web-access')
  })

  it('extracts SSH, sudo and account fields', () => {
    const [failed, invalid, ok, sudo, add, group] = auth([
      'Nov  2 13:24:05 web-01.satuan.example sshd[2101]: Failed password for root from 203.0.113.45 port 50122 ssh2',
      'Nov  2 13:24:20 web-01 sshd[2102]: Invalid user oracle from 203.0.113.45 port 50124',
      'Nov  2 13:26:40 web-01 sshd[2103]: Accepted password for admin from 203.0.113.45 port 50190 ssh2',
      'Nov  2 13:29:02 web-01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash',
      'Nov  2 13:31:00 web-01 useradd[2110]: new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate, shell=/bin/bash',
      "Nov  2 13:31:20 web-01 usermod[2111]: add 'sysupdate' to group 'sudo'",
    ])
    expect(failed.host).toBe('WEB-01')
    expect(failed.fields.outcome).toBe('failure')
    expect(failed.srcIp).toBe('203.0.113.45')
    expect(failed.user).toBe('root')
    expect(invalid.user).toBeUndefined()
    expect(ok.fields.outcome).toBe('success')
    expect(sudo.fields.command).toBe('/bin/bash')
    expect(sudo.fields.run_as).toBe('root')
    expect(add.fields.new_user).toBe('sysupdate')
    expect(group.fields.group).toBe('sudo')
    expect(fired([sudo, add, group])).toEqual(new Set(['sigap-linux-sudo-shell', 'sigap-linux-useradd', 'sigap-linux-priv-group']))
  })

  it('flags SSH guessing, and a login that follows it', () => {
    const guesses = Array.from({ length: 5 }, (_, i) => `Nov  2 13:24:${String(i * 10).padStart(2, '0')} web-01 sshd[${2200 + i}]: Failed password for root from 203.0.113.45 port ${50000 + i} ssh2`)
    const login = 'Nov  2 13:26:40 web-01 sshd[2300]: Accepted password for admin from 203.0.113.45 port 50190 ssh2'
    const ids = fired(auth([...guesses, login]))
    expect(ids).toContain('sigap-native-ssh-brute-force')
    expect(ids).toContain('sigap-native-ssh-success-after-failures')
    // A user mistyping once before logging in is normal.
    const typo = auth(['Nov  2 15:40:06 web-01 sshd[2400]: Failed password for deploy from 10.20.4.30 port 50001 ssh2', 'Nov  2 15:40:12 web-01 sshd[2401]: Accepted password for deploy from 10.20.4.30 port 50002 ssh2'])
    expect([...fired(typo)]).toEqual([])
  })
})

describe('gzip logs', () => {
  it('unpacks .gz files and keeps the inner name', async () => {
    const text = access('203.0.113.45', 1, '/')
    const gz = new Uint8Array(await new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer())
    expect(isGzip(gz)).toBe(true)
    const file = await readLogFile(gz, 'satuan-contoh.example-Nov-2026.gz')
    expect(file.text).toBe(text)
    expect(file.name).toBe('satuan-contoh.example-Nov-2026')
    expect(ingestText(file.text, file.name, 't').events[0].host).toBe('satuan-contoh.example')
  })
})
