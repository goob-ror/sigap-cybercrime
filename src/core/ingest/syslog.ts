import type { FieldValue, NormalizedEvent } from '@/core/model'
import { cleanIp, normalizeUser, toNumber, truncate } from '@/core/ingest/util'

/**
 * Linux auth / syslog lines (`/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`), with
 * RFC 3339 timestamps (current Debian/Ubuntu rsyslog) or classic BSD ones (no year, local time):
 *   `2026-11-02T13:24:05.120+07:00 web-satuan-01 sshd[4120]: Failed password for root from 203.0.113.45 port 50122 ssh2`
 *   `Nov  2 13:24:05 web-satuan-01 sshd[4120]: Accepted password for admin from 203.0.113.45 port 50190 ssh2`
 * Messages from sshd, sudo, useradd, usermod/gpasswd and su get structured fields; any other line
 * is kept with its program and text, so nothing is lost.
 */

export type SyslogLine = { iso?: string; month?: string; day?: string; clock?: string; hostname: string; program: string; pid?: number; message: string }

const SYSLOG_RE = /^(?:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)|([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})) (\S+) ([^\s:[]+)(?:\[(\d+)\])?: ?(.*)$/

const MONTHS: Record<string, string> = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' }

export function parseSyslogLine(line: string): SyslogLine | null {
  const m = SYSLOG_RE.exec(line)
  if (!m || (m[2] && !MONTHS[m[2]])) return null
  return { iso: m[1], month: m[2], day: m[3], clock: m[4], hostname: m[5], program: m[6], pid: toNumber(m[7]), message: m[8] }
}

/** Epoch ms. BSD timestamps carry no year or zone, so both come from the import options. */
export function syslogTime(s: SyslogLine, defaultYear: number, defaultOffset: string): number | undefined {
  let text: string
  if (s.iso) {
    text = s.iso
      .replace(/(\.\d{3})\d+/, '$1') // keep milliseconds only
      .replace(/([+-]\d{2})(\d{2})$/, '$1:$2')
    if (!/(Z|[+-]\d{2}:\d{2})$/.test(text)) text += defaultOffset
  } else {
    text = `${defaultYear}-${MONTHS[s.month!]}-${s.day!.padStart(2, '0')}T${s.clock}${defaultOffset}`
  }
  const t = Date.parse(text)
  return Number.isNaN(t) ? undefined : t
}

/** `web-satuan-01.satuan.local` -> `WEB-SATUAN-01`; addresses are kept as they are. */
function hostOf(hostname: string): string {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':') ? hostname : hostname.split('.')[0].toUpperCase()
}

type AuthInfo = {
  outcome?: 'success' | 'failure'
  method?: string
  user?: string
  invalid?: boolean
  ip?: string
  port?: number
  command?: string
  runAs?: string
  newUser?: string
  group?: string
}

function authInfo(program: string, msg: string): AuthInfo {
  const p = program.toLowerCase()
  let m: RegExpExecArray | null
  if (p === 'sshd') {
    if ((m = /^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)/.exec(msg))) return { outcome: 'failure', method: m[1], invalid: !!m[2], user: m[3], ip: m[4], port: Number(m[5]) }
    if ((m = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/.exec(msg))) return { outcome: 'success', method: m[1], user: m[2], ip: m[3], port: Number(m[4]) }
    if ((m = /^Invalid user (\S*) from (\S+)(?: port (\d+))?/.exec(msg))) return { outcome: 'failure', invalid: true, user: m[1] || undefined, ip: m[2], port: toNumber(m[3]) }
    if ((m = /from (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*) port (\d+)/i.exec(msg))) return { ip: m[1], port: Number(m[2]) }
    return {}
  }
  if (p === 'sudo') {
    if ((m = /^\s*(\S+) : (?:.*?; )?TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)$/.exec(msg))) {
      const failed = /incorrect password|NOT in sudoers|authentication failure/i.test(msg)
      return { user: m[1], runAs: m[2], command: m[3].trim(), outcome: failed ? 'failure' : 'success' }
    }
    return {}
  }
  if (p === 'useradd' && (m = /new user: name=([^,\s]+)/.exec(msg))) return { newUser: m[1], user: m[1] }
  if ((p === 'usermod' || p === 'gpasswd') && (m = /add '([^']+)' to (?:shadow )?group '([^']+)'|user (\S+) added by \S+ to group (\S+)/.exec(msg))) {
    return { user: m[1] ?? m[3], group: m[2] ?? m[4] }
  }
  if (p === 'su') {
    if ((m = /^\(to (\S+)\) (\S+) on/.exec(msg)) || (m = /^Successful su for (\S+) by (\S+)/.exec(msg))) return { outcome: 'success', runAs: m[1], user: m[2] }
    if ((m = /^FAILED su for (\S+) by (\S+)/.exec(msg))) return { outcome: 'failure', runAs: m[1], user: m[2] }
  }
  return {}
}

export function normalizeSyslog(s: SyslogLine, id: string, importId: string, defaultYear: number, defaultOffset: string): NormalizedEvent | null {
  const ts = syslogTime(s, defaultYear, defaultOffset)
  if (ts === undefined) return null
  const info = authInfo(s.program, s.message)
  const fields: Record<string, FieldValue> = {
    hostname: s.hostname,
    program: s.program,
    pid: s.pid ?? null,
    message: s.message,
    outcome: info.outcome ?? null,
    auth_method: info.method ?? null,
    target_user: info.user ?? null,
    invalid_user: info.invalid ?? null,
    src_ip: info.ip ?? null,
    src_port: info.port ?? null,
    command: info.command ?? null,
    run_as: info.runAs ?? null,
    new_user: info.newUser ?? null,
    group: info.group ?? null,
  }
  return {
    id,
    ts,
    dataset: 'linux.auth',
    sourceKind: 'server',
    logsource: { product: 'linux', service: 'auth' },
    host: hostOf(s.hostname),
    // Usernames that do not exist on the host (brute force guesses) are not accounts worth tracking.
    user: info.invalid ? undefined : normalizeUser(info.user),
    srcIp: cleanIp(info.ip),
    message: `${s.program}: ${truncate(s.message, 160)}`,
    importId,
    fields,
  }
}
