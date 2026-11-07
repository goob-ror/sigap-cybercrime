import type { FieldValue, NormalizedEvent } from '@/core/model'
import { cleanIp, normalizeUser, truncate } from '@/core/ingest/util'
import { hostOf } from '@/core/ingest/syslog'

/**
 * Linux auditd (`/var/log/audit/audit.log`). This is the log that shows what was run after a login,
 * which auth.log does not:
 *   type=SYSCALL msg=audit(1793586980.123:456): ... auid=1000 uid=0 exe="/usr/bin/curl"
 *   type=EXECVE msg=audit(1793586980.123:456): argc=2 a0="curl" a1="203.0.113.45/up.sh"
 * Commands appear only where audit rules for `execve` are enabled. Logins are always written.
 */

const LINE_RE = /^(?:node=(\S+) )?type=([A-Z_0-9]+) msg=audit\((\d+)(?:\.(\d+))?:(\d+)\):\s*(.*)$/
const UNSET_UID = '4294967295'

export const isAuditLine = (line: string) => LINE_RE.test(line)

/** A value auditd writes quoted, or as hex when it holds spaces or other special characters. */
function auditValue(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined
  if (raw.startsWith('"')) return raw.slice(1, raw.endsWith('"') ? -1 : undefined)
  if (raw.length >= 2 && raw.length % 2 === 0 && /^[0-9A-F]+$/.test(raw)) {
    let out = ''
    for (let i = 0; i < raw.length; i += 2) out += String.fromCharCode(parseInt(raw.slice(i, i + 2), 16))
    return out
  }
  return raw
}

function pairs(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const m of text.matchAll(/([A-Za-z_0-9]+)=("[^"]*"|'[^']*'|\S+)/g)) out[m[1]] = m[2]
  return out
}

export function parseAuditLog(text: string, host: string | undefined, importId: string): { events: NormalizedEvent[]; errors: { line: number; message: string }[] } {
  const events: NormalizedEvent[] = []
  const errors: { line: number; message: string }[] = []
  // A record's SYSCALL line names who ran it; it comes just before the EXECVE line with the same serial.
  const calls = new Map<string, Record<string, string>>()
  let lineNo = 0
  for (const line of text.split(/\r?\n/)) {
    lineNo++
    if (!line.trim()) continue
    const m = LINE_RE.exec(line)
    if (!m) {
      errors.push({ line: lineNo, message: 'Bukan baris audit' })
      continue
    }
    const [, node, type, seconds, fraction, serial, body] = m
    const ts = Number(seconds) * 1000 + Number((fraction ?? '0').padEnd(3, '0').slice(0, 3))
    const eventHost = node ? hostOf(node) : host
    const id = `${importId}:${lineNo}`
    if (type === 'SYSCALL') {
      calls.set(serial, pairs(body))
      continue
    }
    if (type === 'EXECVE') {
      const p = pairs(body)
      const argc = Number(p.argc) || 0
      const args: string[] = []
      for (let i = 0; i < argc; i++) {
        const value = auditValue(p[`a${i}`])
        if (value !== undefined) args.push(value)
      }
      if (!args.length) continue
      const call = calls.get(serial) ?? {}
      const auid = call.auid && call.auid !== UNSET_UID ? call.auid : undefined
      const command = args.join(' ')
      const fields: Record<string, FieldValue> = { hostname: eventHost ?? null, program: args[0].split('/').pop() ?? args[0], command, uid: call.uid ?? null, auid: auid ?? null, exe: auditValue(call.exe) ?? null, audit_serial: serial }
      events.push({ id, ts, dataset: 'linux.audit', sourceKind: 'server', logsource: { product: 'linux', service: 'auditd' }, host: eventHost, user: auid ? `uid-${auid}` : undefined, process: { name: String(fields.program), cmdline: command }, message: `exec: ${truncate(command, 160)}`, importId, fields })
      calls.delete(serial)
      continue
    }
    if (type !== 'USER_LOGIN' && type !== 'ADD_USER') continue
    // Inside the record, the part that matters is a second quoted msg='...'.
    const inner = pairs(/msg='([^']*)'/.exec(body)?.[1] ?? body)
    const account = auditValue(inner.acct)
    const exe = auditValue(inner.exe)
    const program = exe?.split('/').pop() ?? type.toLowerCase()
    const outcome = inner.res === 'success' ? 'success' : inner.res === 'failed' ? 'failure' : null
    const address = cleanIp(inner.addr === '?' ? undefined : inner.addr)
    const added = type === 'ADD_USER' && outcome === 'success'
    const fields: Record<string, FieldValue> = {
      hostname: eventHost ?? null,
      program: added ? 'useradd' : program,
      message: added ? `new user: name=${account ?? '?'}` : `${inner.op ?? type} ${account ?? '?'} ${inner.res ?? ''}`.trim(),
      outcome,
      target_user: account ?? null,
      src_ip: address ?? null,
      new_user: added ? account ?? null : null,
    }
    events.push({ id, ts, dataset: 'linux.auth', sourceKind: 'server', logsource: { product: 'linux', service: 'auth' }, host: eventHost, user: normalizeUser(account), srcIp: address, message: `audit ${String(fields.program)}: ${String(fields.message)}`, importId, fields })
  }
  return { events, errors }
}
