/**
 * Firewall and router logs that are not key=value: MikroTik RouterOS (very common in Indonesia),
 * pfSense filterlog, and Cisco ASA/FTD. Each becomes the same key=value record FortiGate-style logs
 * produce (`srcip`, `dstip`, `dstport`, `action`, ...), so one set of rules and one normalizer covers them.
 * `action` is `login-failure` / `login-success` for logins to the device itself.
 */

const MONTHS: Record<string, string> = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06', jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' }
const DAY_MS = 24 * 60 * 60_000

type Head = { date?: string; time?: string; tz?: string; month?: string; day?: string; rest: string }
export type FirewallContext = { year: number; offset: string; now: number }
export type FirewallRecord = Record<string, string>

// `<166>`, then ISO, `Nov  3 08:00:00`, `Nov 03 2026 08:00:00:`, or RouterOS `nov/03/2026 08:00:00` / `2026-11-03 08:00:00`.
const HEAD_RE = /^(?:<\d{1,3}>)?(?:(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?:?\s+|([A-Za-z]{3})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}:\d{2}:\d{2}):?\s+|([a-z]{3})\/(\d{2})(?:\/(\d{4}))?\s+(\d{2}:\d{2}:\d{2})\s+)?(.*)$/

function parseHead(line: string): Head {
  const m = HEAD_RE.exec(line)
  if (!m) return { rest: line }
  const rest = m[12]
  if (m[1]) return { date: m[1], time: m[2], tz: m[3], rest }
  if (m[4]) return { month: m[4], day: m[5], date: m[6] ? `${m[6]}-${MONTHS[m[4].toLowerCase()] ?? '01'}-${m[5].padStart(2, '0')}` : undefined, time: m[7], rest }
  if (m[8]) return { month: m[8], day: m[9], date: m[10] ? `${m[10]}-${MONTHS[m[8]] ?? '01'}-${m[9].padStart(2, '0')}` : undefined, time: m[11], rest }
  return { rest }
}

/** Date and time fields of the record. A line without a year falls in the past, not next December. */
function timeFields(head: Head, ctx: FirewallContext): FirewallRecord {
  if (!head.time) return {}
  let date = head.date
  if (!date && head.month && head.day) {
    const month = MONTHS[head.month.toLowerCase()]
    if (!month) return {}
    date = `${ctx.year}-${month}-${head.day.padStart(2, '0')}`
    if (Date.parse(`${date}T${head.time}${ctx.offset}`) > ctx.now + DAY_MS) date = `${ctx.year - 1}-${month}-${head.day.padStart(2, '0')}`
  }
  if (!date) return {}
  return { date, time: head.time, ...(head.tz ? { tz: head.tz === 'Z' ? '+00:00' : head.tz } : {}) }
}

const hostBefore = (rest: string, index: number) => rest.slice(0, index).trim().split(/\s+/).at(-1) || ''

function mikrotik(rest: string): FirewallRecord | null {
  const fw = /(?:^|\s)firewall,[\w,]+\s+(.*)$/.exec(rest)
  if (fw) {
    // `out:` can read `(unknown 0)` for traffic to the router itself.
    const m = /(\S+): in:(.*?) out:(.*?),.*?proto (\S+?)(?: \([^)]*\))?, ([\d.]+)(?::(\d+))?->([\d.]+)(?::(\d+))?/.exec(fw[1])
    if (!m) return null
    return { devname: hostBefore(rest, fw.index + 1), chain: m[1], srcintf: m[2], dstintf: m[3], proto: m[4], srcip: m[5], dstip: m[7], ...(m[8] ? { dstport: m[8] } : {}), ...(m[6] ? { srcport: m[6] } : {}), action: 'log', vendor: 'mikrotik' }
  }
  const sys = /(?:^|\s)(system|account)[,\w]*\s+/.exec(rest)
  if (!sys) return null
  const devname = hostBefore(rest, sys.index + 1)
  const failed = /login failure for user (\S+) from (\S+) via (\S+)/.exec(rest)
  if (failed) return { devname, user: failed[1], srcip: failed[2], service: failed[3], action: 'login-failure', vendor: 'mikrotik' }
  const ok = /user (\S+) logged in from (\S+) via (\S+)/.exec(rest)
  if (ok) return { devname, user: ok[1], srcip: ok[2], service: ok[3], action: 'login-success', vendor: 'mikrotik' }
  return null
}

function pfsense(rest: string): FirewallRecord | null {
  const m = /(?:^|\s)filterlog(?:\[\d+\])?:\s*(.*)$/.exec(rest)
  if (!m) return null
  const c = m[1].split(',')
  const v6 = c[8] === '6'
  // The columns after the IP version differ between IPv4 and IPv6.
  const [proto, src, dst, sport, dport] = v6 ? [c[12], c[15], c[16], c[17], c[18]] : [c[16], c[18], c[19], c[20], c[21]]
  if (!src || !dst) return null
  return { devname: hostBefore(rest, m.index + 1), srcintf: c[4] ?? '', action: c[6] ?? 'log', direction: c[7] ?? '', proto: proto ?? '', srcip: src, dstip: dst, ...(/^\d+$/.test(sport ?? '') ? { srcport: sport } : {}), ...(/^\d+$/.test(dport ?? '') ? { dstport: dport } : {}), vendor: 'pfsense' }
}

function ciscoAsa(rest: string): FirewallRecord | null {
  const m = /%(?:ASA|FTD|PIX)-(\d)-(\d{6}):?\s*(.*)$/.exec(rest)
  if (!m) return null
  const devname = rest.slice(0, m.index).replace(/[:\s]+$/, '').split(/\s+/).at(-1) ?? ''
  const base: FirewallRecord = { devname, asa_id: m[2], asa_severity: m[1], msg: m[3], vendor: 'cisco' }
  const body = m[3]
  const ep = (s: string) => s.split('/')
  let x: RegExpExecArray | null
  if ((x = /^Built (inbound|outbound) (\w+) connection \d+ for \S+?:(\S+) \(.*?\) to \S+?:(\S+) \(/.exec(body))) {
    // ASA names the lower-security side first, so "outbound" means the second address started it.
    const [from, to] = x[1] === 'outbound' ? [ep(x[4]), ep(x[3])] : [ep(x[3]), ep(x[4])]
    return { ...base, action: 'accept', proto: x[2].toLowerCase(), srcip: from[0], srcport: from[1] ?? '', dstip: to[0], dstport: to[1] ?? '' }
  }
  if ((x = /^Deny (\w+) src \S+?:(\S+) dst \S+?:(\S+)/.exec(body))) {
    const [from, to] = [ep(x[2]), ep(x[3])]
    return { ...base, action: 'deny', proto: x[1].toLowerCase(), srcip: from[0], srcport: from[1] ?? '', dstip: to[0], dstport: to[1] ?? '' }
  }
  if ((x = /^Deny inbound (\w+) from (\S+) to (\S+)/.exec(body))) {
    const [from, to] = [ep(x[2]), ep(x[3])]
    return { ...base, action: 'deny', proto: x[1].toLowerCase(), srcip: from[0], srcport: from[1] ?? '', dstip: to[0], dstport: to[1] ?? '' }
  }
  if ((x = /^Login (denied|permitted) from (\S+) to \S+ for user "?([^"\s]+)"?/.exec(body))) {
    return { ...base, action: x[1] === 'denied' ? 'login-failure' : 'login-success', srcip: ep(x[2])[0], user: x[3] }
  }
  // Other messages stay readable in the Log Explorer, with no addresses to draw conclusions from.
  return { ...base, action: 'event' }
}

/** Key=value record of a firewall line, or null when it is none of the supported formats. */
export function parseFirewallLine(line: string, ctx: FirewallContext): FirewallRecord | null {
  const head = parseHead(line)
  const record = ciscoAsa(head.rest) ?? pfsense(head.rest) ?? mikrotik(head.rest)
  if (!record) return null
  const clean = Object.fromEntries(Object.entries(record).filter(([, v]) => v !== ''))
  return { ...timeFields(head, ctx), ...clean }
}

const SNIFF_CONTEXT: FirewallContext = { year: 2000, offset: '+07:00', now: 0 }
export const isFirewallLine = (line: string) => parseFirewallLine(line, SNIFF_CONTEXT) !== null
