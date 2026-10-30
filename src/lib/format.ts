const TZ = 'Asia/Jakarta'

const timeFmt = new Intl.DateTimeFormat('id-ID', { timeZone: TZ, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
const dateFmt = new Intl.DateTimeFormat('id-ID', { timeZone: TZ, day: 'numeric', month: 'short', year: 'numeric' })
const numberFmt = new Intl.NumberFormat('id-ID')

/** `09:13:02.554` in WIB. */
export function fmtTime(ts: number, withMs = true): string {
  const base = timeFmt.format(ts).replace(/\./g, ':')
  return withMs ? `${base}.${String(ts % 1000).padStart(3, '0')}` : base
}

/** `2 Nov 2026` in WIB. */
export function fmtDate(ts: number): string {
  return dateFmt.format(ts)
}

export function fmtDateTime(ts: number): string {
  return `${fmtDate(ts)} · ${fmtTime(ts, false)} WIB`
}

/** `01:01:56` for a duration in ms. */
export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  return [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60].map((n) => String(n).padStart(2, '0')).join(':')
}

export function fmtNumber(n: number): string {
  return numberFmt.format(n)
}

export function shortHash(hash: string): string {
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`
}
