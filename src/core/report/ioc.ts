import type { Detection, Incident, IncidentEntity } from '@/core/model'
import { isExternalIp } from '@/core/net'
import { fmtDateTime } from '@/lib/format'

/**
 * Turns an incident's entities into an IOC (indicator of compromise) blocklist a unit can load
 * into its firewall, DNS resolver or endpoint tool to stop the same attack elsewhere — the
 * "mencegah" (prevent) side of the response. Pure and deterministic, built only from incident data;
 * no network, no reputation lookups (offline-first).
 *
 * Deliberately exported indicators: EXTERNAL IPs, domains, and DROPPED-FILE SHA-256 hashes.
 * Deliberately excluded: internal hosts/OT devices, accounts, file names, common infrastructure,
 * and process-image hashes — those are legitimate Windows binaries (powershell.exe, cmd.exe) and
 * blocklisting them would break the unit's own systems.
 */

export type IocKind = 'ip' | 'domain' | 'sha256'

export type Ioc = {
  kind: IocKind
  value: string
  /** Distinct detections that referenced this indicator. */
  detections: number
  firstSeen: number
  /** Distinct rule titles that flagged it, for the CSV context column. */
  rules: string[]
  /**
   * Why this should be looked at rather than blocked: every incident it appears in is either unconfirmed
   * or only attempts. A generated blocklist is loaded by operators who cannot judge each line, so the
   * list says which lines are safe to load as they are.
   */
  review?: string
}

/** Non-routable / internal domain suffixes a unit must never blackhole in its own DNS. */
const INTERNAL_DOMAIN_SUFFIXES = ['.local', '.localdomain', '.internal', '.intranet', '.lan', '.corp', '.home']

/**
 * A domain a unit could meaningfully block upstream: it has a public-looking name (contains a dot)
 * and no internal/non-routable suffix. Mirrors `isExternalIp` so internal AD/service domains
 * (e.g. `srv.satuan.local`) are never written into the exported DNS sinkhole.
 */
export function isExternalDomain(domain: string): boolean {
  const d = domain.trim().toLowerCase().replace(/\.+$/, '')
  if (!d || !d.includes('.') || /\s/.test(d)) return false
  return !INTERNAL_DOMAIN_SUFFIXES.some((s) => d.endsWith(s))
}

/** External addresses, domains and dropped-file hashes — what a unit would block. */
export function isIndicator(e: Pick<IncidentEntity, 'type' | 'value' | 'common'>): boolean {
  if (e.common) return false
  if (e.type === 'hash') return true
  if (e.type === 'domain') return isExternalDomain(e.value)
  if (e.type === 'ip') return isExternalIp(e.value)
  return false
}

const KIND_OF: Partial<Record<IncidentEntity['type'], IocKind>> = { ip: 'ip', domain: 'domain', hash: 'sha256' }
const KIND_ORDER: Record<IocKind, number> = { ip: 0, domain: 1, sha256: 2 }
const KIND_LABEL: Record<IocKind, string> = { ip: 'Alamat IP eksternal', domain: 'Domain', sha256: 'Hash berkas (SHA-256)' }

const WEAK_EVIDENCE: Partial<Record<NonNullable<Incident['assessment']>, string>> = {
  'perlu-konfirmasi': 'hanya muncul pada temuan yang perlu dikonfirmasi',
  'hanya-percobaan': 'hanya percobaan dari luar; blokir bila berulang',
}

function collect(incidents: Incident[], detectionsById: Map<string, Detection>): Ioc[] {
  const acc = new Map<string, { kind: IocKind; value: string; dets: Set<string>; firstSeen: number; rules: Set<string>; review?: string; strong: boolean }>()
  for (const incident of incidents) {
    const weak = incident.assessment && WEAK_EVIDENCE[incident.assessment]
    for (const e of incident.entities) {
      if (!isIndicator(e)) continue
      const kind = KIND_OF[e.type]
      if (!kind) continue
      const value = kind === 'domain' ? e.value.toLowerCase() : e.value
      const key = `${kind}|${value}`
      let a = acc.get(key)
      if (!a) {
        a = { kind, value, dets: new Set(), firstSeen: e.firstSeen, rules: new Set(), strong: false }
        acc.set(key, a)
      }
      a.firstSeen = Math.min(a.firstSeen, e.firstSeen)
      if (weak) a.review ??= weak
      else a.strong = true
      for (const id of e.detectionIds) {
        a.dets.add(id)
        const title = detectionsById.get(id)?.title
        if (title) a.rules.add(title)
      }
    }
  }
  return [...acc.values()]
    .map((a) => ({ kind: a.kind, value: a.value, detections: a.dets.size, firstSeen: a.firstSeen, rules: [...a.rules].sort(), ...(a.review && !a.strong ? { review: a.review } : {}) }))
    .sort((x, y) => KIND_ORDER[x.kind] - KIND_ORDER[y.kind] || x.value.localeCompare(y.value))
}

/** The exportable indicators of one incident. */
export function incidentIocs(incident: Incident, detectionsById: Map<string, Detection>): Ioc[] {
  return collect([incident], detectionsById)
}

/** The exportable indicators across several incidents, de-duplicated by value. */
export function allIocs(incidents: Incident[], detectionsById: Map<string, Detection>): Ioc[] {
  return collect(incidents, detectionsById)
}

/**
 * Blocking these would hurt the unit more than the attacker: government and TNI domains, which may be
 * the unit's own or ones it depends on, plus update, DNS and messaging services any script may contact.
 * An attacker can host on such a domain, so they stay on the list for a person to judge.
 */
const SENSITIVE_DOMAINS = ['mil.id', 'go.id', 'ac.id', 'microsoft.com', 'windows.com', 'windowsupdate.com', 'office.com', 'office365.com', 'live.com', 'microsoftonline.com', 'google.com', 'googleapis.com', 'gstatic.com', 'dns.google', 'cloudflare.com', 'cloudflare-dns.com', 'whatsapp.com', 'whatsapp.net', 'apple.com', 'icloud.com', 'digicert.com', 'letsencrypt.org']
const SENSITIVE_IPS = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220'])

const underDomain = (value: string, parent: string) => value === parent || value.endsWith(`.${parent}`)

/** Why an indicator should be reviewed rather than loaded as is, or undefined when it can be. */
export function reviewReason(ioc: Ioc, ownDomains: readonly string[] = []): string | undefined {
  if (ioc.kind === 'domain') {
    if (ownDomains.some((d) => underDomain(ioc.value, d.toLowerCase()))) return 'domain milik satuan'
    if (SENSITIVE_DOMAINS.some((d) => underDomain(ioc.value, d))) return 'layanan pemerintah atau layanan umum; memblokirnya dapat mengganggu satuan sendiri'
  }
  if (ioc.kind === 'ip' && SENSITIVE_IPS.has(ioc.value)) return 'DNS publik; memblokirnya dapat memutus akses internet'
  return ioc.review
}

export type BlocklistFile = { name: string; text: string }

export type BlocklistMeta = {
  /** Unit name, from the unit profile. */
  unit: string
  /** What this list covers, e.g. "Kasus KSS-0001" or "Semua insiden". */
  scope: string
  /** Epoch ms; stamped by the caller (the engine never calls Date.now). */
  generatedAt: number
  actor: string
  /** From the unit profile: never proposed for blocking. */
  ownDomains?: readonly string[]
}

const countsOf = (iocs: Ioc[]) => ({
  ip: iocs.filter((i) => i.kind === 'ip').length,
  domain: iocs.filter((i) => i.kind === 'domain').length,
  sha256: iocs.filter((i) => i.kind === 'sha256').length,
})

function headerLines(iocs: Ioc[], meta: BlocklistMeta): string[] {
  const c = countsOf(iocs)
  return [
    '# SIGAP — Daftar Blokir Indikator (IOC)',
    `# Unit        : ${meta.unit}`,
    `# Lingkup     : ${meta.scope}`,
    `# Dibuat      : ${fmtDateTime(meta.generatedAt)} oleh ${meta.actor}`,
    `# Total indikator: ${iocs.length} (IP eksternal: ${c.ip}, Domain: ${c.domain}, Hash berkas: ${c.sha256})`,
    `# Perlu ditinjau, tidak untuk langsung diblokir: ${iocs.filter((i) => reviewReason(i, meta.ownDomains)).length}`,
    '# Sumber: korelasi lokal SIGAP atas log yang diimpor. Verifikasi sebelum diterapkan.',
    '# Hanya indikator eksternal; aset internal satuan tidak disertakan.',
  ]
}

function blocklistTxt(iocs: Ioc[], meta: BlocklistMeta): string {
  const lines = [...headerLines(iocs, meta), '']
  if (iocs.length === 0) lines.push('# Tidak ada indikator eksternal pada lingkup ini.')
  const review = iocs.filter((i) => reviewReason(i, meta.ownDomains))
  const ready = iocs.filter((i) => !reviewReason(i, meta.ownDomains))
  for (const kind of ['ip', 'domain', 'sha256'] as IocKind[]) {
    const group = ready.filter((i) => i.kind === kind)
    if (group.length === 0) continue
    lines.push(`# ${KIND_LABEL[kind]} (${group.length})`)
    for (const i of group) lines.push(i.value)
    lines.push('')
  }
  if (review.length) {
    lines.push(`# PERLU DITINJAU (${review.length}): sengaja dijadikan komentar, jangan diblokir tanpa pemeriksaan`)
    for (const i of review) lines.push(`# ${i.value}  (${reviewReason(i, meta.ownDomains)})`)
    lines.push('')
  }
  return lines.join('\n').trimEnd() + '\n'
}

function csvCell(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function blocklistCsv(iocs: Ioc[], meta: BlocklistMeta): string {
  const rows = [
    `# ${meta.scope} — ${fmtDateTime(meta.generatedAt)}`,
    'tipe,nilai,jumlah_temuan,pertama_terlihat,aturan,saran',
    ...iocs.map((i) => {
      const reason = reviewReason(i, meta.ownDomains)
      return [i.kind, i.value, String(i.detections), fmtDateTime(i.firstSeen), i.rules.join('; '), reason ? `tinjau: ${reason}` : 'blokir'].map(csvCell).join(',')
    }),
  ]
  return rows.join('\n') + '\n'
}

function dnsSinkhole(iocs: Ioc[], meta: BlocklistMeta): string {
  const domains = iocs.filter((i) => i.kind === 'domain')
  const ready = domains.filter((d) => !reviewReason(d, meta.ownDomains))
  const lines = [
    '# SIGAP — DNS sinkhole / berkas hosts',
    `# Lingkup: ${meta.scope} · ${fmtDateTime(meta.generatedAt)}`,
    '# Muat ke Pi-hole, resolver, atau tambahkan ke berkas hosts untuk mengalihkan domain berbahaya.',
    '',
  ]
  if (domains.length === 0) lines.push('# Tidak ada domain pada lingkup ini.')
  else for (const d of ready) lines.push(`0.0.0.0 ${d.value}`)
  const review = domains.filter((d) => reviewReason(d, meta.ownDomains))
  if (review.length) lines.push('', '# Tidak dimasukkan, perlu ditinjau:', ...review.map((d) => `# ${d.value}  (${reviewReason(d, meta.ownDomains)})`))
  return lines.join('\n') + '\n'
}

function readme(iocs: Ioc[], meta: BlocklistMeta): string {
  const c = countsOf(iocs)
  return [
    'SIGAP — Paket Daftar Blokir (IOC)',
    '=================================',
    `Unit     : ${meta.unit}`,
    `Lingkup  : ${meta.scope}`,
    `Dibuat   : ${fmtDateTime(meta.generatedAt)}`,
    `Oleh     : ${meta.actor}`,
    `Total    : ${iocs.length} indikator (IP eksternal: ${c.ip}, Domain: ${c.domain}, Hash berkas: ${c.sha256})`,
    '',
    'Isi paket:',
    '- blocklist.txt        Daftar indikator berkelompok (untuk dibaca / disalin).',
    '- blocklist.csv        Tabel indikator + konteks (jumlah temuan, waktu, aturan).',
    '- dns-sinkhole.hosts   Entri "0.0.0.0 <domain>" untuk DNS sinkhole / Pi-hole / berkas hosts.',
    '- MANIFEST-SHA256.txt  SHA-256 tiap berkas untuk verifikasi integritas.',
    '',
    'Cara memakai (ringkas):',
    '- Firewall satuan   : tambahkan alamat IP eksternal ke daftar blokir keluar.',
    '- DNS / Pi-hole     : muat dns-sinkhole.hosts, atau blokir domain pada resolver.',
    '- Endpoint / AV     : jadikan hash berkas sebagai indikator blokir.',
    '',
    'Catatan:',
    '- Indikator berasal dari korelasi lokal SIGAP atas log yang diimpor; tidak ada',
    '  pencarian ke layanan luar. Verifikasi sebelum diterapkan pada sistem produksi.',
    '- Bagian "PERLU DITINJAU" tidak ikut dimuat: indikator dari temuan yang belum dikonfirmasi,',
    '  domain pemerintah atau milik satuan, dan layanan umum seperti DNS publik dan pembaruan Windows.',
    '- Hanya indikator EKSTERNAL. Aset internal satuan, akun, nama berkas, dan hash',
    '  program bawaan Windows sengaja TIDAK disertakan agar tidak memblokir sistem sendiri.',
  ].join('\n') + '\n'
}

/**
 * The content files of an IOC blocklist package (deterministic, pure). The caller adds
 * `MANIFEST-SHA256.txt` after hashing each file, then zips them.
 */
export function blocklistFiles(iocs: Ioc[], meta: BlocklistMeta): BlocklistFile[] {
  return [
    { name: 'blocklist.txt', text: blocklistTxt(iocs, meta) },
    { name: 'blocklist.csv', text: blocklistCsv(iocs, meta) },
    { name: 'dns-sinkhole.hosts', text: dnsSinkhole(iocs, meta) },
    { name: 'README.txt', text: readme(iocs, meta) },
  ]
}
