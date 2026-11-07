import { useEffect, useState } from 'react'
import { ClipboardCopy, ExternalLink, ListChecks, ShieldAlert, ShieldQuestion } from 'lucide-react'
import { Label } from '@/components/ui/Label'
import { indexLists, matchHost } from '@/core/indicators'
import { ipv4ToInt, isPrivateIp } from '@/core/net'
import { checkUrl, THREAT_LABEL, type SafeBrowsingVerdict } from '@/core/triage/safebrowsing'
import { addCustody } from '@/db/custodyLog'
import { db } from '@/db/db'
import { searchHashes, useOnline } from '@/db/online'

type Props = {
  /** The address as entered, which Safe Browsing checks in full. */
  url: string
  host: string
  ownDomains: readonly string[]
  actor: string
  notify: (message: string) => void
  openSettings: () => void
}

type LocalResult = { lists: number; match: { indicator: string; list: string } | null }

const ADVISORY = 'https://developers.google.com/safe-browsing/v4/advisory'
const SOCIAL_ENGINEERING = 'https://developers.google.com/search/docs/monitor-debug/security/social-engineering'
const MALWARE = 'https://developers.google.com/search/docs/monitor-debug/security/malware'
const INTERNAL_SUFFIX = /(^|\.)(local|lan|internal|intranet|corp|home|localhost|localdomain)$/
const LINK = 'flex items-center justify-center gap-1.5 rounded-lg border border-[#272E3A] bg-[#191F2A] px-2 py-2 text-[11px] font-semibold hover:border-[#38BDF8]/40'

/** A name only this unit can resolve means nothing to an outside service, and telling one about it gives away the name. */
export function isInternalHost(host: string, ownDomains: readonly string[]): boolean {
  const name = host.toLowerCase()
  if (ipv4ToInt(name) !== null) return isPrivateIp(name)
  if (!name.includes('.') || INTERNAL_SUFFIX.test(name)) return true
  return ownDomains.some((own) => name === own.toLowerCase() || name.endsWith(`.${own.toLowerCase()}`))
}

function External({ href, children }: { href: string; children: React.ReactNode }) {
  return <a href={href} target="_blank" rel="noopener noreferrer" className="text-[#7DD3FC] underline underline-offset-2 hover:text-white">{children}</a>
}

/** Google requires this wording, attribution and these links next to anything shown from Safe Browsing. */
function SafeBrowsingNotice({ verdict }: { verdict: SafeBrowsingVerdict }) {
  const flagged = verdict.threats.length > 0
  const malwareLike = verdict.threats.some((t) => t !== 'SOCIAL_ENGINEERING')
  const phishing = verdict.threats.includes('SOCIAL_ENGINEERING')
  return <div data-testid="safe-browsing-result" className={`rounded-lg border p-3 text-xs leading-5 ${flagged ? 'border-[#EF4444]/30 bg-[#EF4444]/10' : 'border-[#272E3A] bg-[#0D1016]'}`}>
    {flagged
      ? <><div className="flex items-start gap-2 font-semibold text-[#FCA5A5]"><ShieldAlert size={14} className="mt-0.5 shrink-0" /><span>Peringatan: alamat ini {verdict.threats.map((t) => THREAT_LABEL[t] ?? 'kemungkinan berbahaya').join(' dan ')}.</span></div>
        <p className="mt-1.5 text-[#D4B4B4]">Jangan membuka alamat ini. {phishing && <>Baca <External href={SOCIAL_ENGINEERING}>arti pengelabuan</External>. </>}{malwareLike && <>Baca <External href={MALWARE}>arti malware dan perangkat lunak yang tidak diinginkan</External>.</>}</p></>
      : <div className="flex items-start gap-2 text-[#AEB6C1]"><ShieldQuestion size={14} className="mt-0.5 shrink-0" /><span>Alamat ini tidak ada di daftar Google Safe Browsing saat ini. <b>Ini bukan berarti aman</b>: situs baru dan serangan yang tertarget sering belum tercatat.</span></div>}
    <p className="mt-2 text-[10px] leading-4 text-[#8D97A6]"><External href={ADVISORY}>Advisory provided by Google</External>. Perlindungan ini tidak sempurna: Google cannot guarantee that its information is comprehensive and error-free.</p>
  </div>
}

/** Reputation of a public address: the unit's own lists offline, Safe Browsing on request, and links for looking further. */
export function ReputationPanel({ url, host, ownDomains, actor, notify, openSettings }: Props) {
  const { status, consent } = useOnline()
  const [local, setLocal] = useState<LocalResult | null>(null)
  const [verdict, setVerdict] = useState<SafeBrowsingVerdict | null>(null)
  const [expired, setExpired] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const internal = isInternalHost(host, ownDomains)

  useEffect(() => {
    let live = true
    void db.indicatorLists.toArray().then((lists) => { if (live) setLocal({ lists: lists.length, match: matchHost(host, indexLists(lists)) }) })
    return () => { live = false }
  }, [host])

  // Google allows showing a result only for as long as its answer says it stays valid.
  useEffect(() => {
    if (!verdict) return
    const timer = window.setTimeout(() => { setVerdict(null); setExpired(true) }, Math.max(verdict.cacheSeconds, 60) * 1000)
    return () => window.clearTimeout(timer)
  }, [verdict])

  const check = async () => {
    setBusy(true); setError(''); setVerdict(null); setExpired(false)
    try {
      await addCustody({ ts: Date.now(), actor, action: 'note', detail: `Alamat ${host} diperiksa ke Google Safe Browsing (yang terkirim hanya awalan hash)` })
      const result = await checkUrl(url, searchHashes)
      if (result) setVerdict(result)
      else setError('Alamat ini tidak dapat dibaca.')
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const copyHost = () => { navigator.clipboard.writeText(host).then(() => notify(`${host} disalin`), () => notify('Gagal menyalin')) }
  const isIp = ipv4ToInt(host) !== null

  return <div className="mt-4 border-t border-[#272E3A] pt-4">
    <Label>Reputasi alamat</Label>
    {local && (local.lists === 0
      ? <p className="text-[11px] leading-4 text-[#657080]"><ListChecks size={12} className="mr-1 inline" />Belum ada daftar indikator lokal. Impor di Pengaturan agar dapat diperiksa tanpa internet.</p>
      : local.match
        ? <p data-testid="local-list-hit" className="rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 p-2.5 text-xs leading-5 text-[#FCA5A5]"><ListChecks size={13} className="mr-1 inline" /><b className="font-mono">{local.match.indicator}</b> tercantum di daftar "{local.match.list}". Daftar bisa memuat situs sah yang pernah disusupi, jadi tetap perlu diperiksa.</p>
        : <p data-testid="local-list-miss" className="text-[11px] leading-4 text-[#8D97A6]"><ListChecks size={12} className="mr-1 inline" />Tidak tercantum di {local.lists} daftar lokal. Ini bukan berarti aman.</p>)}

    {internal ? <p className="mt-2 text-[11px] leading-4 text-[#8D97A6]">Alamat ini tampak internal atau milik satuan, jadi tidak diperiksa ke layanan luar agar namanya tidak keluar.</p> : <>
      {status.safeBrowsing && <div className="mt-3">
        {!consent ? <button onClick={openSettings} className={`${LINK} w-full`}>Izinkan fitur online untuk memakai Google Safe Browsing</button>
          : <button onClick={() => void check()} disabled={busy} className="w-full rounded-lg bg-[#38BDF8] py-2 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC] disabled:opacity-60">{busy ? 'Memeriksa…' : 'Periksa di Google Safe Browsing'}</button>}
        {consent && !verdict && !error && <p className="mt-1.5 text-[10px] leading-4 text-[#657080]">Alamatnya tidak terkirim: hanya awalan hash, dan hasilnya dicocokkan di browser ini.{expired && ' Hasil sebelumnya sudah kedaluwarsa; periksa ulang.'}</p>}
        {error && <p role="alert" className="mt-2 rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 p-2.5 text-xs text-[#FCA5A5]">{error}</p>}
        {verdict && <div className="mt-2"><SafeBrowsingNotice verdict={verdict} /></div>}
      </div>}

      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
        <a className={LINK} target="_blank" rel="noopener noreferrer" href={`https://www.virustotal.com/gui/${isIp ? 'ip-address' : 'domain'}/${encodeURIComponent(host)}`}><ExternalLink size={12} />VirusTotal</a>
        <a className={LINK} target="_blank" rel="noopener noreferrer" href={`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(host)}`}><ExternalLink size={12} />Google</a>
        <button className={`${LINK} col-span-2 sm:col-span-1`} onClick={copyHost}><ClipboardCopy size={12} />Salin alamat</button>
      </div>
      <p className="mt-1.5 text-[10px] leading-4 text-[#657080]">Tautan membuka situs pihak ketiga di tab baru, dan situs itu melihat nama domainnya. Bila komputer ini tidak boleh berinternet, salin alamatnya dan periksa dari komputer lain.</p>
    </>}
  </div>
}
