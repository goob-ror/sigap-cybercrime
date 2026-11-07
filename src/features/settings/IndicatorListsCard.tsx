import { useRef, useState } from 'react'
import { useLiveQuery } from 'dexie-react-hooks'
import { ListChecks, Trash2, TriangleAlert, Upload } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { sha256Hex } from '@/core/evidence/hash'
import { parseIndicatorList, type IndicatorList } from '@/core/indicators'
import { addCustody } from '@/db/custodyLog'
import { db } from '@/db/db'
import { fmtDate, fmtNumber } from '@/lib/format'

const MAX_FILE_BYTES = 100 * 1024 * 1024
const STALE_MS = 30 * 24 * 60 * 60_000

type Props = { actor: string; busy: boolean; notify: (message: string) => void; /** Re-checks the stored events against the changed lists. */ apply: () => void }

/** Threat lists the unit brings itself, checked here with no network. This is how an air-gapped unit gets reputation data. */
export function IndicatorListsCard({ actor, busy, notify, apply }: Props) {
  const lists = useLiveQuery(() => db.indicatorLists.toArray(), []) ?? []
  const [error, setError] = useState('')
  const input = useRef<HTMLInputElement>(null)

  const importFile = async (file: File) => {
    setError('')
    if (file.size > MAX_FILE_BYTES) { setError(`${file.name} terlalu besar (batas 100 MB).`); return }
    const text = await file.text()
    const sha256 = await sha256Hex(text)
    if (await db.indicatorLists.get(sha256)) { notify(`${file.name} sudah pernah diimpor`); return }
    const parsed = parseIndicatorList(text)
    const total = parsed.domains.length + parsed.ips.length + parsed.hashes.length
    if (!total) { setError(`Tidak ada domain, IP, atau hash SHA-256 yang terbaca dari ${file.name}.`); return }
    const list: IndicatorList = { id: sha256, name: file.name, importedAt: Date.now(), importedBy: actor, sha256, ...parsed }
    await db.indicatorLists.put(list)
    await addCustody({ ts: Date.now(), actor, action: 'note', detail: `Daftar indikator ${file.name} diimpor: ${total} indikator (SHA-256 ${sha256})` })
    notify(`${file.name}: ${fmtNumber(total)} indikator diimpor`)
    apply()
  }

  const remove = async (list: IndicatorList) => {
    await db.indicatorLists.delete(list.id)
    await addCustody({ ts: Date.now(), actor, action: 'note', detail: `Daftar indikator ${list.name} dihapus (SHA-256 ${list.sha256})` })
    apply()
  }

  return <Card title="Daftar Indikator Lokal" icon={<ListChecks size={16} className="text-[#38BDF8]" />}>
    <p className="text-xs leading-5 text-[#8D97A6]">Bandingkan log dengan daftar alamat berbahaya tanpa internet. Unduh daftar dari komputer yang terhubung, sesuai lisensi sumbernya, lalu bawa ke sini. SIGAP tidak menyertakan daftar apa pun. Terbaca: berkas hosts, RPZ, CSV dengan kolom URL, dan daftar polos berisi domain, IP, atau hash SHA-256.</p>

    {lists.length > 0 && <ul className="mt-3 space-y-2">{lists.map((list) => <li key={list.id} className="flex items-center gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-xs">
      <div className="min-w-0 flex-1">
        <div className="truncate font-mono text-[#D1D6DD]">{list.name}</div>
        <div className="mt-0.5 text-[10px] text-[#657080]">{fmtNumber(list.domains.length)} domain · {fmtNumber(list.ips.length)} IP · {fmtNumber(list.hashes.length)} hash{list.skipped ? ` · ${fmtNumber(list.skipped)} baris tak terbaca` : ''} · {fmtDate(list.importedAt)} oleh {list.importedBy}</div>
        {Date.now() - list.importedAt > STALE_MS && <div className="mt-1 flex items-center gap-1 text-[10px] text-[#FCD34D]"><TriangleAlert size={11} />Lebih dari 30 hari. Daftar seperti ini cepat usang; perbarui.</div>}
      </div>
      <button aria-label={`Hapus daftar ${list.name}`} disabled={busy} onClick={() => void remove(list)} className="grid size-8 shrink-0 place-items-center rounded-lg border border-[#272E3A] text-[#8D97A6] hover:text-[#FCA5A5] disabled:opacity-50"><Trash2 size={13} /></button>
    </li>)}</ul>}

    {error && <p role="alert" className="mt-3 rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 p-2.5 text-xs text-[#FCA5A5]">{error}</p>}
    <input ref={input} data-testid="indicator-file" type="file" accept=".txt,.csv,.list,.rpz,.zone,text/plain,text/csv" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) void importFile(f).catch((err: Error) => setError(err.message)); e.target.value = '' }} />
    <button disabled={busy} onClick={() => input.current?.click()} className="mt-3 flex items-center justify-center gap-1.5 rounded-lg border border-[#272E3A] px-3 py-2 text-xs text-[#AEB6C1] hover:text-white disabled:opacity-50"><Upload size={13} />Impor daftar</button>
    <p className="mt-2 text-[10px] leading-4 text-[#657080]">Kecocokan menjadi temuan "Perlu konfirmasi", karena daftar bisa memuat situs sah yang pernah disusupi. Tidak ada kecocokan bukan berarti aman.</p>
  </Card>
}
