import { Cloud } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { useOnline } from '@/db/online'
import { saveOnlineConsent } from '@/db/settings'

const ON = 'border-[#22C55E]/25 bg-[#22C55E]/10 text-[#86EFAC]'
const OFF = 'border-[#272E3A] bg-[#131720] text-[#8D97A6]'

/** Whether anything may leave this browser, stated plainly. Off until an operator says otherwise. */
export function OnlineCard({ actor, notify }: { actor: string; notify: (message: string) => void }) {
  const { status, consent, available } = useOnline()

  const change = (allowed: boolean) => {
    void saveOnlineConsent(allowed, actor).then(() => notify(allowed ? 'Fitur online diizinkan di browser ini' : 'Fitur online dimatikan di browser ini'))
  }

  return <Card title="Layanan Online" icon={<Cloud size={16} className="text-[#38BDF8]" />}>
    <Badge className={status.safeBrowsing ? ON : OFF}>GOOGLE SAFE BROWSING: {status.safeBrowsing ? 'TERSEDIA' : 'TIDAK ADA'}</Badge>

    {!available ? <p className="mt-3 text-xs leading-5 text-[#8D97A6]">{status.checked ? 'Instalasi ini tidak memiliki layanan online, seperti kit offline. Seluruh analisis, deteksi, kasus, dan laporan tetap berjalan tanpa internet, dan tidak ada data yang keluar dari browser ini.' : 'Memeriksa…'}</p> : <>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#272E3A] bg-[#0D1016] p-3">
        <div className="min-w-0"><div className="text-sm font-semibold">{consent ? 'Diizinkan di browser ini' : 'Tidak diizinkan'}</div><p className="mt-0.5 text-[11px] leading-4 text-[#8D97A6]">{consent ? 'Tetap tidak ada yang terkirim sampai Anda menekan tombol pemeriksaan.' : 'Tidak ada yang keluar dari browser ini.'}</p></div>
        <button onClick={() => change(!consent)} className={consent ? 'rounded-lg border border-[#272E3A] px-3 py-2 text-xs text-[#AEB6C1] hover:text-white' : 'rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018] hover:bg-[#7DD3FC]'}>{consent ? 'Matikan' : 'Izinkan'}</button>
      </div>
      <p className="mt-3 text-xs leading-5 text-[#AEB6C1]">Saat memeriksa alamat di halaman Triase, yang terkirim ke Google hanya <b>4 byte awal hash</b> alamat itu. Alamatnya sendiri, log, dan kasus tidak pernah terkirim. Hasilnya dicocokkan di browser ini, dan setiap pemeriksaan tercatat pada rantai bukti.</p>
      <p className="mt-2 text-[10px] leading-4 text-[#657080]">Kunci tersimpan di server, tidak pernah sampai ke browser. Google Safe Browsing hanya untuk pemakaian non-komersial.</p>
    </>}
  </Card>
}
