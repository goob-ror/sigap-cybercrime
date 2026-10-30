import { Info } from 'lucide-react'

/** Shown on pages that still use the static design mockup data (wired to real data in Phase 2). */
export function StaticNotice() {
  return <div className="mx-auto mb-4 flex max-w-[1600px] items-center gap-2 rounded-lg border border-[#F59E0B]/25 bg-[#F59E0B]/5 px-3 py-2 text-[11px] text-[#D4A64B]"><Info size={14} className="shrink-0" />Halaman ini masih menampilkan data contoh statis dan akan terhubung ke data impor pada tahap korelasi.</div>
}
