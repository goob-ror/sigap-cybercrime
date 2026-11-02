import { Component, type ReactNode } from 'react'
import { RotateCcw, TriangleAlert } from 'lucide-react'

/** Catches render errors in a page so a bad file or edge case never blanks the whole app. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center p-6 text-center">
        <div>
          <div className="mx-auto mb-4 grid size-12 place-items-center rounded-xl border border-[#EF4444]/30 bg-[#EF4444]/10 text-[#FCA5A5]"><TriangleAlert size={22} /></div>
          <h1 className="text-lg font-semibold">Terjadi kesalahan pada halaman ini</h1>
          <p className="mt-2 text-sm text-[#7E8998]">Data lokal Anda tetap aman di browser ini. Coba buka halaman lain, atau muat ulang aplikasi.</p>
          <pre className="mx-auto mt-3 max-w-md overflow-auto rounded-lg border border-[#272E3A] bg-[#0D1016] p-3 text-left font-mono text-[10px] leading-4 text-[#8D97A6]">{this.state.error.message}</pre>
          <div className="mt-5 flex items-center justify-center gap-2">
            <button onClick={() => this.setState({ error: null })} className="rounded-lg bg-[#38BDF8] px-4 py-2 text-xs font-bold text-[#071018]">Coba lagi</button>
            <button onClick={() => location.reload()} className="flex items-center gap-1.5 rounded-lg border border-[#272E3A] px-4 py-2 text-xs font-semibold hover:border-[#38BDF8]/40"><RotateCcw size={13} />Muat ulang</button>
          </div>
        </div>
      </div>
    )
  }
}
