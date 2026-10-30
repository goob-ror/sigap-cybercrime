import { ChevronDown } from 'lucide-react'

export function Select({ value, setValue, options }: { value: string; setValue: (v: string) => void; options: string[] }) {
  return <div className="relative"><select value={value} onChange={e => setValue(e.target.value)} className="h-9 min-w-36 appearance-none rounded-lg border border-[#272E3A] bg-[#0D1016] pl-3 pr-8 text-xs text-[#CBD1D8] outline-none focus:border-[#38BDF8]/60">{options.map(o => <option key={o}>{o}</option>)}</select><ChevronDown size={13} className="pointer-events-none absolute right-2.5 top-3 text-[#687384]" /></div>
}
