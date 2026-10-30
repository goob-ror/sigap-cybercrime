export function PageTitle({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) {
  return <div><div className="mb-1 text-[10px] font-bold uppercase tracking-[0.18em] text-[#38BDF8]">{eyebrow}</div><h1 className="text-xl font-semibold tracking-tight md:text-2xl">{title}</h1><p className="mt-1 max-w-2xl text-sm text-[#7E8998]">{text}</p></div>
}
