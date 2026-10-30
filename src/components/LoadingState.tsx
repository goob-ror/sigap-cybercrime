export function LoadingState() {
  return <div className="mx-auto max-w-[1600px] animate-pulse"><div className="mb-6 h-7 w-64 rounded bg-[#191F2A]" /><div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{[1,2,3,4].map(i => <div key={i} className="h-24 rounded-xl border border-[#272E3A] bg-[#131720]" />)}</div><div className="mt-4 grid gap-4 xl:grid-cols-[1fr_380px]"><div className="h-[480px] rounded-xl border border-[#272E3A] bg-[#131720]" /><div className="h-[480px] rounded-xl border border-[#272E3A] bg-[#131720]" /></div></div>
}
