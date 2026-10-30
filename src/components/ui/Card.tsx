import { Label } from '@/components/ui/Label'

export function Card({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) { return <section className="rounded-xl border border-[#272E3A] bg-[#131720]"><div className="flex items-center gap-2 border-b border-[#272E3A] px-4 py-3 text-sm font-semibold">{icon}{title}</div><div className="p-4">{children}</div></section> }
export function Info({ title, text }: { title: string; text: string }) { return <div className="min-w-0"><Label>{title}</Label><p className="break-words text-xs leading-5 text-[#B4BCC7]">{text}</p></div> }
