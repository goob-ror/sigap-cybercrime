export function PageTitle({
  eyebrow,
  title,
  text,
}: {
  eyebrow: string;
  title: string;
  text: string;
}) {
  return (
    <div className="min-w-0">
      <div className="mb-1.5 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.2em] text-[#38BDF8]">
        <span className="h-px w-4 bg-[#38BDF8]/40" />
        {eyebrow}
      </div>
      <h1 className="break-words text-2xl font-bold tracking-tight text-[#F0F4F8] md:text-[1.75rem]">
        {title}
      </h1>
      <p className="mt-1.5 max-w-2xl break-words text-sm leading-relaxed text-[#6E7A8A]">
        {text}
      </p>
    </div>
  );
}
