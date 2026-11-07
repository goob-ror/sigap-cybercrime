import { Label } from "@/components/ui/Label";

export function Card({
  title,
  icon,
  children,
  className = "",
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`overflow-hidden rounded-xl border border-[#1E2532] bg-[#0F1520] shadow-sm ${className}`}
    >
      <div className="flex items-center gap-2.5 border-b border-[#1E2532] bg-[#131B27]/60 px-5 py-3.5 text-sm font-semibold text-[#D6DCE6]">
        {icon}
        {title}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Info({ title, text }: { title: string; text: string }) {
  return (
    <div className="min-w-0">
      <Label>{title}</Label>
      <p className="break-words text-xs leading-5 text-[#B4BCC7]">{text}</p>
    </div>
  );
}
