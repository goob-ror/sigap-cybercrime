import type { Detection } from '@/core/model'

export function LogExplorer(_props: { detections: Detection[]; focusEventId: string | null; openDetection: (id: string) => void }) {
  return <p className="text-sm text-[#7E8998]">Log Explorer belum tersedia.</p>
}