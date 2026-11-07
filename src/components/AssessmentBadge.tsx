import { Badge } from '@/components/ui/Badge'
import type { Assessment, Incident } from '@/core/model'
import { ASSESSMENT, assessmentOf } from '@/core/report/narrative'

const STYLE: Record<Assessment, string> = {
  'indikasi-kuat': 'border-[#EF4444]/25 bg-[#EF4444]/10 text-[#FCA5A5]',
  'perlu-konfirmasi': 'border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#FBBF24]',
  'hanya-percobaan': 'border-[#38BDF8]/25 bg-[#38BDF8]/10 text-[#7DD3FC]',
}

/** What the evidence supports: the first thing an operator should read about an incident. */
export function AssessmentBadge({ incident }: { incident: Pick<Incident, 'assessment'> }) {
  const assessment = assessmentOf(incident)
  return <Badge className={STYLE[assessment]}>{ASSESSMENT[assessment].label.toUpperCase()}</Badge>
}
