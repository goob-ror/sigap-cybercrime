import { Cpu, Mail, Monitor, Router } from 'lucide-react'
import { type Source } from '@/data/demoCase'

export function SourceMark({ source, size = 15 }: { source: Source; size?: number }) {
  const Icon = source === 'Email Gateway' ? Mail : source === 'Endpoint' ? Monitor : source === 'Jaringan' ? Router : Cpu
  return <Icon size={size} />
}
