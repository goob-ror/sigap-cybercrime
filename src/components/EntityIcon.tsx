import { Cpu, FileText, Fingerprint, Globe, Globe2, Monitor, UserRound, type LucideIcon } from 'lucide-react'
import type { EntityType, IncidentEntity } from '@/core/model'
import { isPrivateIp } from '@/core/net'

const ICONS: Record<EntityType, LucideIcon> = { host: Monitor, device: Cpu, user: UserRound, ip: Globe2, domain: Globe, hash: Fingerprint, file: FileText }

export function entityTypeLabel(e: Pick<IncidentEntity, 'type' | 'value'>): string {
  switch (e.type) {
    case 'host': return 'Host'
    case 'device': return 'Perangkat OT'
    case 'user': return 'Akun'
    case 'ip': return isPrivateIp(e.value) ? 'IP internal' : 'IP eksternal'
    case 'domain': return 'Domain'
    case 'hash': return 'Hash berkas'
    case 'file': return 'Berkas'
  }
}

/** External addresses and domains are what a unit would block (indicators of compromise). */
export function isIndicator(e: Pick<IncidentEntity, 'type' | 'value' | 'common'>): boolean {
  return !e.common && ((e.type === 'ip' && !isPrivateIp(e.value)) || e.type === 'domain' || e.type === 'hash')
}

/** Colour family per entity type: OT amber, indicators red, the rest blue. */
export function entityTone(e: Pick<IncidentEntity, 'type' | 'value' | 'common'>): { fg: string; bg: string; border: string } {
  if (e.type === 'device') return { fg: '#FBBF24', bg: '#F59E0B1A', border: '#F59E0B66' }
  if (isIndicator(e)) return { fg: '#FCA5A5', bg: '#EF44441A', border: '#EF444466' }
  if (e.type === 'user') return { fg: '#C4B5FD', bg: '#A78BFA1A', border: '#A78BFA55' }
  return { fg: '#7DD3FC', bg: '#38BDF81A', border: '#38BDF855' }
}

export function EntityIcon({ entity, size = 14 }: { entity: Pick<IncidentEntity, 'type' | 'value' | 'common'>; size?: number }) {
  const Icon = ICONS[entity.type]
  const tone = entityTone(entity)
  return <span className="grid size-7 shrink-0 place-items-center rounded-lg border" style={{ color: tone.fg, background: tone.bg, borderColor: tone.border }}><Icon size={size} /></span>
}

export { ICONS as ENTITY_ICONS }
