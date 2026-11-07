import { useLiveQuery } from 'dexie-react-hooks'
import type { DrillResult } from '@/core/drill'
import { createSigningKey } from '@/core/evidence/signing'
import type { UnitProfile } from '@/core/model'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import { addCustody } from '@/db/custodyLog'
import { db } from '@/db/db'

export type Settings = {
  loaded: boolean
  /** Who is using this browser; recorded on every action. Null until they say. */
  operator: string | null
  profile: UnitProfile
  /** False while the fictional demo unit is still in use. */
  custom: boolean
  /** Zone given to logs whose timestamps carry none. */
  importTz: string
  /** Whether the operator has allowed online features. */
  onlineConsent: boolean
  drillResults: DrillResult[]
}

export const WIB_OFFSET = '+07:00'

export function useSettings(): Settings {
  const rows = useLiveQuery(() => db.settings.toArray())
  const stored = rows?.find((r) => r.key === 'profile')?.value as UnitProfile | undefined
  return {
    loaded: rows !== undefined,
    operator: (rows?.find((r) => r.key === 'operator')?.value as string | undefined) ?? null,
    profile: stored ?? DEFAULT_UNIT_PROFILE,
    custom: stored !== undefined,
    importTz: (rows?.find((r) => r.key === 'importTz')?.value as string | undefined) ?? WIB_OFFSET,
    onlineConsent: rows?.find((r) => r.key === 'onlineConsent')?.value === true,
    drillResults: (rows?.find((r) => r.key === 'drillResults')?.value as DrillResult[] | undefined) ?? [],
  }
}

export const saveOperator = (name: string) => db.settings.put({ key: 'operator', value: name })
export const saveImportTz = (offset: string) => db.settings.put({ key: 'importTz', value: offset })

/** Recorded, because what leaves this browser is part of how the evidence was handled. */
export async function saveOnlineConsent(allowed: boolean, actor: string) {
  await db.settings.put({ key: 'onlineConsent', value: allowed })
  await addCustody({ ts: Date.now(), actor, action: 'note', detail: allowed ? 'Fitur online diizinkan di browser ini' : 'Fitur online dimatikan di browser ini' })
}

const MAX_DRILL_RESULTS = 30

export async function saveDrillResult(result: DrillResult) {
  const row = await db.settings.get('drillResults')
  const previous = row?.key === 'drillResults' ? row.value : []
  await db.settings.put({ key: 'drillResults', value: [result, ...previous].slice(0, MAX_DRILL_RESULTS) })
}

/** This browser's signing key, made the first time it is needed. */
export async function signingKey(): Promise<CryptoKeyPair> {
  const row = await db.settings.get('signingKey')
  if (row?.key === 'signingKey') return row.value
  const keys = await createSigningKey()
  await db.settings.put({ key: 'signingKey', value: keys })
  return keys
}
