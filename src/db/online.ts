import { useEffect, useState } from 'react'
import type { HashSearch } from '@/core/triage/safebrowsing'
import { useSettings } from '@/db/settings'

/**
 * The browser's side of the online feature. It only ever calls this page's own origin, where the server
 * holds the key. Nothing here runs by itself: every call follows an operator's click, and only after they
 * have allowed it in Pengaturan. The offline kit has no `/api`, so all of this reads as absent.
 */

export type OnlineStatus = { checked: boolean; safeBrowsing: boolean }

const NOT_AVAILABLE: OnlineStatus = { checked: true, safeBrowsing: false }
const TIMEOUT_MS = 25_000

let cached: Promise<OnlineStatus> | null = null

async function fetchStatus(): Promise<OnlineStatus> {
  try {
    const response = await fetch('./api/status', { headers: { accept: 'application/json' }, cache: 'no-store' })
    // A static server may answer with the app's page, which is not a status.
    if (!response.ok || !(response.headers.get('content-type') ?? '').includes('json')) return NOT_AVAILABLE
    const value = (await response.json()) as Partial<OnlineStatus>
    return { checked: true, safeBrowsing: value.safeBrowsing === true }
  } catch {
    return NOT_AVAILABLE
  }
}

export function useOnlineStatus(): OnlineStatus {
  const [status, setStatus] = useState<OnlineStatus>({ checked: false, safeBrowsing: false })
  useEffect(() => {
    let live = true
    cached ??= fetchStatus()
    void cached.then((value) => { if (live) setStatus(value) })
    return () => { live = false }
  }, [])
  return status
}

/** What this server offers, and whether the operator has allowed it in this browser. */
export function useOnline() {
  const status = useOnlineStatus()
  const { onlineConsent } = useSettings()
  return { status, consent: onlineConsent, available: status.safeBrowsing, active: onlineConsent && status.safeBrowsing }
}

/** The server's own message, which is already written for the operator. */
export class OnlineError extends Error {}

export const searchHashes: HashSearch = async (hashPrefixes) => {
  let response: Response
  try {
    response = await fetch('./api/safe-browsing', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hashPrefixes }), signal: AbortSignal.timeout(TIMEOUT_MS) })
  } catch {
    throw new OnlineError('Server tidak dapat dihubungi. Seluruh analisis SIGAP tetap berjalan tanpa layanan ini.')
  }
  const value = (await response.json().catch(() => null)) as (Awaited<ReturnType<HashSearch>> & { error?: string }) | null
  if (!response.ok || !value) throw new OnlineError(value?.error ?? 'Layanan sedang tidak tersedia.')
  return value
}
