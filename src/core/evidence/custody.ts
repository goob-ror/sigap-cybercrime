import type { CustodyEntry } from '@/core/model'
import { sha256Hex } from '@/core/evidence/hash'

/** `prevHash` of the first entry in every chain. */
export const GENESIS_HASH = '0'.repeat(64)

type NewEntry = Omit<CustodyEntry, 'seq' | 'prevHash' | 'hash'>

/** Canonical text that an entry's hash commits to. Field order is fixed on purpose. */
function canonical(entry: Omit<CustodyEntry, 'hash'>): string {
  return JSON.stringify([
    entry.seq,
    entry.ts,
    entry.actor,
    entry.action,
    entry.artifactId ?? null,
    entry.artifactSha256 ?? null,
    entry.detail,
    entry.prevHash,
  ])
}

/** Returns a new chain with `entry` appended and linked to the previous entry. */
export async function appendCustody(chain: readonly CustodyEntry[], entry: NewEntry): Promise<CustodyEntry[]> {
  const prev = chain.at(-1)
  const unsigned = { ...entry, seq: (prev?.seq ?? -1) + 1, prevHash: prev?.hash ?? GENESIS_HASH }
  return [...chain, { ...unsigned, hash: await sha256Hex(canonical(unsigned)) }]
}

export type ChainCheck = { ok: true } | { ok: false; seq: number; reason: string }

/** Recomputes every hash and link; reports the first entry that was altered, removed or reordered. */
export async function verifyCustodyChain(chain: readonly CustodyEntry[]): Promise<ChainCheck> {
  let prevHash = GENESIS_HASH
  for (const [i, entry] of chain.entries()) {
    if (entry.seq !== i) return { ok: false, seq: entry.seq, reason: `Urutan terputus: diharapkan #${i}` }
    if (entry.prevHash !== prevHash) return { ok: false, seq: entry.seq, reason: 'Tautan ke entri sebelumnya tidak cocok' }
    const { hash, ...unsigned } = entry
    if ((await sha256Hex(canonical(unsigned))) !== hash) return { ok: false, seq: entry.seq, reason: 'Isi entri telah diubah' }
    prevHash = hash
  }
  return { ok: true }
}
