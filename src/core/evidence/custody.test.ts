import { describe, expect, it } from 'vitest'
import { sha256Hex } from '@/core/evidence/hash'
import { GENESIS_HASH, appendCustody, verifyCustodyChain } from '@/core/evidence/custody'
import type { CustodyEntry } from '@/core/model'

describe('sha256Hex', () => {
  it('matches the known digest of "abc"', async () => {
    expect(await sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('hashes bytes and text identically', async () => {
    expect(await sha256Hex(new TextEncoder().encode('SIGAP'))).toBe(await sha256Hex('SIGAP'))
  })
})

describe('custody chain', () => {
  async function sampleChain(): Promise<CustodyEntry[]> {
    let chain: CustodyEntry[] = []
    chain = await appendCustody(chain, { ts: 1, actor: 'operator', action: 'acquired', artifactId: 'a1', artifactSha256: 'f'.repeat(64), detail: 'APK dari prajurit' })
    chain = await appendCustody(chain, { ts: 2, actor: 'operator', action: 'analyzed', artifactId: 'a1', detail: 'Triase APK' })
    chain = await appendCustody(chain, { ts: 3, actor: 'operator', action: 'exported', detail: 'Paket bukti' })
    return chain
  }

  it('links entries in order starting from the genesis hash', async () => {
    const chain = await sampleChain()
    expect(chain.map((e) => e.seq)).toEqual([0, 1, 2])
    expect(chain[0].prevHash).toBe(GENESIS_HASH)
    expect(chain[1].prevHash).toBe(chain[0].hash)
    expect(chain[2].prevHash).toBe(chain[1].hash)
  })

  it('verifies an untouched chain', async () => {
    expect(await verifyCustodyChain(await sampleChain())).toEqual({ ok: true })
  })

  it('detects an edited entry', async () => {
    const chain = await sampleChain()
    chain[1] = { ...chain[1], detail: 'diubah' }
    expect(await verifyCustodyChain(chain)).toMatchObject({ ok: false, seq: 1 })
  })

  it('detects a removed entry', async () => {
    const chain = await sampleChain()
    chain.splice(1, 1)
    expect(await verifyCustodyChain(chain)).toMatchObject({ ok: false })
  })

  it('detects an entry re-hashed after editing (broken link to the next entry)', async () => {
    const chain = await sampleChain()
    const forged = (await appendCustody(chain.slice(0, 1), { ...chain[1], detail: 'diubah' }))[1]
    chain[1] = forged
    expect(await verifyCustodyChain(chain)).toMatchObject({ ok: false, seq: 2 })
  })
})
