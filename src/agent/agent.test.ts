import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { appendFile, mkdtemp, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ingestText } from '@/core/ingest'
import type { NormalizedEvent } from '@/core/model'
import { loadRulePack } from '@/data/rules'
import { generateScenario } from '@/data/scenario/generate'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'
import { Penjaga, type Alert } from '@/agent/penjaga'
import { Tailer } from '@/agent/tail'

const pack = loadRulePack()
const ATTACK_START = Date.UTC(2026, 10, 2, 6, 2, 0) // 13:02 WIB

describe('Pos Jaga on a live web server', () => {
  let events: NormalizedEvent[]

  beforeAll(() => {
    const files = generateScenario().files.filter((f) => f.name.startsWith('web-satuan-01'))
    events = files.flatMap((f, i) => ingestText(f.text, f.name, `w${i}`).events).sort((a, b) => a.ts - b.ts)
  })

  /** Feeds the events one log minute at a time, as a tailer would. */
  function stream(penjaga: Penjaga, list: NormalizedEvent[]) {
    const alerts: Alert[] = []
    let newIncidents = 0
    for (let i = 0; i < list.length; ) {
      const minute = Math.floor(list[i].ts / 60_000)
      let j = i
      while (j < list.length && Math.floor(list[j].ts / 60_000) === minute) j++
      const out = penjaga.push(list.slice(i, j))
      alerts.push(...out.alerts)
      newIncidents += out.updates.filter((u) => u.isNew).length
      i = j
    }
    return { alerts, newIncidents }
  }

  it('stays quiet on a normal day and alerts as the attack unfolds', () => {
    const penjaga = new Penjaga({ pack, profile: DEFAULT_UNIT_PROFILE })
    const before = stream(penjaga, events.filter((e) => e.ts < ATTACK_START))
    expect(before.alerts).toEqual([])
    expect(penjaga.incidents).toEqual([])

    const during = stream(penjaga, events.filter((e) => e.ts >= ATTACK_START))
    expect(during.newIncidents).toBe(1)
    expect(penjaga.incidents.map((i) => i.title)).toEqual(['Peretasan server WEB-SATUAN-01 dari 203.0.113.45'])
    // The first alert comes minutes into the attack, long before the backdoor account (13:31).
    expect(during.alerts[0].detection.ts).toBeLessThan(Date.UTC(2026, 10, 2, 6, 10))
    expect(during.alerts.map((a) => a.detection.ruleId)).toEqual(expect.arrayContaining(['sigap-web-sqli', 'sigap-web-webshell', 'sigap-native-ssh-success-after-failures', 'sigap-linux-priv-group']))
    // Repeats of the same rule from the same source are folded into one alert.
    expect(during.alerts.filter((a) => a.detection.ruleId === 'sigap-web-sqli')).toHaveLength(1)
    expect(during.alerts.every((a) => a.detection.level === 'high' || a.detection.level === 'critical')).toBe(true)
  })

  it('finds the same incident as SIGAP Kit does on the whole file', () => {
    const live = new Penjaga({ pack, profile: DEFAULT_UNIT_PROFILE })
    stream(live, events)
    const batch = new Penjaga({ pack, profile: DEFAULT_UNIT_PROFILE })
    batch.push(events)
    expect(live.incidents.map((i) => [i.title, i.detectionIds.length, i.score])).toEqual(batch.incidents.map((i) => [i.title, i.detectionIds.length, i.score]))
  })

  it('does not alert again after a restart', () => {
    const first = new Penjaga({ pack, profile: DEFAULT_UNIT_PROFILE })
    first.push(events)
    const second = new Penjaga({ pack, profile: DEFAULT_UNIT_PROFILE })
    second.restore(first.windowEvents())
    expect(second.push(first.windowEvents())).toEqual({ alerts: [], updates: [] })
    expect(second.incidents).toHaveLength(1)
  })

  it('drops events older than the window', () => {
    const penjaga = new Penjaga({ pack, profile: DEFAULT_UNIT_PROFILE, windowMs: 60 * 60_000 })
    penjaga.push(events)
    expect(penjaga.windowEvents()[0].ts).toBeGreaterThanOrEqual(events.at(-1)!.ts - 60 * 60_000)
  })
})

describe('Tailer', () => {
  let dir: string
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  const texts = async (tailer: Tailer, paths: string[]) => (await tailer.poll(paths)).map((c) => c.text).join('')

  it('returns whole lines only, then the rest once it is written', async () => {
    dir = await mkdtemp(join(tmpdir(), 'sigap-tail-'))
    const log = join(dir, 'access.log')
    await writeFile(log, 'satu\ndu')
    const tailer = new Tailer()
    expect(await texts(tailer, [dir])).toBe('satu\n')
    expect(await texts(tailer, [dir])).toBe('')
    await appendFile(log, 'a\ntiga\n')
    expect(await texts(tailer, [dir])).toBe('dua\ntiga\n')
  })

  it('follows rotation by rename without re-reading, and copytruncate from the start', async () => {
    dir = await mkdtemp(join(tmpdir(), 'sigap-tail-'))
    const log = join(dir, 'access.log')
    await writeFile(log, 'lama-1\nlama-2\n')
    const tailer = new Tailer()
    await tailer.poll([dir])
    await rename(log, join(dir, 'access.log.1'))
    await writeFile(log, 'baru-1\n')
    expect(await texts(tailer, [dir])).toBe('baru-1\n')
    await writeFile(log, 'x\n') // truncated and rewritten, shorter than before
    expect(await texts(tailer, [dir])).toBe('x\n')
  })

  it('skips compressed rotations and can start at the end of existing files', async () => {
    dir = await mkdtemp(join(tmpdir(), 'sigap-tail-'))
    await writeFile(join(dir, 'access.log.2.gz'), 'tidak dibaca\n')
    await writeFile(join(dir, 'auth.log'), 'sudah ada\n')
    const tailer = new Tailer({ files: {} }, false)
    expect(await texts(tailer, [dir])).toBe('')
    await appendFile(join(dir, 'auth.log'), 'baru\n')
    expect(await texts(tailer, [dir])).toBe('baru\n')
  })
})
