import { describe, expect, it } from 'vitest'
import { computeCoverage } from '@/core/coverage'
import { runDetections } from '@/core/detect/engine'
import { indexLists, matchHost, parseIndicatorList, type IndicatorList } from '@/core/indicators'
import { correlate } from '@/core/correlate/correlate'
import type { NormalizedEvent } from '@/core/model'
import { incidentStory } from '@/core/report/narrative'
import { loadRulePack } from '@/data/rules'
import { RULES } from '@/data/rules/catalog'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const SHA = 'a'.repeat(64)

function list(name: string, text: string): IndicatorList {
  return { id: name, name, importedAt: 0, importedBy: 'uji', sha256: '0', ...parseIndicatorList(text) }
}

function event(id: string, change: Partial<NormalizedEvent>): NormalizedEvent {
  return { id, importId: 'i', ts: 1_000, host: 'WS-1', dataset: 'x', logsource: { product: 'zeek', service: 'dns' }, fields: {}, raw: '', ...change } as NormalizedEvent
}

describe('parseIndicatorList', () => {
  it('reads a hosts file, leaving out comments', () => {
    const parsed = parseIndicatorList('# URLhaus\n127.0.0.1\tevil.example\n0.0.0.0 bad.example  # note\n::1 ipv6.example\n\n! comment')
    expect(parsed.domains.sort()).toEqual(['bad.example', 'evil.example', 'ipv6.example'])
    expect(parsed.skipped).toBe(0)
  })

  it('reads a CSV feed with a URL column, taking the host of each', () => {
    const parsed = parseIndicatorList('# id,dateadded,url,status\n"1","2026-01-01","http://evil.example/a.exe","online"\n2,2026-01-01,http://203.0.113.9:8080/b,online\n')
    expect(parsed.domains).toEqual(['evil.example'])
    expect(parsed.ips).toEqual(['203.0.113.9'])
  })

  it('reads a plain list of domains, addresses and hashes, in any case', () => {
    const parsed = parseIndicatorList(`EVIL.example.\n203.0.113.5\n${SHA.toUpperCase()}\nbukan indikator!\n`)
    expect(parsed).toEqual({ domains: ['evil.example'], ips: ['203.0.113.5'], hashes: [SHA], skipped: 1 })
  })

  it('reads an RPZ zone, and counts what it cannot read rather than guessing', () => {
    const parsed = parseIndicatorList('$TTL 300\n; zone\nevil.example CNAME .\n@ SOA ns. admin. 1 1 1 1 1\n')
    expect(parsed.domains).toEqual(['evil.example'])
    expect(parsed.skipped).toBe(0)
  })

  it('removes duplicates', () => {
    expect(parseIndicatorList('a.example\na.example\n0.0.0.0 a.example').domains).toEqual(['a.example'])
  })
})

describe('matchHost', () => {
  const index = indexLists([list('Daftar A', 'evil.example\n203.0.113.5'), list('Daftar B', 'evil.example\nother.example')])

  it('covers subdomains, and names the first list holding it', () => {
    expect(matchHost('a.b.evil.example', index)).toEqual({ indicator: 'evil.example', list: 'Daftar A' })
    expect(matchHost('OTHER.example.', index)).toEqual({ indicator: 'other.example', list: 'Daftar B' })
    expect(matchHost('203.0.113.5', index)).toEqual({ indicator: '203.0.113.5', list: 'Daftar A' })
  })

  it('does not match a name that merely ends the same, or a top-level domain', () => {
    expect(matchHost('notevil.example', index)).toBeNull()
    expect(matchHost('example', index)).toBeNull()
    expect(matchHost('203.0.113.55', index)).toBeNull()
  })
})

describe('indicator rule', () => {
  const lists = [list('URLhaus', `evil.example\n203.0.113.5\n${SHA}`)]
  const events = [
    event('dns', { domain: 'cdn.evil.example' }),
    event('dns2', { domain: 'cdn.evil.example', ts: 2_000 }),
    event('conn', { host: 'WS-2', dstIp: '203.0.113.5' }),
    event('file', { host: 'WS-3', file: { sha256: SHA.toUpperCase() } } as Partial<NormalizedEvent>),
    event('clean', { domain: 'baik.example', dstIp: '198.51.100.1' }),
  ]

  it('runs only when there is a list, so the rule count stays honest', () => {
    expect(loadRulePack(DEFAULT_UNIT_PROFILE).native.some((r) => r.meta.id === 'sigap-native-indicator-list')).toBe(false)
    expect(loadRulePack(DEFAULT_UNIT_PROFILE, lists).native.some((r) => r.meta.id === 'sigap-native-indicator-list')).toBe(true)
    expect(runDetections(events, loadRulePack(DEFAULT_UNIT_PROFILE)).filter((d) => d.ruleId === 'sigap-native-indicator-list')).toEqual([])
  })

  it('makes one finding per address and host, with the list named, and rates it as needing a check', () => {
    const hits = runDetections(events, loadRulePack(DEFAULT_UNIT_PROFILE, lists)).filter((d) => d.ruleId === 'sigap-native-indicator-list')
    expect(hits).toHaveLength(3)
    const domain = hits.find((d) => d.matched.Indikator === 'evil.example')!
    expect(domain.eventIds).toEqual(['dns', 'dns2'])
    expect(domain.matched.Daftar).toBe('URLhaus')
    expect(domain.signal).toBe('ambigu')
    expect(hits.map((d) => d.matched.Indikator).sort()).toEqual(['203.0.113.5', SHA, 'evil.example'].sort())
  })

  it('has its title and response steps in the catalog the pages read', () => {
    expect(RULES.get('sigap-native-indicator-list')?.respons.length).toBeGreaterThan(0)
  })

  it('becomes an incident with a readable story, despite naming no ATT&CK technique', () => {
    const pack = loadRulePack(DEFAULT_UNIT_PROFILE, lists)
    const detections = runDetections(events, pack)
    const { incidents } = correlate(detections, events, DEFAULT_UNIT_PROFILE)
    expect(incidents.length).toBeGreaterThan(0)
    const byId = new Map(detections.map((d) => [d.id, d]))
    const story = incidentStory(incidents[0], byId, new Map(events.map((e) => [e.id, e])))
    expect(story.length).toBeGreaterThan(0)
    for (const step of story) expect(step.label).toBeTruthy()
  })

  it('counts as a rule with data once a log is present', () => {
    const metas = (p: ReturnType<typeof loadRulePack>) => [...p.sigma, ...p.native].map((r) => r.meta)
    const without = computeCoverage(events, metas(loadRulePack(DEFAULT_UNIT_PROFILE)))
    const withList = computeCoverage(events, metas(loadRulePack(DEFAULT_UNIT_PROFILE, lists)))
    expect(withList.rulesTotal).toBe(without.rulesTotal + 1)
    expect(withList.rulesWithData).toBe(without.rulesWithData + 1)
    expect(computeCoverage([], metas(loadRulePack(DEFAULT_UNIT_PROFILE, lists))).rulesWithData).toBe(0)
  })
})
