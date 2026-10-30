import { describe, expect, it } from 'vitest'
import { load } from 'js-yaml'
import { compileSigma, globToRegex, loadSigmaRules, parseCondition } from '@/core/detect/sigma'
import type { NormalizedEvent } from '@/core/model'

function event(fields: NormalizedEvent['fields'], logsource: NormalizedEvent['logsource'] = { product: 'windows', category: 'process_creation' }): NormalizedEvent {
  return { id: 'e1', ts: 0, dataset: 'test', sourceKind: 'endpoint', logsource, message: '', importId: 'i', fields }
}

function rule(detection: string, logsource = '{ product: windows, category: process_creation }') {
  return compileSigma(load(`title: t\nid: r\nlogsource: ${logsource}\ndetection:\n${detection}`) as Record<string, unknown>)
}

describe('globToRegex', () => {
  it('treats * and ? as wildcards, case-insensitively', () => {
    expect(globToRegex('*\\WINWORD.EXE').test('C:\\Office\\winword.exe')).toBe(true)
    expect(globToRegex('a?c').test('abc')).toBe(true)
    expect(globToRegex('a?c').test('abbc')).toBe(false)
  })

  it('keeps escaped wildcards literal', () => {
    expect(globToRegex('100\\*').test('100*')).toBe(true)
    expect(globToRegex('100\\*').test('1000')).toBe(false)
  })
})

describe('parseCondition', () => {
  it('gives not > and > or precedence', () => {
    expect(parseCondition('a or b and not c')).toEqual({ op: 'or', args: [{ op: 'ref', name: 'a' }, { op: 'and', args: [{ op: 'ref', name: 'b' }, { op: 'not', arg: { op: 'ref', name: 'c' } }] }] })
  })

  it('rejects aggregations', () => {
    expect(() => parseCondition('selection | count() > 5')).toThrow('Agregasi')
  })
})

describe('compileSigma', () => {
  it('ANDs fields in a map and ORs list values', () => {
    const r = rule(`  sel:\n    Image|endswith: ['\\cmd.exe', '\\powershell.exe']\n    CommandLine|contains: whoami\n  condition: sel`)
    expect(r.match(event({ Image: 'C:\\x\\powershell.exe', CommandLine: 'cmd /c WHOAMI' }))).toEqual({ Image: 'C:\\x\\powershell.exe', CommandLine: 'cmd /c WHOAMI' })
    expect(r.match(event({ Image: 'C:\\x\\notepad.exe', CommandLine: 'whoami' }))).toBeNull()
  })

  it('supports |all, not-filters and only reports positive matches', () => {
    const r = rule(`  sel:\n    CommandLine|contains|all: [comsvcs, MiniDump]\n  filter:\n    User: SYSTEM\n  condition: sel and not filter`)
    expect(r.match(event({ CommandLine: 'rundll32 comsvcs.dll, MiniDump 1 x full', User: 'rina' }))).toEqual({ CommandLine: 'rundll32 comsvcs.dll, MiniDump 1 x full' })
    expect(r.match(event({ CommandLine: 'rundll32 comsvcs.dll', User: 'rina' }))).toBeNull()
    expect(r.match(event({ CommandLine: 'comsvcs MiniDump', User: 'SYSTEM' }))).toBeNull()
  })

  it('supports 1 of / all of with wildcards', () => {
    const r = rule(`  sel_a:\n    EventID: 1102\n  sel_b:\n    EventID: 104\n  condition: 1 of sel_*`, '{ product: windows }')
    expect(r.match(event({ EventID: 104 }, { product: 'windows', service: 'system' }))).not.toBeNull()
    expect(r.match(event({ EventID: 4624 }, { product: 'windows' }))).toBeNull()
  })

  it('supports cidr, numeric comparisons and windash', () => {
    const net = rule(`  sel:\n    DestinationIp|cidr: 10.0.0.0/8\n  condition: not sel`, '{ category: network_connection }')
    expect(net.match(event({ DestinationIp: '203.0.113.66' }, { category: 'network_connection' }))).not.toBeNull()
    expect(net.match(event({ DestinationIp: '10.1.2.3' }, { category: 'network_connection' }))).toBeNull()

    const num = rule(`  sel:\n    values|gt: 240\n  condition: sel`, '{ product: zeek }')
    expect(num.match(event({ values: '265' }, { product: 'zeek' }))).not.toBeNull()
    expect(num.match(event({ values: '230' }, { product: 'zeek' }))).toBeNull()

    const dash = rule(`  sel:\n    CommandLine|windash|contains: ' -create '\n  condition: sel`)
    expect(dash.match(event({ CommandLine: 'schtasks /create /tn x' }))).not.toBeNull()
  })

  it('treats null as "field absent" and checks the logsource', () => {
    const r = rule(`  sel:\n    ParentImage: null\n  condition: sel`)
    expect(r.match(event({ Image: 'x' }))).not.toBeNull()
    expect(r.match(event({ Image: 'x' }, { product: 'windows', category: 'file_event' }))).toBeNull()
  })

  it('matches keyword lists against any field', () => {
    const r = rule(`  keywords: ['mimikatz', 'sekurlsa']\n  condition: keywords`)
    expect(r.match(event({ CommandLine: 'x sekurlsa::logonpasswords' }))).toEqual({ CommandLine: 'x sekurlsa::logonpasswords' })
  })
})

describe('loadSigmaRules', () => {
  it('skips unsupported rules with a reason instead of failing', () => {
    const { rules, skipped } = loadSigmaRules({
      'a.yml': 'title: ok\nid: ok\nlogsource: {product: windows}\ndetection:\n  s:\n    EventID: 1\n  condition: s\n---\ntitle: agg\nid: agg\nlogsource: {product: windows}\ndetection:\n  s:\n    EventID: 1\n  condition: s | count() > 3\n---\ntitle: b64\nid: b64\nlogsource: {product: windows}\ndetection:\n  s:\n    CommandLine|base64: x\n  condition: s',
    })
    expect(rules.map((r) => r.meta.id)).toEqual(['ok'])
    expect(skipped.map((s) => s.source)).toEqual(['a.yml#agg', 'a.yml#b64'])
  })
})
