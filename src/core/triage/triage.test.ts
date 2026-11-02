import { describe, expect, it } from 'vitest'
import type { NormalizedEvent } from '@/core/model'
import { analyzeUrl } from '@/core/triage/url'
import { matchIocs, parseIndicators } from '@/core/triage/match'
import { decodeAxml } from '@/core/triage/axml'
import { analyzeApk } from '@/core/triage/apk'
import { SAMPLE_APK, SAMPLE_APK_STRINGS, encodeSampleManifest } from '@/data/sampleApk'

// Synthetic, fictional only: RFC 5737 TEST-NET, .example / .top (generic) domains, repeated-byte hashes.
const HASH = 'cd'.repeat(32)
const T0 = Date.UTC(2026, 10, 2, 2, 0, 0)

const ids = (input: string) => new Set(analyzeUrl(input).signals.map((s) => s.id))

describe('analyzeUrl', () => {
  it('finds no structural signal on a plain official-looking URL', () => {
    const r = analyzeUrl('https://portal.satuan.go.id/')
    expect(r.valid).toBe(true)
    expect(r.signals).toHaveLength(0)
    expect(r.score).toBe(0)
  })

  it('raises several signals on a lure URL and scores higher', () => {
    const r = analyzeUrl('http://bri-verif.secure-login.top/akun/update?token=8f2a1c')
    const seen = new Set(r.signals.map((s) => s.id))
    expect(seen).toContain('tld')
    expect(seen).toContain('lure')
    expect(seen).toContain('sensitive-param')
    expect(r.score).toBeGreaterThan(0.4)
  })

  it('flags punycode (incl. IDN homoglyph hosts the URL API converts to xn--)', () => {
    expect(ids('http://xn--pple-43d.com')).toContain('punycode')
    expect(ids('http://pаypal.com')).toContain('punycode') // Cyrillic a -> xn--
  })

  it('flags IP hosts, userinfo and odd schemes', () => {
    expect(ids('http://203.0.113.5/login')).toContain('ip-host')
    expect(ids('http://user@contoh.example/')).toContain('userinfo')
    expect(ids('javascript:alert(1)')).toContain('scheme-odd')
  })

  it('flags URL shorteners', () => {
    expect(ids('https://bit.ly/abc123')).toContain('shortener')
  })

  it('reports invalid input', () => {
    expect(analyzeUrl('').valid).toBe(false)
    expect(analyzeUrl('   ').valid).toBe(false)
  })
})

describe('parseIndicators', () => {
  it('extracts IPs, domains and hashes, refangs, and skips file names', () => {
    const text = `Lihat hxxp://cdn-tukin[.]top dan IP 203.0.113.66
    hash ${HASH}, lampiran laporan.docx (abaikan)`
    const out = parseIndicators(text)
    const byKind = (k: string) => out.filter((i) => i.kind === k).map((i) => i.value)
    expect(byKind('ip')).toEqual(['203.0.113.66'])
    expect(byKind('domain')).toEqual(['cdn-tukin.top'])
    expect(byKind('sha256')).toEqual([HASH])
    expect(out.map((i) => i.value)).not.toContain('laporan.docx')
  })

  it('de-duplicates repeated indicators', () => {
    expect(parseIndicators('203.0.113.66 203.0.113.66 cdn.example cdn.example')).toHaveLength(2)
  })
})

describe('matchIocs', () => {
  const ev = (id: string, rest: Partial<NormalizedEvent>): NormalizedEvent =>
    ({ id, ts: T0, dataset: 'winevent', sourceKind: 'endpoint', logsource: {}, message: id, importId: 'x', fields: {}, ...rest })

  it('finds where each indicator appears in the events, and reports misses', () => {
    const events = [
      ev('e1', { dstIp: '203.0.113.66', host: 'WS-MIN-03' }),
      ev('e2', { domain: 'cdn-tukin.top', host: 'WS-MIN-03' }),
      ev('e3', { process: { sha256: HASH }, host: 'SRV-SATUAN-01' }),
      ev('e4', { srcIp: '10.0.0.5' }), // unrelated internal traffic
    ]
    const indicators = parseIndicators(`203.0.113.66 cdn-tukin.top ${HASH} absent.example`)
    const matches = matchIocs(indicators, events)
    const count = (v: string) => matches.find((m) => m.value === v)!.events.length
    expect(count('203.0.113.66')).toBe(1)
    expect(count('cdn-tukin.top')).toBe(1)
    expect(count(HASH)).toBe(1)
    expect(count('absent.example')).toBe(0)
  })
})

describe('APK triage (AXML)', () => {
  it('round-trips the binary manifest through encode -> decode', () => {
    const m = decodeAxml(encodeSampleManifest())
    expect(m.package).toBe(SAMPLE_APK.package)
    expect(m.versionName).toBe(SAMPLE_APK.versionName)
    expect(m.labels).toContain(SAMPLE_APK.label)
    expect(m.permissions).toEqual(SAMPLE_APK.permissions)
  })

  it('rejects non-AXML bytes', () => {
    expect(() => decodeAxml(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]))).toThrow()
  })

  it('scores the sample APK as high-risk with the right signals', () => {
    const manifest = decodeAxml(encodeSampleManifest())
    const report = analyzeApk({ manifest, strings: SAMPLE_APK_STRINGS, sha256: 'ef'.repeat(32), size: 4096 })
    expect(report.package).toBe(SAMPLE_APK.package)
    expect(report.permissionCount).toBe(SAMPLE_APK.permissions.length)
    expect(report.permissions.some((p) => p.name.endsWith('SEND_SMS'))).toBe(true)
    const signals = report.signals.map((s) => s.id)
    expect(signals).toContain('banker') // SMS + overlay + install
    expect(signals).toContain('sms-contacts')
    expect(report.indicators).toContain('cdn-tukin.example') // embedded endpoint
    expect(report.score).toBeGreaterThan(0.8)
  })

  it('does not flag benign permissions (INTERNET is not dangerous)', () => {
    const manifest = { permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'], labels: [] }
    const report = analyzeApk({ manifest, strings: [], sha256: 'ab'.repeat(32), size: 1024 })
    expect(report.permissions).toHaveLength(0)
    expect(report.score).toBe(0)
  })
})
