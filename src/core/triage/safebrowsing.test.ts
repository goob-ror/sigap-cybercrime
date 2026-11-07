import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { canonicalize, checkUrl, expressions, type HashSearch } from '@/core/triage/safebrowsing'

const canon = (input: string) => canonicalize(input)?.url

describe('canonicalize (test vectors published by Google)', () => {
  it.each([
    ['http://host/%25%32%35', 'http://host/%25'],
    ['http://host/%25%32%35%25%32%35', 'http://host/%25%25'],
    ['http://host/%2525252525252525', 'http://host/%25'],
    ['http://host/asdf%25%32%35asd', 'http://host/asdf%25asd'],
    ['http://host/%%%25%32%35asd%%', 'http://host/%25%25%25asd%25%25'],
    ['http://www.google.com/', 'http://www.google.com/'],
    ['http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/', 'http://168.188.99.26/.secure/www.ebay.com/'],
    ['http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B', 'http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+'],
    ['http://3279880203/blah', 'http://195.127.0.11/blah'],
    ['http://www.google.com/blah/..', 'http://www.google.com/'],
    ['www.google.com/', 'http://www.google.com/'],
    ['www.google.com', 'http://www.google.com/'],
    ['http://www.evil.com/blah#frag', 'http://www.evil.com/blah'],
    ['http://www.GOOgle.com/', 'http://www.google.com/'],
    ['http://www.google.com.../', 'http://www.google.com/'],
    ['http://www.google.com/foo\tbar\rbaz\n2', 'http://www.google.com/foobarbaz2'],
    ['http://www.google.com/q?', 'http://www.google.com/q?'],
    ['http://www.google.com/q?r?', 'http://www.google.com/q?r?'],
    ['http://www.google.com/q?r?s', 'http://www.google.com/q?r?s'],
    ['http://evil.com/foo#bar#baz', 'http://evil.com/foo'],
    ['http://evil.com/foo;', 'http://evil.com/foo;'],
    ['http://evil.com/foo?bar;', 'http://evil.com/foo?bar;'],
    ['http://notrailingslash.com', 'http://notrailingslash.com/'],
    ['http://www.gotaport.com:1234/', 'http://www.gotaport.com/'],
    ['  http://www.google.com/  ', 'http://www.google.com/'],
    ['http:// leadingspace.com/', 'http://%20leadingspace.com/'],
    ['http://%20leadingspace.com/', 'http://%20leadingspace.com/'],
    ['%20leadingspace.com/', 'http://%20leadingspace.com/'],
    ['https://www.securesite.com/', 'https://www.securesite.com/'],
    ['http://host.com/ab%23cd', 'http://host.com/ab%23cd'],
    ['http://host.com//twoslashes?more//slashes', 'http://host.com/twoslashes?more//slashes'],
  ])('%s', (input, expected) => {
    expect(canon(input)).toBe(expected)
  })

  it('finds no host in an empty address', () => {
    expect(canonicalize('')).toBeNull()
    expect(canonicalize('http:///path')).toBeNull()
  })

  it('reads the disguised ways of writing an address, and drops a login part', () => {
    expect(canon('http://0xC3.0x7F.0.11/')).toBe('http://195.127.0.11/')
    expect(canon('http://0303.0177.0.11/')).toBe('http://195.127.0.11/')
    expect(canon('http://user:pw@evil.example/x')).toBe('http://evil.example/x')
  })

  it('does not mistake a numeric-looking name for an address', () => {
    expect(canon('http://1.2.3.4.5/')).toBe('http://1.2.3.4.5/')
    expect(canon('http://999.1.1.1/')).toBe('http://999.1.1.1/')
  })
})

describe('expressions', () => {
  const of = (input: string) => expressions(canonicalize(input)!).sort()

  it('matches the example in Google\'s documentation', () => {
    expect(of('http://a.b.c/1/2.html?param=1')).toEqual(['a.b.c/', 'a.b.c/1/', 'a.b.c/1/2.html', 'a.b.c/1/2.html?param=1', 'b.c/', 'b.c/1/', 'b.c/1/2.html', 'b.c/1/2.html?param=1'])
  })

  it('stops at five hosts and six paths', () => {
    const all = of('http://a.b.c.d.e.f.g/1.html')
    expect(all).toEqual(['a.b.c.d.e.f.g/', 'a.b.c.d.e.f.g/1.html', 'c.d.e.f.g/', 'c.d.e.f.g/1.html', 'd.e.f.g/', 'd.e.f.g/1.html', 'e.f.g/', 'e.f.g/1.html', 'f.g/', 'f.g/1.html'])
    expect(of('http://x.y/a/b/c/d/e/f.html?q=1')).toEqual(['x.y/', 'x.y/a/', 'x.y/a/b/', 'x.y/a/b/c/', 'x.y/a/b/c/d/e/f.html', 'x.y/a/b/c/d/e/f.html?q=1'])
    expect(of('http://a.b.c.d.e.f.g.h/a/b/c/d/e/f.html?q=1').length).toBeLessThanOrEqual(30)
  })

  it('never shortens an address, whose parts mean nothing alone', () => {
    expect(of('http://1.2.3.4/a')).toEqual(['1.2.3.4/', '1.2.3.4/a'])
  })
})

const sha = (text: string) => createHash('sha256').update(text).digest()

describe('checkUrl', () => {
  it('sends 4-byte prefixes and never the address', async () => {
    let sent: string[] = []
    const search: HashSearch = async (prefixes) => { sent = prefixes; return { matches: [], cacheSeconds: 300 } }
    const verdict = await checkUrl('http://evil.example/rahasia?token=abc', search)
    expect(verdict).toEqual({ host: 'evil.example', checked: sent.length, threats: [], cacheSeconds: 300 })
    expect(sent.length).toBeGreaterThan(0)
    for (const prefix of sent) expect(Buffer.from(prefix, 'base64')).toHaveLength(4)
    expect(JSON.stringify(sent)).not.toContain('evil')
    expect(sent).toContain(sha('evil.example/').subarray(0, 4).toString('base64'))
  })

  it('counts a threat only when the whole hash matches: a shared prefix is not a match', async () => {
    const real = sha('evil.example/').toString('base64')
    const lookalike = Buffer.concat([sha('evil.example/').subarray(0, 4), Buffer.alloc(28, 1)]).toString('base64')
    const hit = await checkUrl('http://evil.example/', async () => ({ matches: [{ hash: real, threats: ['MALWARE'] }, { hash: lookalike, threats: ['SOCIAL_ENGINEERING'] }], cacheSeconds: 60 }))
    expect(hit?.threats).toEqual(['MALWARE'])
    const miss = await checkUrl('http://evil.example/', async () => ({ matches: [{ hash: lookalike, threats: ['MALWARE'] }], cacheSeconds: 60 }))
    expect(miss?.threats).toEqual([])
  })

  it('catches a listed domain from a deep page on a subdomain', async () => {
    const listed = sha('evil.example/').toString('base64')
    const verdict = await checkUrl('https://login.evil.example/a/b.html?x=1', async () => ({ matches: [{ hash: listed, threats: ['SOCIAL_ENGINEERING'] }], cacheSeconds: 60 }))
    expect(verdict?.threats).toEqual(['SOCIAL_ENGINEERING'])
  })

  it('asks nothing when there is no host', async () => {
    let asked = false
    expect(await checkUrl('', async () => { asked = true; return { matches: [], cacheSeconds: 0 } })).toBeNull()
    expect(asked).toBe(false)
  })
})
