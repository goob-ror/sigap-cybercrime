import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { createApi, decodeHashesResponse } from './api.mjs'

const SB_KEY = 'safebrowsing-test-key-0123456789'
const KEYS = { SAFE_BROWSING_API: SB_KEY }
const PREFIX = 'AAAAAA=='

type Upstream = { url: string; init: RequestInit }

const servers: http.Server[] = []
afterEach(() => { for (const s of servers.splice(0)) s.close() })

/** A real HTTP server around the API, so headers, bodies and limits behave as they will in production. */
async function start(env: Record<string, string>, fetchImpl: (url: string, init: RequestInit) => Promise<Response> = async () => new Response(new Uint8Array()), now?: () => number) {
  const calls: Upstream[] = []
  const api = createApi({ env, now, fetchImpl: ((url: string, init: RequestInit) => { calls.push({ url, init }); return fetchImpl(url, init) }) as typeof fetch })
  const server = http.createServer((req, res) => {
    void api.handle(req, res).then((handled) => { if (!handled) { res.statusCode = 404; res.end('app') } })
  })
  servers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  const post = (path: string, body: unknown, headers: Record<string, string> = { 'content-type': 'application/json' }) => fetch(`${base}${path}`, { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body) })
  return { base, calls, post }
}

/** Protobuf encoders for what Google's response looks like. */
const varint = (n: number) => { const out: number[] = []; while (n > 127) { out.push((n & 127) | 128); n = Math.floor(n / 128) } out.push(n); return out }
const tagged = (field: number, n: number) => [...varint(field * 8), ...varint(n)]
const bytes = (field: number, value: number[]) => [...varint(field * 8 + 2), ...varint(value.length), ...value]
const detail = (threat: number, attributes: number[] = []) => bytes(2, [...tagged(1, threat), ...attributes.flatMap((a) => tagged(2, a))])
const fullHash = (seed: number, details: number[]) => bytes(1, [...bytes(1, new Array(32).fill(seed)), ...details])
const cache = (seconds: number) => bytes(2, tagged(1, seconds))

describe('status', () => {
  it('reports what is set up, and never the key', async () => {
    const { base } = await start(KEYS)
    const response = await fetch(`${base}/api/status`)
    const text = await response.text()
    expect(JSON.parse(text)).toEqual({ safeBrowsing: true })
    expect(text).not.toContain(SB_KEY)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })

  it('treats a placeholder left in .env as no key', async () => {
    const { base } = await start({ SAFE_BROWSING_API: 'your-key-here' })
    expect(await (await fetch(`${base}/api/status`)).json()).toEqual({ safeBrowsing: false })
  })

  it('answers under a subfolder, and leaves every other path to the app', async () => {
    const { base } = await start(KEYS)
    expect((await fetch(`${base}/sigap/api/status`)).status).toBe(200)
    expect(await (await fetch(`${base}/index.html`)).text()).toBe('app')
  })
})

describe('requests from elsewhere', () => {
  it('answers only its own pages', async () => {
    const { base, post, calls } = await start(KEYS)
    const json = { 'content-type': 'application/json' }
    const body = { hashPrefixes: [PREFIX] }
    expect((await post('/api/safe-browsing', body, { ...json, origin: 'https://evil.example' })).status).toBe(403)
    expect((await post('/api/safe-browsing', body, { ...json, origin: 'null' })).status).toBe(403)
    expect(calls).toHaveLength(0)
    expect((await post('/api/safe-browsing', body, { ...json, origin: base })).status).toBe(200)
  })

  it('refuses what a cross-site form could send', async () => {
    const { post, calls } = await start(KEYS)
    expect((await post('/api/safe-browsing', 'hashPrefixes=AAAAAA', { 'content-type': 'application/x-www-form-urlencoded' })).status).toBe(415)
    expect((await post('/api/safe-browsing', 'bukan json')).status).toBe(400)
    expect((await post('/api/safe-browsing', '[1]')).status).toBe(400)
    expect(calls).toHaveLength(0)
  })

  it('refuses an oversized body and a wrong method', async () => {
    const { base, post } = await start(KEYS)
    expect((await post('/api/safe-browsing', { hashPrefixes: [PREFIX], x: 'a'.repeat(70_000) })).status).toBe(413)
    expect((await fetch(`${base}/api/safe-browsing`)).status).toBe(405)
    expect((await fetch(`${base}/api/status`, { method: 'POST' })).status).toBe(405)
  })

  it('has no route that reaches anything but Safe Browsing', async () => {
    const { post, calls } = await start(KEYS)
    expect(await (await post('/api/ai', { task: 'jelaskan', facts: {} })).text()).toBe('app')
    expect(calls).toHaveLength(0)
  })
})

describe('Safe Browsing', () => {
  it('passes prefixes only, with the key in a header, and decodes the answer', async () => {
    const answer = new Uint8Array([...fullHash(7, detail(2)), ...cache(300)])
    const { post, calls } = await start(KEYS, async () => new Response(answer))
    const response = await post('/api/safe-browsing', { hashPrefixes: [PREFIX, PREFIX] })
    expect(await response.json()).toEqual({ matches: [{ hash: Buffer.alloc(32, 7).toString('base64'), threats: ['SOCIAL_ENGINEERING'] }], cacheSeconds: 300 })
    expect(calls[0].url).toContain(`hashPrefixes=${encodeURIComponent(PREFIX)}`)
    expect(calls[0].url.match(/hashPrefixes/g)).toHaveLength(1)
    expect(calls[0].url).not.toContain(SB_KEY)
    expect((calls[0].init.headers as Record<string, string>)['x-goog-api-key']).toBe(SB_KEY)
  })

  it('refuses anything that is not a 4-byte prefix, such as a URL or a whole hash', async () => {
    const { post, calls } = await start(KEYS)
    for (const hashPrefixes of [['http://evil.example/'], ['AAAAAAAAAAA='], [PREFIX, 'x'], [], 'AAAAAA==', new Array(61).fill(PREFIX)]) {
      expect((await post('/api/safe-browsing', { hashPrefixes })).status).toBe(400)
    }
    expect(calls).toHaveLength(0)
  })

  it('decodes several threats, and leaves out what Google says is not for warnings', () => {
    const decoded = decodeHashesResponse(new Uint8Array([
      ...fullHash(1, [...detail(1), ...detail(3)]),
      ...fullHash(2, detail(2, [1])), // CANARY
      ...fullHash(3, detail(4, [2])), // FRAME_ONLY
      ...fullHash(4, detail(99)), // a type this version does not know
      ...cache(70_000),
    ]))
    expect(decoded.matches).toEqual([{ hash: Buffer.alloc(32, 1).toString('base64'), threats: ['MALWARE', 'UNWANTED_SOFTWARE'] }])
    expect(decoded.cacheSeconds).toBe(70_000)
  })

  it('reads an empty answer as no match, and a broken one as an error', async () => {
    expect(decodeHashesResponse(new Uint8Array())).toEqual({ matches: [], cacheSeconds: 0 })
    const { post } = await start(KEYS, async () => new Response(new Uint8Array([0x0a, 0xff])))
    expect((await post('/api/safe-browsing', { hashPrefixes: [PREFIX] })).status).toBe(502)
  })

  it('stops at the hourly limit, then recovers', async () => {
    let time = 0
    const { post, calls } = await start({ ...KEYS, SAFE_BROWSING_LIMIT_PER_HOUR: '1' }, undefined, () => time)
    const ask = () => post('/api/safe-browsing', { hashPrefixes: [PREFIX] })
    expect((await ask()).status).toBe(200)
    expect((await ask()).status).toBe(429)
    expect(calls).toHaveLength(1)
    time += 60 * 60_000
    expect((await ask()).status).toBe(200)
  })

  it('is off without a key', async () => {
    const { post } = await start({})
    expect((await post('/api/safe-browsing', { hashPrefixes: [PREFIX] })).status).toBe(503)
  })

  it('never passes on what Google says, which could quote the key', async () => {
    const { post } = await start(KEYS, async () => new Response(`bad key ${SB_KEY}`, { status: 403 }))
    const response = await post('/api/safe-browsing', { hashPrefixes: [PREFIX] })
    expect(response.status).toBe(502)
    expect(await response.text()).not.toContain(SB_KEY)
  })

  it('reports an unreachable service, and an exhausted quota', async () => {
    const down = await start(KEYS, async () => { throw new Error(`connect failed ${SB_KEY}`) })
    const response = await down.post('/api/safe-browsing', { hashPrefixes: [PREFIX] })
    expect(response.status).toBe(502)
    expect(await response.text()).not.toContain(SB_KEY)
    const quota = await start(KEYS, async () => new Response('{}', { status: 429 }))
    expect((await quota.post('/api/safe-browsing', { hashPrefixes: [PREFIX] })).status).toBe(429)
  })
})
