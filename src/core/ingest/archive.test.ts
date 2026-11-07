import { describe, expect, it } from 'vitest'
import JSZip from 'jszip'
import { sha256Hex } from '@/core/evidence/hash'
import { ArchiveError, expandZip, isZip } from '@/core/ingest/archive'
import { ingestText } from '@/core/ingest'
import { decodeText } from '@/core/ingest/util'

const LOG = JSON.stringify([{ EventID: 4625, Channel: 'Security', Computer: 'WS-MIN-03', TimeCreated: '2026-11-02T02:13:02.0000000Z', EventData: { TargetUserName: 'sertu.rina', IpAddress: '10.20.1.44' } }])

async function zipOf(files: Record<string, string>): Promise<Uint8Array> {
  const zip = new JSZip()
  for (const [name, text] of Object.entries(files)) zip.file(name, text)
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' })
}

const manifestFor = async (files: Record<string, string>) => (await Promise.all(Object.entries(files).map(async ([name, text]) => `${await sha256Hex(text)}  ${name}`))).join('\r\n')

describe('expandZip', () => {
  it('recognizes ZIP data', async () => {
    expect(isZip(await zipOf({ 'a.log': 'x' }))).toBe(true)
    expect(isZip(new TextEncoder().encode('PK bukan zip'))).toBe(false)
    expect(isZip(new Uint8Array())).toBe(false)
  })

  it('returns the log files of a collector ZIP, which then import normally', async () => {
    const logs = { 'Security.json': LOG }
    const bytes = await zipOf({ ...logs, 'MANIFEST-SHA256.txt': await manifestFor({ ...logs, 'info-pengumpulan.json': '{}' }), 'info-pengumpulan.json': '{}' })
    const { logs: entries } = await expandZip(bytes)
    expect(entries.map((e) => e.name)).toEqual(['Security.json'])
    const result = ingestText(decodeText(entries[0].bytes), entries[0].name, 'imp')
    expect(result.format).toBe('winevent-jsonl')
    expect(result.events[0]).toMatchObject({ host: 'WS-MIN-03', user: 'sertu.rina' })
  })

  it('accepts a ZIP without a manifest and flattens folders', async () => {
    const { logs: entries, collection } = await expandZip(await zipOf({ 'folder/web-01-access.log': 'baris', '__MACOSX/._x': 'sampah' }))
    expect(entries.map((e) => e.name)).toEqual(['web-01-access.log'])
    expect(collection).toBeUndefined()
  })

  it('reads what the collector recorded about logs it could not read', async () => {
    const info = JSON.stringify({ komputer: 'WS-1', administrator: false, log: [{ channel: 'Security', status: 'perlu-administrator', terpotong: false }, { channel: 'System', status: 'ok', terpotong: true }, { channel: 'Microsoft-Windows-Sysmon/Operational', status: 'tidak-ada', terpotong: false }] })
    const { collection } = await expandZip(await zipOf({ 'System.json': LOG, 'info-pengumpulan.json': info }))
    expect(collection).toEqual({ computer: 'WS-1', administrator: false, unread: ['Security'], truncated: ['System'] })
  })

  it('refuses a file that differs from the manifest', async () => {
    const manifest = await manifestFor({ 'Security.json': LOG })
    await expect(expandZip(await zipOf({ 'Security.json': `${LOG} `, 'MANIFEST-SHA256.txt': manifest }))).rejects.toThrow('Security.json berubah')
  })

  it('refuses a file the manifest lists but the ZIP lacks', async () => {
    const manifest = await manifestFor({ 'Security.json': LOG, 'System.json': LOG })
    await expect(expandZip(await zipOf({ 'Security.json': LOG, 'MANIFEST-SHA256.txt': manifest }))).rejects.toThrow('System.json hilang')
  })

  it('refuses a log file the manifest does not list', async () => {
    const manifest = await manifestFor({ 'Security.json': LOG })
    await expect(expandZip(await zipOf({ 'Security.json': LOG, 'Selipan.json': LOG, 'MANIFEST-SHA256.txt': manifest }))).rejects.toThrow('Selipan.json tidak tercatat')
  })

  it('refuses data that cannot be opened, and a ZIP with no logs', async () => {
    await expect(expandZip(new Uint8Array([0x50, 0x4b, 3, 4, 0, 0]))).rejects.toThrow(ArchiveError)
    await expect(expandZip(await zipOf({ 'README.txt': 'hanya catatan' }))).rejects.toThrow('tidak berisi berkas log')
  })
})
