import JSZip from 'jszip'
import { parseCollectionInfo, type CollectionInfo } from '@/core/coverage'
import { parseManifest, sha256Hex } from '@/core/evidence/hash'
import { decodeText } from '@/core/ingest/util'

/**
 * Opens a ZIP of log files, such as the one the SIGAP collector writes, so an operator can import it
 * without unpacking it first. When it carries a `MANIFEST-SHA256.txt`, every file is checked against
 * it and the ZIP is refused on any difference: it is evidence, and importing it would hide the change.
 */

export type ArchiveEntry = { name: string; bytes: Uint8Array }
/** `collection`: what the collector recorded, such as which logs it could not read. */
export type ExpandedZip = { logs: ArchiveEntry[]; collection?: CollectionInfo }
export class ArchiveError extends Error {}

const MANIFEST = /^manifest-sha256\.txt$/i
/** Files that describe the ZIP rather than hold logs. */
const NOT_LOGS = /^(info-pengumpulan\.json|readme.*|baca-saya.*|\.ds_store|thumbs\.db)$/i
const COLLECTION_INFO = /^info-pengumpulan\.json$/i
const MAX_UNPACKED = 1024 ** 3

const baseName = (path: string) => path.split(/[\\/]/).pop() ?? path

/** True for ZIP data (magic bytes `PK\x03\x04`, or `PK\x05\x06` when empty). */
export function isZip(bytes: Uint8Array): boolean {
  return bytes.length > 3 && bytes[0] === 0x50 && bytes[1] === 0x4b && ((bytes[2] === 3 && bytes[3] === 4) || (bytes[2] === 5 && bytes[3] === 6))
}

export async function expandZip(bytes: Uint8Array): Promise<ExpandedZip> {
  let zip: JSZip
  try {
    zip = await JSZip.loadAsync(bytes)
  } catch (err) {
    throw new ArchiveError(`ZIP rusak atau tidak dapat dibuka: ${(err as Error).message}`)
  }
  const files = Object.values(zip.files).filter((f) => !f.dir && !/(^|[\\/])__MACOSX[\\/]/.test(f.name))

  // Checked before unpacking: a small ZIP can expand to more than the browser has memory for.
  // JSZip has no public field for the size a file declares.
  const declared = files.reduce((sum, f) => sum + ((f as unknown as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0), 0)
  if (declared > MAX_UNPACKED) throw new ArchiveError('Isi ZIP lebih dari 1 GB. Bongkar dahulu, lalu impor berkasnya sedikit demi sedikit.')

  const entries = await Promise.all(files.map(async (f) => ({ name: baseName(f.name), path: f.name.replace(/\\/g, '/'), bytes: await f.async('uint8array') })))
  const logs = entries.filter((e) => !MANIFEST.test(e.name) && !NOT_LOGS.test(e.name))
  const manifest = entries.find((e) => MANIFEST.test(e.name))

  if (manifest) {
    const listed = parseManifest(new TextDecoder().decode(manifest.bytes))
    const problems: string[] = []
    for (const line of listed) {
      const entry = entries.find((e) => e.path === line.name.replace(/\\/g, '/') || e.name === baseName(line.name))
      if (!entry) problems.push(`${line.name} hilang`)
      else if ((await sha256Hex(entry.bytes)) !== line.hash) problems.push(`${line.name} berubah`)
    }
    for (const log of logs) if (!listed.some((l) => l.name.replace(/\\/g, '/') === log.path || baseName(l.name) === log.name)) problems.push(`${log.name} tidak tercatat`)
    if (problems.length) throw new ArchiveError(`Isi ZIP tidak cocok dengan MANIFEST-SHA256.txt (${problems.slice(0, 5).join('; ')}). Berkas tidak diimpor; minta pengumpulan ulang.`)
  }

  if (!logs.length) throw new ArchiveError('ZIP tidak berisi berkas log.')
  const info = entries.find((e) => COLLECTION_INFO.test(e.name))
  return { logs: logs.map(({ name, bytes }) => ({ name, bytes })), collection: info ? parseCollectionInfo(decodeText(info.bytes)) : undefined }
}
