import { sha256Hex } from '@/core/evidence/hash'
import { analyzeApk, type ApkReport } from '@/core/triage/apk'
import { decodeAxml } from '@/core/triage/axml'
import { encodeSampleManifest, SAMPLE_APK_STRINGS } from '@/data/sampleApk'

/**
 * Browser-side glue for APK triage: unzip the APK, hash it, read its binary AndroidManifest.xml,
 * and scan entries for embedded URLs — all offline (JSZip + Web Crypto, no network). The sample
 * builder produces our benign demo APK through the exact same path.
 */

const URL_RE = /https?:\/\/[^\s"'<>\\)]{4,200}/gi
const SKIP = /\.(png|jpg|jpeg|gif|webp|arsc|so|ttf|otf|mp3|mp4|ogg)$/i

function printable(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '\n'
  }
  return s
}

export async function analyzeApkBytes(bytes: Uint8Array): Promise<ApkReport> {
  const { default: JSZip } = await import('jszip')
  const sha256 = await sha256Hex(bytes)
  const zip = await JSZip.loadAsync(bytes)
  const manifestFile = zip.file('AndroidManifest.xml')
  if (!manifestFile) throw new Error('Tidak ada AndroidManifest.xml — berkas bukan APK yang valid')
  const manifest = decodeAxml(await manifestFile.async('uint8array'))

  const urls = new Set<string>()
  for (const file of Object.values(zip.files)) {
    if (file.dir || file.name === 'AndroidManifest.xml' || SKIP.test(file.name)) continue
    for (const m of printable(await file.async('uint8array')).match(URL_RE) ?? []) {
      urls.add(m)
      if (urls.size >= 50) break
    }
    if (urls.size >= 50) break
  }
  return analyzeApk({ manifest, strings: [...urls], sha256, size: bytes.byteLength })
}

/** Build our benign sample APK (no code, no payload) so the demo can run the full triage path. */
export async function buildSampleApkBytes(): Promise<Uint8Array> {
  const { default: JSZip } = await import('jszip')
  const zip = new JSZip()
  zip.file('AndroidManifest.xml', encodeSampleManifest())
  zip.file('assets/config.txt', SAMPLE_APK_STRINGS.join('\n'))
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' })
}
