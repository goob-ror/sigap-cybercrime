// Assembles the offline kit from `dist/` and `dist-agent/` (run through `npm run build:kit`):
//   dist-kit/sigap-kit.zip          what personnel receive
//   dist/unduh/sigap-kit.zip        the same file, served by the app for download
// The attack-side drill script in tools/ is deliberately left out.
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { copyFile, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import JSZip from 'jszip'

const root = path.resolve(import.meta.dirname, '..')
const from = (...parts) => path.join(root, ...parts)

const FILES = [
  ['kit/README-KIT.txt', 'README-KIT.txt'],
  ['kit/Buka-SIGAP.cmd', 'Buka-SIGAP.cmd'],
  ['kit/buka-sigap.ps1', 'buka-sigap.ps1'],
  ['kit/buka-sigap.sh', 'buka-sigap.sh'],
  ['collector/Kumpulkan-Log.cmd', 'pengumpul-log/Kumpulkan-Log.cmd'],
  ['collector/sigap-collect.ps1', 'pengumpul-log/sigap-collect.ps1'],
  ['collector/README.md', 'pengumpul-log/README.md'],
  ['docs/PANDUAN_LOG_WEB.md', 'panduan/PANDUAN_LOG_WEB.md'],
  ['docs/POS_JAGA.md', 'pos-jaga/POS_JAGA.md'],
  ['dist-agent/pos-jaga.mjs', 'pos-jaga/pos-jaga.mjs'],
]

/** Windows batch files need CRLF and shell scripts need LF, wherever this build runs. */
function withLineEndings(name, bytes) {
  const ext = path.extname(name).toLowerCase()
  if (!['.cmd', '.ps1', '.txt', '.sh', '.md'].includes(ext)) return bytes
  const lf = bytes.toString('utf8').replace(/\r\n/g, '\n')
  return Buffer.from(ext === '.sh' || ext === '.md' ? lf : lf.replace(/\n/g, '\r\n'), 'utf8')
}

async function listFiles(dir, base = dir) {
  const out = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await listFiles(full, base)))
    else out.push(path.relative(base, full).split(path.sep).join('/'))
  }
  return out
}

const missing = ['dist/index.html', ...FILES.map(([source]) => source)].filter((source) => !existsSync(from(source)))
if (missing.length) {
  console.error(`Kit tidak dapat dibuat, berkas tidak ada:\n- ${missing.join('\n- ')}\nJalankan lewat: npm run build:kit`)
  process.exit(1)
}

const zip = new JSZip()
const folder = zip.folder('sigap-kit')
for (const [source, target] of FILES) folder.file(target, withLineEndings(target, await readFile(from(source))))

// The app's own copy of the kit stays out of the kit.
await rm(from('dist/unduh'), { recursive: true, force: true })
for (const name of await listFiles(from('dist'))) folder.file(`app/${name}`, await readFile(from('dist', name)))

const bytes = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 9 } })
const sha256 = createHash('sha256').update(bytes).digest('hex')
const checksum = `${sha256}  sigap-kit.zip\n`

await rm(from('dist-kit'), { recursive: true, force: true })
await mkdir(from('dist-kit'), { recursive: true })
await writeFile(from('dist-kit/sigap-kit.zip'), bytes)
await writeFile(from('dist-kit/sigap-kit.zip.sha256'), checksum)

await mkdir(from('dist/unduh'), { recursive: true })
await copyFile(from('dist-kit/sigap-kit.zip'), from('dist/unduh/sigap-kit.zip'))
await writeFile(from('dist/unduh/sigap-kit.zip.sha256'), checksum)

console.log(`Kit offline: dist-kit/sigap-kit.zip (${(bytes.length / 1024 ** 2).toFixed(2)} MB)\nSHA-256: ${sha256}`)
