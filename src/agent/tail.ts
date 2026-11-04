import { open, readdir, stat } from 'node:fs/promises'
import { basename, join } from 'node:path'

/**
 * Follows log files the way `tail -F` does, by polling (works the same on Linux, Windows and
 * network shares). Positions are kept per file identity (device + inode), not per name, so:
 *
 * - log rotation by rename (`access.log` -> `access.log.1`) does not re-read the old file,
 * - a new `access.log` after rotation is read from the start,
 * - copy-truncate rotation (file shrinks) is read again from the start.
 *
 * Only whole lines are returned; a line still being written is picked up on the next poll.
 * Compressed rotations (`.gz`) are skipped: their content was already read before compression.
 */

export type FilePosition = { path: string; offset: number }
export type TailState = { files: Record<string, FilePosition> }
export type Chunk = { path: string; id: string; offset: number; text: string }

const MAX_READ = 8 * 1024 * 1024
const SKIP = /\.(gz|zip|bz2|xz|7z|tmp|swp)$|^\./i

/** Files to follow: each path is a file, or a folder whose files (not subfolders) are followed. */
export async function listLogFiles(paths: readonly string[]): Promise<string[]> {
  const out: string[] = []
  for (const p of paths) {
    const s = await stat(p).catch(() => null)
    if (!s) continue
    if (s.isFile()) out.push(p)
    else if (s.isDirectory()) {
      for (const entry of await readdir(p, { withFileTypes: true })) {
        if (entry.isFile() && !SKIP.test(entry.name)) out.push(join(p, entry.name))
      }
    }
  }
  return [...new Set(out)].sort()
}

export class Tailer {
  constructor(
    public state: TailState = { files: {} },
    /** On first sight of a file: read what is already there (true) or only what comes next. */
    private readonly fromStart = true,
  ) {}

  /** Reads the new complete lines of every file. */
  async poll(paths: readonly string[]): Promise<Chunk[]> {
    const chunks: Chunk[] = []
    const seen = new Set<string>()
    for (const path of await listLogFiles(paths)) {
      const s = await stat(path, { bigint: true }).catch(() => null)
      if (!s) continue
      const id = `${s.dev}-${s.ino}`
      seen.add(id)
      const size = Number(s.size)
      let pos = this.state.files[id]
      if (!pos) pos = this.state.files[id] = { path, offset: this.fromStart ? 0 : size }
      pos.path = path
      if (size < pos.offset) pos.offset = 0 // truncated (copytruncate)
      if (size === pos.offset) continue
      const chunk = await readLines(path, pos.offset, Math.min(size, pos.offset + MAX_READ))
      if (!chunk) continue
      chunks.push({ path, id, offset: pos.offset, text: chunk.text })
      pos.offset += chunk.bytes
    }
    // Forget files that no longer exist (rotated away and deleted).
    for (const id of Object.keys(this.state.files)) if (!seen.has(id)) delete this.state.files[id]
    return chunks
  }
}

/** Reads [start, end) and returns the text up to the last newline, with its byte length. */
async function readLines(path: string, start: number, end: number): Promise<{ text: string; bytes: number } | null> {
  const handle = await open(path, 'r')
  try {
    const buffer = Buffer.alloc(end - start)
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, start)
    const last = buffer.subarray(0, bytesRead).lastIndexOf(0x0a)
    // A "line" longer than the read limit is not a log line: skip it rather than stall on it.
    if (last < 0) return bytesRead === MAX_READ ? { text: '', bytes: bytesRead } : null
    return { text: buffer.subarray(0, last + 1).toString('utf8'), bytes: last + 1 }
  } finally {
    await handle.close()
  }
}

export const fileLabel = (path: string) => basename(path)
