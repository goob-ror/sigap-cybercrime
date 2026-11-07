/** SHA-256 of bytes or UTF-8 text, as lowercase hex. Uses Web Crypto (browser and Node 20+). */
export async function sha256Hex(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource)
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

/** Lines of a `sha256sum`-style manifest (`<hash>  <name>`); anything else, such as comments, is skipped. */
export function parseManifest(text: string): { name: string; hash: string }[] {
  return text.split(/\r?\n/).map((l) => /^([0-9a-f]{64})\s+(.+)$/i.exec(l.trim())).filter((m): m is RegExpExecArray => !!m).map((m) => ({ hash: m[1].toLowerCase(), name: m[2] }))
}
