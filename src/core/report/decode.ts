const ENCODED_RE = /\s[-/–—]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+["']?([A-Za-z0-9+/=]{4,})/i

/**
 * The command hidden in `powershell -EncodedCommand <base64>`: Base64 of UTF-16LE text. The response
 * step for this finding used to tell a non-analyst to decode it by hand. Null when it is not there or
 * does not decode to readable text.
 */
export function decodeEncodedCommand(commandLine: string | undefined): string | null {
  const encoded = commandLine ? ENCODED_RE.exec(commandLine)?.[1] : undefined
  if (!encoded) return null
  try {
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))
    const text = new TextDecoder('utf-16le', { fatal: true }).decode(bytes)
    // Any bytes decode to something, usually CJK. PowerShell source is overwhelmingly ASCII.
    const readable = text.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '').length
    return text && readable / text.length >= 0.9 ? text : null
  } catch {
    return null
  }
}
