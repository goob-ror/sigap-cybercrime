/**
 * Minimal decoder for Android's binary XML (AXML) — enough to read an APK's AndroidManifest.xml
 * offline: package name, version, declared permissions and the <uses-sdk> levels. No Android
 * tooling, no network. Format reference: AOSP ResourceTypes.h (ResChunk_header, ResStringPool,
 * ResXMLTree_node / attrExt / Res_value).
 */

// Chunk types (little-endian u16).
export const RES_STRING_POOL = 0x0001
export const RES_XML = 0x0003
export const RES_XML_START_ELEMENT = 0x0102
export const RES_XML_RESOURCE_MAP = 0x0180
export const UTF8_FLAG = 0x0100
export const TYPE_STRING = 0x03
const NO_REF = 0xffffffff

export type AxmlManifest = {
  package?: string
  versionName?: string
  minSdk?: number
  targetSdk?: number
  permissions: string[]
  labels: string[]
  /**
   * Permissions a component demands of its callers. An accessibility or device-admin service is declared
   * this way (`<service android:permission=...>`), not with `<uses-permission>`.
   */
  componentPermissions?: string[]
  /** Broadcast and intent actions the app listens for, e.g. incoming SMS. */
  actions?: string[]
}

function readLen8(dv: DataView, p: number): [number, number] {
  const v = dv.getUint8(p)
  return v & 0x80 ? [((v & 0x7f) << 8) | dv.getUint8(p + 1), 2] : [v, 1]
}

function readLen16(dv: DataView, p: number): [number, number] {
  const v = dv.getUint16(p, true)
  return v & 0x8000 ? [((v & 0x7fff) << 16) | dv.getUint16(p + 2, true), 4] : [v, 2]
}

function readUtf8(dv: DataView, p: number): string {
  const [, n1] = readLen8(dv, p) // char count (unused)
  const [byteLen, n2] = readLen8(dv, p + n1)
  const start = p + n1 + n2
  return new TextDecoder('utf-8').decode(new Uint8Array(dv.buffer, dv.byteOffset + start, byteLen))
}

function readUtf16(dv: DataView, p: number): string {
  const [len, n] = readLen16(dv, p)
  const start = p + n
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(dv.getUint16(start + i * 2, true))
  return s
}

function parseStringPool(dv: DataView, base: number): string[] {
  const count = dv.getUint32(base + 8, true)
  const flags = dv.getUint32(base + 16, true)
  const stringsStart = dv.getUint32(base + 20, true)
  const utf8 = (flags & UTF8_FLAG) !== 0
  const out: string[] = []
  for (let i = 0; i < count; i++) {
    const off = dv.getUint32(base + 28 + i * 4, true)
    const p = base + stringsStart + off
    out.push(utf8 ? readUtf8(dv, p) : readUtf16(dv, p))
  }
  return out
}

const strOf = (strings: string[], ref: number): string | undefined => (ref !== NO_REF && ref < strings.length ? strings[ref] : undefined)

function parseStartElement(dv: DataView, base: number, header: number, strings: string[], out: AxmlManifest): void {
  const name = strOf(strings, dv.getUint32(base + header + 4, true))
  if (!name) return
  const attrStart = dv.getUint16(base + header + 8, true)
  const attrSize = dv.getUint16(base + header + 10, true)
  const attrCount = dv.getUint16(base + header + 12, true)
  const attrs: Record<string, string> = {}
  let ap = base + header + attrStart
  for (let i = 0; i < attrCount; i++) {
    const aName = strOf(strings, dv.getUint32(ap + 4, true))
    const rawRef = dv.getUint32(ap + 8, true)
    const dataType = dv.getUint8(ap + 15)
    const data = dv.getUint32(ap + 16, true)
    const value = rawRef !== NO_REF ? strOf(strings, rawRef) : dataType === TYPE_STRING ? strOf(strings, data) : String(data)
    if (aName && value !== undefined) attrs[aName] = value
    ap += attrSize
  }
  if (name === 'manifest') {
    if (attrs.package) out.package = attrs.package
    if (attrs.versionName) out.versionName = attrs.versionName
  } else if (name === 'uses-permission' || name === 'uses-permission-sdk-23') {
    if (attrs.name) out.permissions.push(attrs.name)
  } else if (name === 'uses-sdk') {
    if (attrs.minSdkVersion) out.minSdk = Number(attrs.minSdkVersion)
    if (attrs.targetSdkVersion) out.targetSdk = Number(attrs.targetSdkVersion)
  } else if (name === 'application' && attrs.label) {
    out.labels.push(attrs.label)
  } else if ((name === 'service' || name === 'receiver' || name === 'activity') && attrs.permission) {
    ;(out.componentPermissions ??= []).push(attrs.permission)
  } else if (name === 'action' && attrs.name) {
    ;(out.actions ??= []).push(attrs.name)
  }
}

/** Decode a binary AndroidManifest.xml. Throws if it is not AXML. */
export function decodeAxml(bytes: Uint8Array): AxmlManifest {
  if (bytes.byteLength < 8) throw new Error('Berkas terlalu pendek untuk AXML')
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (dv.getUint16(0, true) !== RES_XML) throw new Error('Bukan AndroidManifest biner (AXML)')
  const total = bytes.byteLength
  const out: AxmlManifest = { permissions: [], labels: [] }
  let strings: string[] = []
  let pos = dv.getUint16(2, true) // headerSize of the outer XML chunk
  while (pos + 8 <= total) {
    const type = dv.getUint16(pos, true)
    const header = dv.getUint16(pos + 2, true)
    const size = dv.getUint32(pos + 4, true)
    if (size < 8 || pos + size > total) break
    if (type === RES_STRING_POOL) strings = parseStringPool(dv, pos)
    else if (type === RES_XML_START_ELEMENT) parseStartElement(dv, pos, header, strings, out)
    pos += size
  }
  return out
}
