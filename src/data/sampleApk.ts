import { RES_STRING_POOL, RES_XML, TYPE_STRING, UTF8_FLAG } from '@/core/triage/axml'

/**
 * Builds a benign sample AndroidManifest.xml in Android's binary format (AXML), plus the metadata
 * for a fictional lookalike app, so the APK triage demo has something real to parse. There is NO
 * code and NO payload — only a manifest with scary-looking permissions and a text asset. Fully
 * synthetic and offline. Used to produce `src/features/triage` sample and to round-trip-test the
 * decoder (`decodeAxml`).
 */

const NO_REF = 0xffffffff
const ANDROID_URI = 'http://schemas.android.com/apk/res/android'

/** A fictional "payroll info" app with a banking-trojan-style permission set — but harmless. */
export const SAMPLE_APK = {
  package: 'id.satuan.tukininfo.update',
  label: 'Info Tukin',
  versionName: '2.4',
  permissions: [
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.READ_CONTACTS',
    'android.permission.READ_PHONE_STATE',
    'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.INTERNET',
    'android.permission.ACCESS_NETWORK_STATE',
  ],
}

/** Benign strings an analyst would find inside the app (ties to the demo C2 domain). Fictional. */
export const SAMPLE_APK_STRINGS = [
  'Info Tukin - pembaruan data',
  'http://cdn-tukin.example/kumpul',
  'POST /kumpul HTTP/1.1',
  'nrp;nama;saldo;otp',
]

class W {
  private b: number[] = []
  u8(v: number) { this.b.push(v & 0xff) }
  u16(v: number) { this.u8(v); this.u8(v >>> 8) }
  u32(v: number) { this.u16(v & 0xffff); this.u16(v >>> 16) }
  bytes(a: ArrayLike<number>) { for (let i = 0; i < a.length; i++) this.b.push(a[i] & 0xff) }
  get length() { return this.b.length }
  out() { return Uint8Array.from(this.b) }
}

function writeLen8(w: W, v: number) {
  if (v >= 128) { w.u8(0x80 | (v >> 8)); w.u8(v & 0xff) } else w.u8(v)
}

function buildStringPool(strings: string[]): Uint8Array {
  const enc = new TextEncoder()
  const datas = strings.map((s) => {
    const bytes = enc.encode(s)
    const w = new W()
    writeLen8(w, s.length) // UTF-16 unit count (ASCII here)
    writeLen8(w, bytes.length)
    w.bytes(bytes)
    w.u8(0) // null terminator
    return w.out()
  })
  const offsets: number[] = []
  let off = 0
  for (const d of datas) { offsets.push(off); off += d.length }
  const pad = (4 - (off % 4)) % 4
  const stringsStart = 28 + strings.length * 4
  const w = new W()
  w.u16(RES_STRING_POOL); w.u16(28); w.u32(stringsStart + off + pad)
  w.u32(strings.length); w.u32(0); w.u32(UTF8_FLAG); w.u32(stringsStart); w.u32(0)
  for (const o of offsets) w.u32(o)
  for (const d of datas) w.bytes(d)
  for (let i = 0; i < pad; i++) w.u8(0)
  return w.out()
}

function xmlNode(type: number, body: Uint8Array): Uint8Array {
  const w = new W()
  w.u16(type); w.u16(16); w.u32(16 + body.length)
  w.u32(0); w.u32(NO_REF) // lineNumber, comment
  w.bytes(body)
  return w.out()
}

type Attr = { ns: number; name: number; value: number }

function startElement(ns: number, name: number, attrs: Attr[]): Uint8Array {
  const b = new W()
  b.u32(ns); b.u32(name)
  b.u16(20); b.u16(20); b.u16(attrs.length); b.u16(0); b.u16(0); b.u16(0)
  for (const a of attrs) {
    b.u32(a.ns); b.u32(a.name); b.u32(a.value)
    b.u16(8); b.u8(0); b.u8(TYPE_STRING); b.u32(a.value)
  }
  return xmlNode(0x0102, b.out())
}

function endElement(ns: number, name: number): Uint8Array {
  const b = new W()
  b.u32(ns); b.u32(name)
  return xmlNode(0x0103, b.out())
}

function namespaceNode(type: number, prefix: number, uri: number): Uint8Array {
  const b = new W()
  b.u32(prefix); b.u32(uri)
  return xmlNode(type, b.out())
}

/** Encode a benign AndroidManifest.xml to binary AXML. */
export function encodeSampleManifest(spec = SAMPLE_APK): Uint8Array {
  const pool: string[] = []
  const idx = (s: string) => {
    const i = pool.indexOf(s)
    return i >= 0 ? i : pool.push(s) - 1
  }
  // Intern in a stable order.
  const android = idx('android')
  const uri = idx(ANDROID_URI)
  const aPackage = idx('package')
  const aVersion = idx('versionName')
  const aName = idx('name')
  const aLabel = idx('label')
  const eManifest = idx('manifest')
  const ePerm = idx('uses-permission')
  const eApp = idx('application')
  const vPackage = idx(spec.package)
  const vVersion = idx(spec.versionName)
  const vLabel = idx(spec.label)
  const permIdx = spec.permissions.map((p) => idx(p))

  const nodes: Uint8Array[] = []
  nodes.push(namespaceNode(0x0100, android, uri))
  nodes.push(startElement(NO_REF, eManifest, [{ ns: NO_REF, name: aPackage, value: vPackage }, { ns: uri, name: aVersion, value: vVersion }]))
  for (let i = 0; i < permIdx.length; i++) {
    nodes.push(startElement(NO_REF, ePerm, [{ ns: uri, name: aName, value: permIdx[i] }]))
    nodes.push(endElement(NO_REF, ePerm))
  }
  nodes.push(startElement(NO_REF, eApp, [{ ns: uri, name: aLabel, value: vLabel }]))
  nodes.push(endElement(NO_REF, eApp))
  nodes.push(endElement(NO_REF, eManifest))
  nodes.push(namespaceNode(0x0101, android, uri))

  const pool_ = buildStringPool(pool)
  const bodyLen = pool_.length + nodes.reduce((n, c) => n + c.length, 0)
  const head = new W()
  head.u16(RES_XML); head.u16(8); head.u32(8 + bodyLen)
  const out = new W()
  out.bytes(head.out()); out.bytes(pool_)
  for (const n of nodes) out.bytes(n)
  return out.out()
}
