/**
 * Reader for Windows `.evtx` files, the format an admin actually copies off a machine, so they can be
 * dropped into SIGAP with no conversion step and no Windows tooling. Output has the same shape as the
 * SIGAP collector's records, so everything after this point treats them alike.
 *
 * Format: a 4 KB file header, then 64 KB chunks. Each chunk holds records whose body is "binary XML":
 * a token stream that usually instantiates a template stored once per chunk, with the event's values
 * passed as substitutions. Names and templates are found by offset from the start of the chunk.
 * Reference: libyal/libevtx "Windows XML Event Log (EVTX) format".
 *
 * Damaged records are counted and skipped: a log with a corrupted chunk still gives what it can.
 */

const FILE_HEADER_SIZE = 4096
const CHUNK_SIZE = 65536
const CHUNK_HEADER_SIZE = 512
const RECORD_HEADER_SIZE = 24
/** Ticks between 1601 and 1970, in milliseconds. */
const FILETIME_UNIX_MS = 11_644_473_600_000n

const Token = { EOF: 0x00, OPEN: 0x01, CLOSE_START: 0x02, CLOSE_EMPTY: 0x03, END: 0x04, VALUE: 0x05, ATTRIBUTE: 0x06, CDATA: 0x07, CHAR_REF: 0x08, ENTITY_REF: 0x09, TEMPLATE: 0x0c, SUBSTITUTION: 0x0d, OPTIONAL_SUBSTITUTION: 0x0e, FRAGMENT: 0x0f } as const
const Type = { NULL: 0x00, STRING: 0x01, ANSI: 0x02, I8: 0x03, U8: 0x04, I16: 0x05, U16: 0x06, I32: 0x07, U32: 0x08, I64: 0x09, U64: 0x0a, F32: 0x0b, F64: 0x0c, BOOL: 0x0d, BINARY: 0x0e, GUID: 0x0f, SIZE: 0x10, FILETIME: 0x11, SYSTEMTIME: 0x12, SID: 0x13, HEX32: 0x14, HEX64: 0x15, BINXML: 0x21, ARRAY: 0x80 } as const

type Node = { name: string; attrs: Record<string, string>; children: (Node | string)[] }
type Substitution = { type: number; offset: number; size: number }
type Chunk = { dv: DataView; base: number; names: Map<number, string>; utf16: TextDecoder }

export type EvtxRecord = {
  EventID: number
  Channel: string
  Computer: string
  TimeCreated: string
  ProviderName: string
  EventRecordID: string
  Level?: number
  EventData: Record<string, string>
  UserData?: Record<string, string>
}

export type EvtxResult = { records: EvtxRecord[]; errors: number }

/** True for an `.evtx` file (magic `ElfFile\0`). */
export function isEvtx(bytes: Uint8Array): boolean {
  return bytes.length >= 8 && String.fromCharCode(...bytes.subarray(0, 8)) === 'ElfFile\0'
}

function readName(c: Chunk, relative: number): string {
  const cached = c.names.get(relative)
  if (cached !== undefined) return cached
  const at = c.base + relative
  const length = c.dv.getUint16(at + 6, true)
  const name = c.utf16.decode(new Uint8Array(c.dv.buffer, c.dv.byteOffset + at + 8, length * 2))
  c.names.set(relative, name)
  return name
}

/** A name stored in place, rather than referred to: next offset, hash, length, characters, NUL. */
const nameSize = (c: Chunk, relative: number) => 8 + (c.dv.getUint16(c.base + relative + 6, true) + 1) * 2

const hex = (n: bigint | number) => `0x${n.toString(16)}`

/** With the 100 ns precision Windows itself prints, so values read the same as in Event Viewer. */
function filetimeIso(value: bigint): string {
  const seconds = new Date(Number(value / 10_000_000n) * 1000 - Number(FILETIME_UNIX_MS)).toISOString().slice(0, 19)
  return `${seconds}.${String(value % 10_000_000n).padStart(7, '0')}Z`
}

/** Bytes per item of a fixed-size array value; strings are NUL-separated instead. */
const ITEM_SIZE: Partial<Record<number, number>> = { [Type.I8]: 1, [Type.U8]: 1, [Type.I16]: 2, [Type.U16]: 2, [Type.I32]: 4, [Type.U32]: 4, [Type.I64]: 8, [Type.U64]: 8, [Type.F32]: 4, [Type.F64]: 8, [Type.BOOL]: 4, [Type.GUID]: 16, [Type.FILETIME]: 8, [Type.SYSTEMTIME]: 16, [Type.HEX32]: 4, [Type.HEX64]: 8 }

function arrayItems(c: Chunk, sub: Substitution): string[] {
  const type = sub.type & ~Type.ARRAY
  if (type === Type.STRING) {
    const items = c.utf16.decode(new Uint8Array(c.dv.buffer, c.dv.byteOffset + sub.offset, sub.size)).split('\0')
    // Each string ends in a NUL, so the split leaves one empty piece at the end. Empty items in between are real.
    if (items.at(-1) === '') items.pop()
    return items
  }
  const size = ITEM_SIZE[type]
  if (!size) return [valueText(c, type, sub.offset, sub.size)]
  const items: string[] = []
  for (let at = 0; at + size <= sub.size; at += size) items.push(valueText(c, type, sub.offset + at, size))
  return items
}

function readSid(c: Chunk, at: number): string {
  const count = c.dv.getUint8(at + 1)
  let authority = 0
  for (let i = 0; i < 6; i++) authority = authority * 256 + c.dv.getUint8(at + 2 + i)
  const parts = [`S-${c.dv.getUint8(at)}-${authority}`]
  for (let i = 0; i < count; i++) parts.push(String(c.dv.getUint32(at + 8 + i * 4, true)))
  return parts.join('-')
}

function readGuid(c: Chunk, at: number): string {
  const b = (i: number) => c.dv.getUint8(at + i).toString(16).padStart(2, '0')
  return `{${c.dv.getUint32(at, true).toString(16).padStart(8, '0')}-${c.dv.getUint16(at + 4, true).toString(16).padStart(4, '0')}-${c.dv.getUint16(at + 6, true).toString(16).padStart(4, '0')}-${b(8)}${b(9)}-${b(10)}${b(11)}${b(12)}${b(13)}${b(14)}${b(15)}}`
}

/** One value as text. `size` is the byte length; strings are not NUL-terminated by contract, so they are trimmed. */
function valueText(c: Chunk, type: number, at: number, size: number): string {
  const { dv } = c
  const raw = () => new Uint8Array(dv.buffer, dv.byteOffset + at, size)
  switch (type) {
    case Type.NULL: return ''
    // Up to the first NUL, as Windows renders them: what follows is leftover memory, not part of the value.
    case Type.STRING: return c.utf16.decode(raw()).replace(/\0.*$/s, '')
    case Type.ANSI: return new TextDecoder('latin1').decode(raw()).replace(/\0.*$/s, '')
    case Type.I8: return String(dv.getInt8(at))
    case Type.U8: return String(dv.getUint8(at))
    case Type.I16: return String(dv.getInt16(at, true))
    case Type.U16: return String(dv.getUint16(at, true))
    case Type.I32: return String(dv.getInt32(at, true))
    case Type.U32: return String(dv.getUint32(at, true))
    case Type.I64: return String(dv.getBigInt64(at, true))
    case Type.U64: return String(dv.getBigUint64(at, true))
    case Type.F32: return String(dv.getFloat32(at, true))
    case Type.F64: return String(dv.getFloat64(at, true))
    case Type.BOOL: return dv.getUint32(at, true) ? 'true' : 'false'
    case Type.BINARY: return [...raw()].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()
    case Type.GUID: return readGuid(c, at)
    case Type.SIZE: return size === 8 ? hex(dv.getBigUint64(at, true)) : hex(dv.getUint32(at, true))
    case Type.FILETIME: return filetimeIso(dv.getBigUint64(at, true))
    case Type.SYSTEMTIME: {
      const u = (i: number) => dv.getUint16(at + i * 2, true)
      return new Date(Date.UTC(u(0), u(1) - 1, u(3), u(4), u(5), u(6), u(7))).toISOString()
    }
    case Type.SID: return readSid(c, at)
    case Type.HEX32: return hex(dv.getUint32(at, true))
    case Type.HEX64: return hex(dv.getBigUint64(at, true))
    default: return [...raw()].map((b) => b.toString(16).padStart(2, '0')).join('')
  }
}

/** A substitution in element content: nested binary XML becomes nodes, anything else text. */
function emitSubstitution(c: Chunk, sub: Substitution | undefined, into: (Node | string)[]) {
  if (!sub || sub.size === 0 || sub.type === Type.NULL) return
  if (sub.type === Type.BINXML) parseContent(c, sub.offset, [], into)
  else if (sub.type & Type.ARRAY) into.push(arrayItems(c, sub).join(','))
  else into.push(valueText(c, sub.type, sub.offset, sub.size))
}

/** Reads the text-like tokens that follow an attribute name. */
function parseAttributeValue(c: Chunk, start: number, subs: Substitution[]): [string, number] {
  const { dv } = c
  let pos = start
  let text = ''
  for (;;) {
    const type = dv.getUint8(pos) & 0x0f
    if (type === Token.VALUE) {
      const length = dv.getUint16(pos + 2, true)
      text += c.utf16.decode(new Uint8Array(dv.buffer, dv.byteOffset + pos + 4, length * 2))
      pos += 4 + length * 2
    } else if (type === Token.SUBSTITUTION || type === Token.OPTIONAL_SUBSTITUTION) {
      const sub = subs[dv.getUint16(pos + 1, true)]
      if (sub && sub.size && sub.type !== Type.NULL && sub.type !== Type.BINXML) text += sub.type & Type.ARRAY ? arrayItems(c, sub).join(',') : valueText(c, sub.type, sub.offset, sub.size)
      pos += 4
    } else if (type === Token.CHAR_REF) {
      text += String.fromCharCode(dv.getUint16(pos + 1, true))
      pos += 3
    } else if (type === Token.ENTITY_REF) {
      text += `&${readName(c, dv.getUint32(pos + 1, true))};`
      pos += 5
    } else return [text, pos]
  }
}

function parseElement(c: Chunk, start: number, subs: Substitution[], into: (Node | string)[]): number {
  const { dv, base } = c
  const hasAttributes = (dv.getUint8(start) & 0x40) !== 0
  const nameOffset = dv.getUint32(start + 7, true)
  // Token, dependency id, data size, name offset; then attribute-list size and an inline name, when present.
  let pos = start + 11 + (hasAttributes ? 4 : 0)
  if (base + nameOffset > start) pos += nameSize(c, nameOffset)
  const node: Node = { name: readName(c, nameOffset), attrs: {}, children: [] }
  into.push(node)

  while ((dv.getUint8(pos) & 0x0f) === Token.ATTRIBUTE) {
    const attrName = dv.getUint32(pos + 1, true)
    const tokenAt = pos
    pos += 5
    if (base + attrName > tokenAt) pos += nameSize(c, attrName)
    const [value, next] = parseAttributeValue(c, pos, subs)
    node.attrs[readName(c, attrName)] = value
    pos = next
  }

  const close = dv.getUint8(pos) & 0x0f
  if (close === Token.CLOSE_EMPTY) return pos + 1
  if (close !== Token.CLOSE_START) throw new Error(`Token penutup tidak dikenal: ${close}`)

  // An array substitution stands for the element itself: Windows writes one element per item.
  // Classic events keep their whole EventData this way, as `<Data>%1</Data>` repeated.
  const first = dv.getUint8(pos + 1) & 0x0f
  const arraySub = first === Token.SUBSTITUTION || first === Token.OPTIONAL_SUBSTITUTION ? subs[dv.getUint16(pos + 2, true)] : undefined
  if (arraySub && arraySub.type & Type.ARRAY && (dv.getUint8(pos + 5) & 0x0f) === Token.END) {
    into.pop()
    for (const item of arrayItems(c, arraySub)) into.push({ name: node.name, attrs: node.attrs, children: item ? [item] : [] })
    return pos + 6
  }

  pos = parseContent(c, pos + 1, subs, node.children)
  if ((dv.getUint8(pos) & 0x0f) !== Token.END) throw new Error('Elemen tidak ditutup')
  return pos + 1
}

function parseTemplate(c: Chunk, start: number, into: (Node | string)[]): number {
  const { dv, base } = c
  // Token, reserved byte, template id, then where the definition lives (often right here).
  const definition = base + dv.getUint32(start + 6, true)
  let pos = start + 10
  // Definition: next offset (4), GUID (16), body size (4), body.
  const bodySize = dv.getUint32(definition + 20, true)
  if (definition === pos) pos += 24 + bodySize
  const count = dv.getUint32(pos, true)
  pos += 4
  const subs: Substitution[] = []
  for (let i = 0; i < count; i++, pos += 4) subs.push({ size: dv.getUint16(pos, true), type: dv.getUint8(pos + 2), offset: 0 })
  for (const sub of subs) {
    sub.offset = pos
    pos += sub.size
  }
  parseContent(c, definition + 24, subs, into)
  return pos
}

/** Reads tokens into `into` until the end of the stream or of the enclosing element. */
function parseContent(c: Chunk, start: number, subs: Substitution[], into: (Node | string)[]): number {
  const { dv } = c
  let pos = start
  for (;;) {
    const type = dv.getUint8(pos) & 0x0f
    switch (type) {
      case Token.EOF: return pos + 1
      case Token.END:
      case Token.CLOSE_EMPTY: return pos
      case Token.FRAGMENT: pos += 4; break
      case Token.TEMPLATE: pos = parseTemplate(c, pos, into); break
      case Token.OPEN: pos = parseElement(c, pos, subs, into); break
      case Token.VALUE: {
        const length = dv.getUint16(pos + 2, true)
        into.push(c.utf16.decode(new Uint8Array(dv.buffer, dv.byteOffset + pos + 4, length * 2)))
        pos += 4 + length * 2
        break
      }
      case Token.CDATA: {
        const length = dv.getUint16(pos + 1, true)
        into.push(c.utf16.decode(new Uint8Array(dv.buffer, dv.byteOffset + pos + 3, length * 2)))
        pos += 3 + length * 2
        break
      }
      case Token.SUBSTITUTION:
      case Token.OPTIONAL_SUBSTITUTION:
        emitSubstitution(c, subs[dv.getUint16(pos + 1, true)], into)
        pos += 4
        break
      case Token.CHAR_REF:
        into.push(String.fromCharCode(dv.getUint16(pos + 1, true)))
        pos += 3
        break
      case Token.ENTITY_REF:
        into.push(`&${readName(c, dv.getUint32(pos + 1, true))};`)
        pos += 5
        break
      default:
        throw new Error(`Token biner tidak dikenal: ${type}`)
    }
  }
}

const isNode = (n: Node | string): n is Node => typeof n !== 'string'
const textOf = (n: Node | undefined): string => (n ? n.children.map((x) => (isNode(x) ? textOf(x) : x)).join('') : '')
const childOf = (n: Node | undefined, name: string) => n?.children.find((x): x is Node => isNode(x) && x.name === name)

/** Named fields of `<EventData>` or a `<UserData>` wrapper, as the collector reads them. */
function namedData(n: Node | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  let i = 0
  for (const child of n?.children ?? []) {
    if (!isNode(child)) continue
    i++
    out[child.attrs.Name || (child.name === 'Data' ? `param${i}` : child.name)] = textOf(child)
  }
  return out
}

function toRecord(event: Node, fallback: bigint, recordId: bigint): EvtxRecord | null {
  const system = childOf(event, 'System')
  if (!system) return null
  const eventId = Number(textOf(childOf(system, 'EventID')))
  if (!Number.isFinite(eventId)) return null
  const level = Number(textOf(childOf(system, 'Level')))
  const userData = childOf(event, 'UserData')?.children.find(isNode)
  return {
    EventID: eventId,
    Channel: textOf(childOf(system, 'Channel')),
    Computer: textOf(childOf(system, 'Computer')),
    TimeCreated: childOf(system, 'TimeCreated')?.attrs.SystemTime || filetimeIso(fallback),
    ProviderName: childOf(system, 'Provider')?.attrs.Name ?? '',
    EventRecordID: textOf(childOf(system, 'EventRecordID')) || String(recordId),
    ...(Number.isFinite(level) ? { Level: level } : {}),
    EventData: namedData(childOf(event, 'EventData')),
    ...(userData ? { UserData: namedData(userData) } : {}),
  }
}

function hasMagic(dv: DataView, at: number, magic: string): boolean {
  for (let i = 0; i < magic.length; i++) if (dv.getUint8(at + i) !== magic.charCodeAt(i)) return false
  return true
}

/** Every readable record of an `.evtx` file, in file order. */
export function parseEvtx(bytes: Uint8Array): EvtxResult {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const utf16 = new TextDecoder('utf-16le')
  const records: EvtxRecord[] = []
  let errors = 0
  for (let base = FILE_HEADER_SIZE; base + CHUNK_SIZE <= bytes.byteLength; base += CHUNK_SIZE) {
    if (!hasMagic(dv, base, 'ElfChnk\0')) continue
    const chunk: Chunk = { dv, base, names: new Map(), utf16 }
    const free = Math.min(dv.getUint32(base + 48, true), CHUNK_SIZE)
    let at = base + CHUNK_HEADER_SIZE
    while (at - base + RECORD_HEADER_SIZE < free && dv.getUint32(at, true) === 0x00002a2a) {
      const size = dv.getUint32(at + 4, true)
      if (size < RECORD_HEADER_SIZE || at - base + size > CHUNK_SIZE) {
        errors++
        break
      }
      try {
        const nodes: (Node | string)[] = []
        parseContent(chunk, at + RECORD_HEADER_SIZE, [], nodes)
        const event = nodes.find(isNode)
        const record = event && toRecord(event, dv.getBigUint64(at + 16, true), dv.getBigUint64(at + 8, true))
        if (record) records.push(record)
        else errors++
      } catch {
        errors++
      }
      at += size
    }
  }
  return { records, errors }
}
