import { describe, expect, it } from 'vitest'
import { runDetections } from '@/core/detect/engine'
import type { NormalizedEvent, UnitProfile } from '@/core/model'
import { isValidCidr } from '@/core/net'
import { cleanOperatorName, parseUnitProfile } from '@/core/profile'
import { loadRulePack } from '@/data/rules'
import { DEFAULT_UNIT_PROFILE } from '@/data/unitProfile'

const REAL: UnitProfile = {
  name: 'Satuan Uji',
  otSubnets: ['192.168.50.0/24'],
  engineeringHosts: ['192.168.50.10'],
  uploadThresholdBytes: 1024,
  assets: [{ name: 'PLC-1', ip: '192.168.50.22', kind: 'ot', role: 'PLC' }],
  ot: { runCoils: [0] },
}

function event(id: string, logsource: NormalizedEvent['logsource'], fields: NormalizedEvent['fields']): NormalizedEvent {
  return { id, ts: 0, dataset: 'test', sourceKind: 'network', logsource, message: '', importId: 'i', fields }
}

const modbusConn = (ip: string) => event(`conn-${ip}`, { product: 'zeek', service: 'conn' }, { 'id.orig_h': ip, 'id.resp_p': 502 })
const firewall502 = (ip: string) => event(`fw-${ip}`, { category: 'firewall' }, { srcip: ip, dstport: 502, action: 'accept' })
const modbusWrite = (ip: string) => event(`write-${ip}`, { product: 'zeek' }, { 'id.orig_h': ip, func: 'WRITE_SINGLE_REGISTER' })
const coilStop = (ip: string) => event(`stop-${ip}`, { product: 'zeek' }, { 'id.orig_h': ip, func: 'WRITE_SINGLE_COIL', address: 0, values: 'F' })

const fired = (events: NormalizedEvent[], profile?: UnitProfile) => new Set(runDetections(events, loadRulePack(profile)).map((d) => d.ruleId))

describe('rules follow the unit profile', () => {
  it('loads every rule with a custom profile', () => {
    const custom = loadRulePack(REAL)
    const standard = loadRulePack()
    expect(custom.skipped).toEqual([])
    expect(custom.sigma.length).toBe(standard.sigma.length)
  })

  it('treats the OT segment and engineering host from the profile as legitimate', () => {
    const inside = [modbusConn('192.168.50.10'), firewall502('192.168.50.10'), modbusWrite('192.168.50.10'), coilStop('192.168.50.10')]
    expect(fired(inside, REAL)).toEqual(new Set())
    expect(fired(inside, DEFAULT_UNIT_PROFILE)).toEqual(new Set(['sigap-net-it-to-modbus', 'sigap-fw-it-to-modbus', 'sigap-ot-modbus-write-unauthorized', 'sigap-ot-genset-stop-coil']))
  })

  it('no longer trusts the demo unit addresses under a real profile', () => {
    const demo = [modbusConn('10.40.7.10'), firewall502('10.40.7.10'), modbusWrite('10.40.7.10'), coilStop('10.40.7.10')]
    expect(fired(demo, DEFAULT_UNIT_PROFILE)).toEqual(new Set())
    expect(fired(demo, REAL).size).toBe(4)
  })

  it('reads the generator points from the profile, and stays silent without them', () => {
    const setpoint = event('sp', { product: 'zeek' }, { 'id.orig_h': '10.1.1.1', func: 'WRITE_SINGLE_REGISTER', address: 40, values: 300 })
    const withMap = { ...REAL, ot: { runCoils: [7], setpointRegisters: [40], setpointMin: 180, setpointMax: 260 } }
    const coil = (address: number) => event(`c${address}`, { product: 'zeek' }, { 'id.orig_h': '10.1.1.1', func: 'WRITE_SINGLE_COIL', address, values: 'F' })
    expect(fired([setpoint], withMap)).toContain('sigap-ot-setpoint-out-of-range')
    expect(fired([coil(7)], withMap)).toContain('sigap-ot-genset-stop-coil')
    expect(fired([coil(0)], withMap)).not.toContain('sigap-ot-genset-stop-coil')
    const withoutMap = { ...REAL, ot: undefined }
    expect(fired([setpoint, coil(0)], withoutMap)).toEqual(new Set(['sigap-ot-modbus-write-unauthorized']))
  })

  it('names OT hosts from the profile instead of assuming a naming scheme', () => {
    const rdp = (computer: string) => event(computer, { product: 'windows', service: 'security' }, { EventID: 4624, LogonType: 10, Computer: computer })
    const unit = { ...REAL, assets: [{ name: 'SCADA-MABES', ip: '10.9.9.9', kind: 'ot' as const, role: '' }, { name: 'WS-1', ip: '10.9.9.8', kind: 'it' as const, role: '' }] }
    expect(fired([rdp('SCADA-MABES.satuan.local')], unit)).toContain('sigap-win-rdp-to-ot-host')
    expect(fired([rdp('HMI-LAIN')], unit)).not.toContain('sigap-win-rdp-to-ot-host')
    expect(fired([rdp('WS-1')], unit)).not.toContain('sigap-win-rdp-to-ot-host')
  })

  it('flags everything when the allowlists are empty', () => {
    const none = { ...REAL, otSubnets: [], engineeringHosts: [] }
    expect(fired([modbusConn('192.168.50.10'), modbusWrite('192.168.50.10')], none)).toEqual(new Set(['sigap-net-it-to-modbus', 'sigap-ot-modbus-write-unauthorized']))
  })
})

describe('parseUnitProfile', () => {
  it('accepts a valid profile and trims it', () => {
    const result = parseUnitProfile({ ...REAL, name: '  Satuan Uji ', otSubnets: [' 192.168.50.0/24 '] })
    expect(result).toEqual({ ok: true, profile: REAL })
  })

  it('accepts the built-in demo profile', () => {
    expect(parseUnitProfile(DEFAULT_UNIT_PROFILE)).toEqual({ ok: true, profile: DEFAULT_UNIT_PROFILE })
  })

  it('reports every problem with a reason', () => {
    const result = parseUnitProfile({ name: ' ', otSubnets: ['192.168.50.0'], engineeringHosts: ['server-1'], uploadThresholdBytes: NaN, assets: [{ name: '', ip: '999.1.1.1', kind: 'x' }] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.errors).toHaveLength(7)
  })

  it('checks the optional fields', () => {
    const bad = parseUnitProfile({ ...REAL, ownDomains: ['bukan domain'], ot: { runCoils: [-1], setpointMin: 240, setpointMax: 200 }, reportMarking: 'x'.repeat(81) })
    expect(bad.ok).toBe(false)
    if (!bad.ok) expect(bad.errors).toHaveLength(4)
    const good = parseUnitProfile({ ...REAL, ownDomains: [' Satuan.MIL.id '], ot: { runCoils: [1], setpointRegisters: [], setpointMin: 200 }, reportMarking: ' TERBATAS ' })
    expect(good).toEqual({ ok: true, profile: { ...REAL, ownDomains: ['satuan.mil.id'], ot: { runCoils: [1], setpointMin: 200 }, reportMarking: 'TERBATAS' } })
  })

  it('rejects duplicate asset addresses', () => {
    const asset = REAL.assets[0]
    const result = parseUnitProfile({ ...REAL, assets: [asset, { ...asset, name: 'PLC-2' }] })
    expect(result.ok).toBe(false)
  })

  it.each([null, [], 'teks', 5])('rejects %j', (input) => {
    expect(parseUnitProfile(input).ok).toBe(false)
  })

  it('rejects a CIDR that would match every address', () => {
    expect(isValidCidr('0.0.0.0/0')).toBe(false)
    expect(isValidCidr('10.0.0.0/8')).toBe(true)
    expect(isValidCidr('10.0.0.0/33')).toBe(false)
  })
})

describe('OT process fields', () => {
  const base = { name: 'Satuan', otSubnets: [], engineeringHosts: [], uploadThresholdBytes: 1, assets: [] }

  it('keeps the running-state register and the registers to follow', () => {
    const parsed = parseUnitProfile({ ...base, ot: { runStatusRegister: 0, measuredRegisters: [{ address: 1, label: ' Tegangan ', unit: 'V' }, { address: 3, label: 'Beban' }] } })
    expect(parsed.ok && parsed.profile.ot).toEqual({ runStatusRegister: 0, measuredRegisters: [{ address: 1, label: 'Tegangan', unit: 'V' }, { address: 3, label: 'Beban' }] })
  })

  it.each([
    ['a text register', { runStatusRegister: 'nol' }],
    ['a register out of range', { runStatusRegister: 70000 }],
    ['a list that is not a list', { measuredRegisters: 'semua' }],
    ['an entry with no label', { measuredRegisters: [{ address: 1, label: ' ' }] }],
    ['an entry with a bad address', { measuredRegisters: [{ address: Number.NaN, label: 'x' }] }],
  ])('rejects %s', (_, ot) => {
    expect(parseUnitProfile({ ...base, ot }).ok).toBe(false)
  })
})

describe('cleanOperatorName', () => {
  it('normalizes whitespace', () => {
    expect(cleanOperatorName('  Serda   Andi ')).toBe('Serda Andi')
  })

  it('rejects names too short or too long to identify someone', () => {
    expect(cleanOperatorName(' a ')).toBeNull()
    expect(cleanOperatorName('x'.repeat(61))).toBeNull()
  })
})
