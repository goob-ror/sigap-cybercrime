import type { UnitAsset, UnitProfile } from '@/core/model'
import { ipv4ToInt, isValidCidr } from '@/core/net'

export type ProfileResult = { ok: true; profile: UnitProfile } | { ok: false; errors: string[] }

const isStringList = (value: unknown): value is string[] => Array.isArray(value) && value.every((v) => typeof v === 'string')

/**
 * Checks untrusted input (the settings form, an imported JSON file, Pos Jaga's --profil) and returns
 * a clean profile. A wrong address here silently changes what counts as an attack, so anything
 * invalid is rejected with a reason rather than ignored.
 */
export function parseUnitProfile(raw: unknown): ProfileResult {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, errors: ['Profil harus berupa objek JSON.'] }
  const input = raw as Record<string, unknown>
  const errors: string[] = []

  const name = typeof input.name === 'string' ? input.name.trim() : ''
  if (!name) errors.push('Nama satuan wajib diisi.')

  let otSubnets: string[] = []
  if (!isStringList(input.otSubnets)) errors.push('Segmen OT harus berupa daftar CIDR.')
  else {
    otSubnets = input.otSubnets.map((s) => s.trim())
    for (const net of otSubnets) if (!isValidCidr(net)) errors.push(`Segmen OT tidak valid: "${net}" (contoh: 192.168.50.0/24).`)
  }

  let engineeringHosts: string[] = []
  if (!isStringList(input.engineeringHosts)) errors.push('Host engineering harus berupa daftar alamat IPv4.')
  else {
    engineeringHosts = input.engineeringHosts.map((s) => s.trim())
    for (const ip of engineeringHosts) if (ipv4ToInt(ip) === null) errors.push(`Host engineering tidak valid: "${ip}" (harus alamat IPv4).`)
  }

  const uploadThresholdBytes = input.uploadThresholdBytes
  if (typeof uploadThresholdBytes !== 'number' || !Number.isFinite(uploadThresholdBytes) || uploadThresholdBytes <= 0) errors.push('Ambang unggahan harus berupa angka lebih dari 0.')

  const assets: UnitAsset[] = []
  if (!Array.isArray(input.assets)) errors.push('Daftar aset harus berupa daftar.')
  else {
    const seen = new Set<string>()
    input.assets.forEach((item: unknown, i) => {
      const label = `Aset #${i + 1}`
      const a = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>
      const assetName = typeof a.name === 'string' ? a.name.trim() : ''
      const ip = typeof a.ip === 'string' ? a.ip.trim() : ''
      if (!assetName) errors.push(`${label}: nama wajib diisi.`)
      if (ipv4ToInt(ip) === null) errors.push(`${label}: alamat IP tidak valid ("${ip}").`)
      else if (seen.has(ip)) errors.push(`${label}: alamat ${ip} sudah dipakai aset lain.`)
      seen.add(ip)
      if (a.kind !== 'it' && a.kind !== 'ot') errors.push(`${label}: jenis harus "it" atau "ot".`)
      assets.push({ name: assetName, ip, kind: a.kind as UnitAsset['kind'], role: typeof a.role === 'string' ? a.role.trim() : '' })
    })
  }

  let ownDomains: string[] | undefined
  if (input.ownDomains !== undefined) {
    if (!isStringList(input.ownDomains)) errors.push('Domain milik satuan harus berupa daftar nama domain.')
    else {
      ownDomains = input.ownDomains.map((s) => s.trim().toLowerCase()).filter(Boolean)
      for (const d of ownDomains) if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) errors.push(`Domain tidak valid: "${d}" (contoh: satuan.mil.id).`)
    }
  }

  const ot: NonNullable<UnitProfile['ot']> = {}
  if (input.ot !== undefined) {
    const raw = (input.ot && typeof input.ot === 'object' ? input.ot : {}) as Record<string, unknown>
    const points = (key: 'runCoils' | 'setpointRegisters', label: string) => {
      if (raw[key] === undefined) return
      const list = raw[key]
      if (!Array.isArray(list) || list.some((v) => !Number.isInteger(v) || v < 0 || v > 65535)) errors.push(`${label} harus berupa nomor 0 sampai 65535.`)
      else if (list.length) ot[key] = list as number[]
    }
    points('runCoils', 'Coil RUN')
    points('setpointRegisters', 'Register setpoint')
    for (const [key, label] of [['setpointMin', 'Batas bawah setpoint'], ['setpointMax', 'Batas atas setpoint']] as const) {
      if (raw[key] === undefined) continue
      if (typeof raw[key] !== 'number' || !Number.isFinite(raw[key])) errors.push(`${label} harus berupa angka.`)
      else ot[key] = raw[key]
    }
    if (ot.setpointMin !== undefined && ot.setpointMax !== undefined && ot.setpointMin >= ot.setpointMax) errors.push('Batas bawah setpoint harus lebih kecil dari batas atas.')
    if (raw.runStatusRegister !== undefined) {
      if (!Number.isInteger(raw.runStatusRegister) || (raw.runStatusRegister as number) < 0 || (raw.runStatusRegister as number) > 65535) errors.push('Register status RUN harus berupa nomor 0 sampai 65535.')
      else ot.runStatusRegister = raw.runStatusRegister as number
    }
    if (raw.measuredRegisters !== undefined) {
      if (!Array.isArray(raw.measuredRegisters)) errors.push('Register yang dipantau harus berupa daftar.')
      else {
        const measured: NonNullable<typeof ot.measuredRegisters> = []
        for (const item of raw.measuredRegisters as unknown[]) {
          const m = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>
          const label = typeof m.label === 'string' ? m.label.trim() : ''
          if (!Number.isInteger(m.address) || (m.address as number) < 0 || (m.address as number) > 65535 || !label) {
            errors.push('Register yang dipantau ditulis seperti: 1=Tegangan keluaran (V), 3=Beban (kW).')
            break
          }
          const unit = typeof m.unit === 'string' && m.unit.trim() ? m.unit.trim() : undefined
          measured.push({ address: m.address as number, label: label.slice(0, 40), ...(unit ? { unit: unit.slice(0, 10) } : {}) })
        }
        if (measured.length) ot.measuredRegisters = measured
      }
    }
  }

  const reportMarking = typeof input.reportMarking === 'string' ? input.reportMarking.trim() : ''
  if (reportMarking.length > 80) errors.push('Penandaan laporan paling panjang 80 karakter.')

  if (errors.length) return { ok: false, errors }
  return {
    ok: true,
    profile: {
      name,
      otSubnets,
      engineeringHosts,
      uploadThresholdBytes: uploadThresholdBytes as number,
      assets,
      ...(ownDomains?.length ? { ownDomains } : {}),
      ...(Object.keys(ot).length ? { ot } : {}),
      ...(reportMarking ? { reportMarking } : {}),
    },
  }
}

/** Trimmed operator name, or null when it is too short or too long to identify someone. */
export function cleanOperatorName(raw: string): string | null {
  const name = raw.trim().replace(/\s+/g, ' ')
  return name.length >= 2 && name.length <= 60 ? name : null
}
