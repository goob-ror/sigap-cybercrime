import type { Level } from '@/core/model'
import { LEVEL_RANK } from '@/core/labels'
import type { AxmlManifest } from '@/core/triage/axml'
import { parseIndicators } from '@/core/triage/match'

/**
 * Risk assessment of an Android app from its manifest + embedded strings, offline. Flags dangerous
 * permissions and tell-tale combinations (SMS + overlay + install = banking trojan pattern), and
 * surfaces embedded domains/IPs so they can be matched against the unit's logs. The app is never
 * installed or run. Score is explainable: `1 − Π(1 − weight)`.
 */

const LEVEL_WEIGHT: Record<Level, number> = { critical: 0.6, high: 0.4, medium: 0.2, low: 0.1, informational: 0.05 }

/** Short permission name -> Indonesian meaning + risk. Benign permissions are intentionally absent. */
const DANGEROUS: Record<string, { label: string; level: Level }> = {
  SEND_SMS: { label: 'Mengirim SMS (bisa menguras pulsa / sebar tautan)', level: 'high' },
  RECEIVE_SMS: { label: 'Menerima SMS (mencuri OTP)', level: 'high' },
  READ_SMS: { label: 'Membaca SMS tersimpan (OTP/kode)', level: 'high' },
  READ_CONTACTS: { label: 'Membaca daftar kontak', level: 'medium' },
  READ_CALL_LOG: { label: 'Membaca log panggilan', level: 'high' },
  REQUEST_INSTALL_PACKAGES: { label: 'Memasang aplikasi lain di luar Play Store', level: 'high' },
  SYSTEM_ALERT_WINDOW: { label: 'Menimpa layar aplikasi lain (overlay)', level: 'high' },
  BIND_ACCESSIBILITY_SERVICE: { label: 'Layanan aksesibilitas — dapat membaca & mengendalikan layar', level: 'critical' },
  READ_PHONE_STATE: { label: 'Membaca status & nomor telepon', level: 'medium' },
  RECORD_AUDIO: { label: 'Merekam audio', level: 'high' },
  CAMERA: { label: 'Mengakses kamera', level: 'medium' },
  ACCESS_FINE_LOCATION: { label: 'Lokasi presisi', level: 'medium' },
  WRITE_EXTERNAL_STORAGE: { label: 'Menulis ke penyimpanan', level: 'low' },
  RECEIVE_BOOT_COMPLETED: { label: 'Berjalan otomatis saat ponsel menyala', level: 'low' },
  QUERY_ALL_PACKAGES: { label: 'Melihat semua aplikasi terpasang', level: 'medium' },
  DISABLE_KEYGUARD: { label: 'Menonaktifkan kunci layar', level: 'medium' },
  WRITE_SETTINGS: { label: 'Mengubah pengaturan sistem', level: 'medium' },
}

export type ApkPermission = { name: string; label: string; level: Level }
export type ApkSignal = { id: string; label: string; level: Level }

export type ApkReport = {
  package?: string
  label?: string
  versionName?: string
  sha256: string
  size: number
  /** Notable (dangerous) permissions, most severe first. */
  permissions: ApkPermission[]
  /** Total declared permissions (including benign ones). */
  permissionCount: number
  /** Domains/IPs embedded in the app, to match against the logs. */
  indicators: string[]
  signals: ApkSignal[]
  score: number
}

export type ApkInput = { manifest: AxmlManifest; strings: string[]; sha256: string; size: number }

const shortName = (p: string) => p.split('.').at(-1) ?? p

export function analyzeApk(input: ApkInput): ApkReport {
  const permissions: ApkPermission[] = []
  for (const name of input.manifest.permissions) {
    const d = DANGEROUS[shortName(name)]
    if (d) permissions.push({ name, label: d.label, level: d.level })
  }
  permissions.sort((a, b) => LEVEL_RANK[b.level] - LEVEL_RANK[a.level] || a.name.localeCompare(b.name))

  const have = new Set(input.manifest.permissions.map(shortName))
  const sms = have.has('READ_SMS') || have.has('RECEIVE_SMS') || have.has('SEND_SMS')
  const indicators = parseIndicators(input.strings.join('\n')).filter((i) => i.kind !== 'sha256').map((i) => i.value)

  const signals: ApkSignal[] = []
  if (sms && have.has('SYSTEM_ALERT_WINDOW') && have.has('REQUEST_INSTALL_PACKAGES'))
    signals.push({ id: 'banker', label: 'Pola trojan perbankan: akses SMS + overlay layar + pasang aplikasi', level: 'critical' })
  if (have.has('BIND_ACCESSIBILITY_SERVICE'))
    signals.push({ id: 'accessibility', label: 'Meminta layanan aksesibilitas (kendali penuh perangkat)', level: 'critical' })
  if (sms && have.has('READ_CONTACTS'))
    signals.push({ id: 'sms-contacts', label: 'Kombinasi SMS + kontak: pola pencurian OTP dan penyebaran', level: 'high' })
  if (indicators.length)
    signals.push({ id: 'embedded', label: `Memuat ${indicators.length} alamat/domain tertanam`, level: 'medium' })
  if (permissions.length >= 5)
    signals.push({ id: 'many', label: `Banyak izin berisiko (${permissions.length})`, level: 'medium' })

  const weights = [...permissions.map((p) => p.level), ...signals.map((s) => s.level)]
  const score = 1 - weights.reduce((acc, l) => acc * (1 - LEVEL_WEIGHT[l]), 1)

  return {
    package: input.manifest.package,
    label: input.manifest.labels[0],
    versionName: input.manifest.versionName,
    sha256: input.sha256,
    size: input.size,
    permissions,
    permissionCount: input.manifest.permissions.length,
    indicators,
    signals,
    score,
  }
}
