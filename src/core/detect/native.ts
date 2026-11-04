import type { NormalizedEvent, UnitProfile } from '@/core/model'
import type { RuleMeta } from '@/core/detect/sigma'
import { formatBytes } from '@/core/ingest/kv'
import { ipInCidr, isPrivateIp } from '@/core/net'

/**
 * Rules that need several events at once (counts, sums, distinct values). Sigma's own
 * correlation syntax is not supported, so these are written in TypeScript but expose the same
 * metadata as Sigma rules so the UI treats them alike.
 */

export type NativeHit = { eventIds: string[]; matched: Record<string, string>; ts: number }
export type NativeRule = { meta: RuleMeta; run(events: readonly NormalizedEvent[]): NativeHit[] }

const base = { kind: 'native' as const, status: 'experimental', author: 'SIGAP (Tim Pengen Seblak)', references: [] }

/** Splits time-sorted events into runs where consecutive events are at most `gapMs` apart. */
function clusters<T extends { ts: number }>(items: T[], gapMs: number): T[][] {
  const out: T[][] = []
  for (const item of items) {
    const last = out.at(-1)
    if (last && item.ts - last.at(-1)!.ts <= gapMs) last.push(item)
    else out.push([item])
  }
  return out
}

function groupBy<T>(items: readonly T[], key: (item: T) => string | undefined): Map<string, T[]> {
  const map = new Map<string, T[]>()
  for (const item of items) {
    const k = key(item)
    if (k === undefined) continue
    if (!map.has(k)) map.set(k, [])
    map.get(k)!.push(item)
  }
  for (const list of map.values()) list.sort((a, b) => (a as { ts: number }).ts - (b as { ts: number }).ts)
  return map
}

const MINUTE = 60_000

export function createNativeRules(profile: UnitProfile): NativeRule[] {
  const isEngineering = (ip: string | undefined) => !!ip && profile.engineeringHosts.includes(ip)

  const failedLogonBurst: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-failed-logon-burst',
      title: 'Rentetan logon gagal dari satu sumber',
      description: 'Lima atau lebih logon gagal (EventID 4625) dari sumber yang sama dengan jeda antar-percobaan tidak lebih dari 5 menit. Pola ini khas tebak kata sandi (brute force / password spraying).',
      level: 'high',
      tags: ['attack.credential_access', 'attack.t1110'],
      falsepositives: ['Pengguna lupa kata sandi dan mencoba berulang kali', 'Layanan dengan kredensial kedaluwarsa'],
      respons: ['Identifikasi host sumber dan pemiliknya', 'Kunci sementara akun yang menjadi sasaran', 'Periksa apakah ada logon berhasil dari sumber yang sama setelah rentetan ini'],
      logsource: { product: 'windows', service: 'security' },
    },
    run(events) {
      const failures = events.filter((e) => e.logsource.service === 'security' && Number(e.fields.EventID) === 4625)
      const hits: NativeHit[] = []
      for (const [source, list] of groupBy(failures, (e) => e.srcIp ?? (e.fields.WorkstationName as string | undefined) ?? e.host)) {
        for (const run of clusters(list, 5 * MINUTE)) {
          if (run.length < 5) continue
          const targets = [...new Set(run.map((e) => String(e.fields.TargetUserName ?? '?')))]
          hits.push({ eventIds: run.map((e) => e.id), ts: run[0].ts, matched: { Sumber: source, 'Jumlah kegagalan': String(run.length), 'Akun sasaran': targets.join(', '), Target: run[0].host ?? '?' } })
        }
      }
      return hits
    },
  }

  const largeUpload: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-large-upload',
      title: 'Volume unggahan besar ke tujuan eksternal',
      description: `Total data keluar dari satu host internal ke satu alamat eksternal melebihi ${formatBytes(profile.uploadThresholdBytes)} dalam rangkaian sesi berdekatan (jeda ≤ 30 menit). Dapat menandakan eksfiltrasi data.`,
      level: 'high',
      tags: ['attack.exfiltration', 'attack.t1048', 'attack.t1567.002'],
      falsepositives: ['Pencadangan ke layanan cloud resmi', 'Unggahan berkas besar yang disetujui'],
      respons: ['Konfirmasi apakah tujuan merupakan layanan resmi satuan', 'Blokir alamat tujuan di firewall bila tidak dikenal', 'Amankan host sumber dan identifikasi data yang dikirim'],
      logsource: { category: 'firewall' },
    },
    run(events) {
      const outbound = events.filter((e) => e.dstIp && !isPrivateIp(e.dstIp) && e.srcIp && Number(e.fields.sentbyte ?? e.fields.orig_bytes) > 0)
      const hits: NativeHit[] = []
      for (const [, list] of groupBy(outbound, (e) => `${e.dataset}|${e.srcIp}|${e.dstIp}`)) {
        for (const run of clusters(list, 30 * MINUTE)) {
          const total = run.reduce((sum, e) => sum + Number(e.fields.sentbyte ?? e.fields.orig_bytes ?? 0), 0)
          if (total < profile.uploadThresholdBytes) continue
          const first = run[0]
          hits.push({
            eventIds: run.map((e) => e.id),
            ts: first.ts,
            matched: { Sumber: first.srcIp!, Tujuan: first.domain ? `${first.domain} (${first.dstIp})` : first.dstIp!, 'Total keluar': formatBytes(total), 'Jumlah sesi': String(run.length), 'Sumber log': first.dataset },
          })
        }
      }
      return hits
    },
  }

  const modbusDiscovery: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-modbus-discovery',
      title: 'Pemindaian register Modbus oleh host tidak berwenang',
      description: 'Sebuah host di luar daftar HMI/engineering membaca 10 atau lebih register Modbus berbeda dalam waktu singkat (jeda ≤ 2 menit). Pola ini khas pengintaian proses OT sebelum manipulasi.',
      level: 'high',
      tags: ['attack.discovery', 'attack.t0888', 'attack.t0846'],
      falsepositives: ['Laptop teknisi vendor saat pemeliharaan terjadwal (tambahkan ke daftar engineering)'],
      respons: ['Identifikasi host sumber dan siapa yang menggunakannya', 'Batasi akses ke port 502 hanya dari HMI/engineering', 'Siagakan operator untuk memantau kondisi fisik genset'],
      logsource: { product: 'zeek' },
    },
    run(events) {
      const reads = events.filter((e) => e.ot?.protocol === 'modbus' && /^READ/i.test(e.ot.func ?? '') && !isEngineering(e.srcIp))
      const hits: NativeHit[] = []
      for (const [source, list] of groupBy(reads, (e) => e.srcIp)) {
        for (const run of clusters(list, 2 * MINUTE)) {
          const registers = new Set(run.map((e) => `${e.ot!.unitId ?? '?'}:${e.ot!.register ?? '?'}`))
          if (registers.size < 10) continue
          const inOt = profile.otSubnets.some((net) => ipInCidr(source, net))
          hits.push({
            eventIds: run.map((e) => e.id),
            ts: run[0].ts,
            matched: { Sumber: `${source}${inOt ? '' : ' (di luar segmen OT)'}`, Tujuan: run[0].dstIp ?? '?', 'Register berbeda': String(registers.size), 'Jumlah permintaan': String(run.length) },
          })
        }
      }
      return hits
    },
  }

  const LOGIN_PATH = /\/(wp-login\.php|xmlrpc\.php|login|signin|sign-in|logon|auth|session|admin\/login|user\/login|administrator)(\/|\.php|\.aspx?)?$/i
  const isWeb = (e: NormalizedEvent) => e.dataset === 'web.access'
  const isSsh = (e: NormalizedEvent) => e.dataset === 'linux.auth' && String(e.fields.program).toLowerCase() === 'sshd'

  const webLoginBrute: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-web-login-brute',
      title: 'Rentetan percobaan login ke halaman web',
      description: 'Sepuluh atau lebih permintaan POST ke halaman login (wp-login, /login, /admin/login, xmlrpc) dari satu alamat dengan jeda tidak lebih dari 2 menit. Pola tebak kata sandi terhadap panel admin situs.',
      level: 'high',
      tags: ['attack.credential_access', 'attack.t1110', 'attack.t1110.001'],
      falsepositives: ['Uji beban atau pemantauan otomatis yang memanggil halaman login'],
      respons: ['Blokir alamat IP sumber di firewall/WAF', 'Periksa apakah ada status 200/302 setelah rentetan (login berhasil)', 'Aktifkan pembatasan percobaan login dan verifikasi dua langkah untuk admin'],
      logsource: { category: 'webserver' },
    },
    run(events) {
      const posts = events.filter((e) => isWeb(e) && String(e.fields['cs-method']).toUpperCase() === 'POST' && LOGIN_PATH.test(String(e.fields['cs-uri-stem'] ?? '')))
      const hits: NativeHit[] = []
      for (const [source, list] of groupBy(posts, (e) => e.srcIp)) {
        for (const run of clusters(list, 2 * MINUTE)) {
          if (run.length < 10) continue
          const statuses = new Map<string, number>()
          for (const e of run) statuses.set(String(e.fields['sc-status']), (statuses.get(String(e.fields['sc-status'])) ?? 0) + 1)
          hits.push({
            eventIds: run.map((e) => e.id),
            ts: run[0].ts,
            matched: { Sumber: source, 'Jumlah percobaan': String(run.length), Halaman: [...new Set(run.map((e) => String(e.fields['cs-uri-stem'])))].join(', '), 'Kode status': [...statuses].map(([s, n]) => `${s}×${n}`).join(', '), Target: run[0].host ?? '?' },
          })
        }
      }
      return hits
    },
  }

  const web404Scan: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-web-404-scan',
      title: 'Pemindaian direktori situs (banjir 404)',
      description: 'Satu alamat meminta 20 atau lebih path berbeda yang tidak ada (404) dengan jeda tidak lebih dari 2 menit. Ciri alat pemindai yang menebak folder dan berkas tersembunyi.',
      level: 'medium',
      tags: ['attack.reconnaissance', 'attack.t1595', 'attack.t1595.003'],
      falsepositives: ['Tautan rusak massal setelah situs dipindah (dari banyak alamat, bukan satu)'],
      respons: ['Blokir alamat IP sumber', 'Periksa apakah pemindai menemukan path berstatus 200 (berkas yang tidak semestinya publik)'],
      logsource: { category: 'webserver' },
    },
    run(events) {
      const misses = events.filter((e) => isWeb(e) && Number(e.fields['sc-status']) === 404)
      const hits: NativeHit[] = []
      for (const [source, list] of groupBy(misses, (e) => e.srcIp)) {
        for (const run of clusters(list, 2 * MINUTE)) {
          const paths = new Set(run.map((e) => String(e.fields['cs-uri-stem'])))
          if (paths.size < 20) continue
          hits.push({
            eventIds: run.map((e) => e.id),
            ts: run[0].ts,
            matched: { Sumber: source, 'Path berbeda (404)': String(paths.size), 'Jumlah permintaan': String(run.length), Contoh: [...paths].slice(0, 4).join(', '), Target: run[0].host ?? '?' },
          })
        }
      }
      return hits
    },
  }

  const sshBrute: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-ssh-brute-force',
      title: 'Rentetan login SSH gagal dari satu sumber',
      description: 'Lima atau lebih login SSH gagal dari alamat yang sama ke satu server dengan jeda tidak lebih dari 5 menit. Pola tebak kata sandi terhadap akun server.',
      level: 'high',
      tags: ['attack.credential_access', 'attack.t1110.001'],
      falsepositives: ['Skrip otomatis dengan kunci/kata sandi kedaluwarsa'],
      respons: ['Blokir alamat IP sumber (atau aktifkan fail2ban)', 'Matikan login root lewat SSH dan login dengan kata sandi; gunakan kunci', 'Periksa apakah ada login berhasil dari sumber yang sama setelah rentetan ini'],
      logsource: { product: 'linux', service: 'auth' },
    },
    run(events) {
      const fails = events.filter((e) => isSsh(e) && e.fields.outcome === 'failure' && e.srcIp)
      const hits: NativeHit[] = []
      for (const [, list] of groupBy(fails, (e) => `${e.host ?? '?'}|${e.srcIp}`)) {
        for (const run of clusters(list, 5 * MINUTE)) {
          if (run.length < 5) continue
          const targets = [...new Set(run.map((e) => String(e.fields.target_user ?? '?')))]
          hits.push({ eventIds: run.map((e) => e.id), ts: run[0].ts, matched: { Sumber: run[0].srcIp!, 'Jumlah kegagalan': String(run.length), 'Akun sasaran': targets.join(', '), Target: run[0].host ?? '?' } })
        }
      }
      return hits
    },
  }

  const sshSuccessAfterFailures: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-ssh-success-after-failures',
      title: 'Login SSH berhasil setelah rentetan gagal',
      description: 'Sebuah alamat berhasil login SSH setelah sedikitnya 3 kali gagal dari alamat yang sama dalam 30 menit terakhir. Kemungkinan besar kata sandi berhasil ditebak dan penyerang kini masuk ke server.',
      level: 'critical',
      tags: ['attack.credential_access', 'attack.t1110', 'attack.initial_access', 'attack.t1078'],
      falsepositives: ['Pengguna lupa kata sandi lalu berhasil (dari alamat internal yang dikenal)'],
      respons: ['Putus sesi tersebut dan kunci akun yang dipakai', 'Anggap server disusupi: periksa akun baru, sudo, dan berkas yang diubah setelah waktu login', 'Ganti kata sandi akun dan blokir alamat sumber'],
      logsource: { product: 'linux', service: 'auth' },
    },
    run(events) {
      const ssh = events.filter((e) => isSsh(e) && e.srcIp && (e.fields.outcome === 'failure' || e.fields.outcome === 'success'))
      const hits: NativeHit[] = []
      for (const [, list] of groupBy(ssh, (e) => `${e.host ?? '?'}|${e.srcIp}`)) {
        list.forEach((s, i) => {
          if (s.fields.outcome !== 'success') return
          const failures = list.slice(0, i).filter((f) => f.fields.outcome === 'failure' && s.ts - f.ts <= 30 * MINUTE)
          if (failures.length < 3) return
          hits.push({ eventIds: [...failures.map((f) => f.id), s.id], ts: s.ts, matched: { Sumber: s.srcIp!, Akun: String(s.fields.target_user ?? '?'), 'Kegagalan sebelumnya': String(failures.length), Host: s.host ?? '?' } })
        })
      }
      return hits
    },
  }

  return [failedLogonBurst, largeUpload, modbusDiscovery, webLoginBrute, web404Scan, sshBrute, sshSuccessAfterFailures]
}
