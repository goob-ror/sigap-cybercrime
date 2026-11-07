import type { NormalizedEvent, UnitProfile } from '@/core/model'
import type { RuleMeta } from '@/core/detect/sigma'
import { INDICATOR_LOGSOURCE, indexLists, matchHost, type IndicatorList } from '@/core/indicators'
import { formatBytes } from '@/core/ingest/kv'
import { ipInCidr, isPrivateIp } from '@/core/net'

/**
 * Rules that need several events at once (counts, sums, distinct values). Sigma's own
 * correlation syntax is not supported, so these are written in TypeScript but expose the same
 * metadata as Sigma rules so the UI treats them alike.
 */

export type NativeHit = { eventIds: string[]; matched: Record<string, string>; ts: number }
export type NativeRule = { meta: RuleMeta; run(events: readonly NormalizedEvent[]): NativeHit[] }

const MAX_EVENTS_PER_INDICATOR = 200
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

export function createNativeRules(profile: UnitProfile, lists: readonly IndicatorList[] = []): NativeRule[] {
  const isEngineering =(ip: string | undefined) => !!ip && profile.engineeringHosts.includes(ip)

  const failedLogonBurst: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-failed-logon-burst',
      title: 'Rentetan logon gagal dari satu sumber',
      description: 'Lima atau lebih logon gagal (EventID 4625) dari sumber yang sama dengan jeda antar-percobaan tidak lebih dari 5 menit. Pola ini khas tebak kata sandi (brute force / password spraying).',
      level: 'high',
      signal: 'percobaan',
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
      description: 'Total data keluar dari satu host internal ke satu alamat eksternal melebihi ambang pada profil satuan dalam rangkaian sesi berdekatan (jeda ≤ 30 menit). Dapat menandakan eksfiltrasi data.',
      level: 'high',
      signal: 'ambigu',
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
      signal: 'ambigu',
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
      signal: 'percobaan',
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
      signal: 'percobaan',
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
      signal: 'percobaan',
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
      description: 'Sebuah alamat berhasil login SSH setelah gagal dari alamat yang sama dalam 30 menit terakhir: sedikitnya 3 kali, atau 2 kali bila yang berhasil adalah akun lain. Kemungkinan besar kata sandi berhasil ditebak dan penyerang kini masuk ke server.',
      level: 'critical',
      signal: 'kuat',
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
          // Someone mistyping their own password twice is normal. Failing on one account, then getting in on another, is not.
          const otherAccount = failures.some((f) => String(f.fields.target_user) !== String(s.fields.target_user))
          if (failures.length < 3 && !(failures.length === 2 && otherAccount)) return
          hits.push({ eventIds: [...failures.map((f) => f.id), s.id], ts: s.ts, matched: { Sumber: s.srcIp!, Akun: String(s.fields.target_user ?? '?'), 'Kegagalan sebelumnya': String(failures.length), Host: s.host ?? '?' } })
        })
      }
      return hits
    },
  }

  const winSuccessAfterFailures: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-win-success-after-failures',
      title: 'Logon Windows berhasil setelah rentetan gagal',
      description: 'Sebuah alamat berhasil logon jarak jauh (tipe 3 atau 10) setelah sedikitnya 5 kali gagal dari alamat yang sama ke host itu dalam 30 menit terakhir, memakai akun yang ditebak atau akun yang belum pernah terlihat dari alamat itu. Kemungkinan besar kata sandi berhasil ditebak.',
      level: 'critical',
      signal: 'kuat',
      tags: ['attack.credential_access', 'attack.t1110', 'attack.initial_access', 'attack.t1078'],
      falsepositives: ['Pengguna lupa kata sandi lalu berhasil (dari alamat internal yang dikenal)', 'Layanan yang kata sandinya baru diperbarui'],
      respons: ['Tanyakan kepada pemilik akun apakah ia yang login', 'Bila tidak, putuskan sesi, kunci akun, dan ganti kata sandinya dari perangkat bersih', 'Periksa aktivitas akun itu di host tersebut setelah waktu login'],
      logsource: { product: 'windows', service: 'security' },
    },
    run(events) {
      const logons = events.filter((e) => e.logsource.service === 'security' && e.srcIp && (Number(e.fields.EventID) === 4625 || (Number(e.fields.EventID) === 4624 && [3, 10].includes(Number(e.fields.LogonType)))))
      const hits: NativeHit[] = []
      for (const [, list] of groupBy(logons, (e) => `${e.host ?? '?'}|${e.srcIp}`)) {
        list.forEach((s, i) => {
          if (Number(s.fields.EventID) !== 4624) return
          const failures = list.slice(0, i).filter((f) => Number(f.fields.EventID) === 4625 && s.ts - f.ts <= 30 * MINUTE)
          if (failures.length < 5) return
          // The owner of an infected PC keeps opening file shares while it guesses passwords: an account
          // that was already logging on from there, and is not the one being guessed, says nothing new.
          const account = String(s.fields.TargetUserName ?? '').toLowerCase()
          const guessed = failures.some((f) => String(f.fields.TargetUserName ?? '').toLowerCase() === account)
          const routine = list.some((l) => l.ts < failures[0].ts && Number(l.fields.EventID) === 4624 && String(l.fields.TargetUserName ?? '').toLowerCase() === account)
          if (!guessed && routine) return
          hits.push({ eventIds: [...failures.map((f) => f.id), s.id], ts: s.ts, matched: { Sumber: s.srcIp!, Akun: String(s.fields.TargetUserName ?? '?'), 'Kegagalan sebelumnya': String(failures.length), Host: s.host ?? '?' } })
        })
      }
      return hits
    },
  }

  const deviceLoginBrute: NativeRule = {
    meta: {
      ...base,
      id: 'sigap-native-device-login-brute',
      title: 'Rentetan login gagal ke perangkat jaringan',
      description: 'Lima atau lebih login gagal ke firewall atau router (MikroTik, Cisco) dari satu alamat dengan jeda tidak lebih dari 5 menit. Panel admin yang terbuka ke internet terus-menerus ditebak seperti ini.',
      level: 'high',
      signal: 'percobaan',
      tags: ['attack.credential_access', 'attack.t1110.001'],
      falsepositives: ['Admin lupa kata sandi perangkat'],
      respons: ['Tutup akses panel admin (Winbox, SSH, web) dari internet', 'Ganti kata sandi admin perangkat bila lemah', 'Periksa apakah ada login berhasil dari alamat yang sama'],
      logsource: { category: 'firewall' },
    },
    run(events) {
      const fails = events.filter((e) => e.fields.action === 'login-failure' && e.srcIp)
      const hits: NativeHit[] = []
      for (const [, list] of groupBy(fails, (e) => `${e.host ?? '?'}|${e.srcIp}`)) {
        for (const run of clusters(list, 5 * MINUTE)) {
          if (run.length < 5) continue
          hits.push({ eventIds: run.map((e) => e.id), ts: run[0].ts, matched: { Sumber: run[0].srcIp!, 'Jumlah kegagalan': String(run.length), Perangkat: run[0].host ?? '?' } })
        }
      }
      return hits
    },
  }

  const rules = [failedLogonBurst, largeUpload, modbusDiscovery, webLoginBrute, web404Scan, sshBrute, sshSuccessAfterFailures, winSuccessAfterFailures, deviceLoginBrute]
  return lists.length ? [...rules, indicatorListRule(lists)] : rules
}

/** Exists only once a unit has imported a list: without one, nothing could ever make it fire. */
export function indicatorListRule(lists: readonly IndicatorList[]): NativeRule {
  return {
    meta: {
      ...base,
      id: 'sigap-native-indicator-list',
      title: 'Alamat cocok dengan daftar indikator lokal',
      description: 'Domain, alamat IP, atau hash pada log tercantum di daftar indikator yang diimpor satuan. Daftar seperti ini bisa memuat situs sah yang pernah disusupi, jadi kecocokan perlu diperiksa.',
      level: 'high',
      signal: 'ambigu',
      tags: ['attack.command_and_control'],
      falsepositives: ['Situs sah yang pernah disusupi lalu sudah dibersihkan', 'Layanan bersama yang satu alamatnya dipakai banyak situs'],
      respons: ['Periksa host yang menghubungi alamat itu dan waktunya', 'Blokir alamatnya bila tidak ada keperluan yang sah', 'Periksa apakah daftarnya masih baru'],
      logsource: { category: INDICATOR_LOGSOURCE },
    },
    run(events) {
      const index = indexLists(lists)
      const found = new Map<string, NativeHit>()
      const record = (e: NormalizedEvent, indicator: string, list: string) => {
        const key = `${indicator}|${e.host ?? ''}`
        const hit = found.get(key)
        if (!hit) {
          found.set(key, { eventIds: [e.id], ts: e.ts, matched: { Indikator: indicator, Daftar: list, Host: e.host ?? '?' } })
          return
        }
        if (hit.eventIds.length < MAX_EVENTS_PER_INDICATOR) hit.eventIds.push(e.id)
        hit.ts = Math.min(hit.ts, e.ts)
      }
      for (const e of events) {
        for (const host of [e.domain, e.dstIp, e.srcIp]) {
          const match = host ? matchHost(host, index) : null
          if (match) record(e, match.indicator, match.list)
        }
        for (const hash of [e.file?.sha256, e.process?.sha256]) {
          const list = hash ? index.hashes.get(hash.toLowerCase()) : undefined
          if (list) record(e, hash!.toLowerCase(), list)
        }
      }
      return [...found.values()]
    },
  }
}
