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

  return [failedLogonBurst, largeUpload, modbusDiscovery]
}
