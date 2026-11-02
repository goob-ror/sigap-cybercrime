/**
 * Playbook penanganan insiden — panduan respons langkah-demi-langkah dalam Bahasa Indonesia untuk
 * operator satuan tanpa analis khusus. Tiap playbook berfase: tindakan segera (saat), pemulihan &
 * investigasi (pasca), dan pencegahan (agar tidak berulang). Statis dan sintetis; dicocokkan ke
 * sebuah insiden lewat taktik ATT&CK dan aturan yang menyala (`recommendPlaybooks`).
 *
 * Catatan keselamatan OT dicantumkan di langkahnya: tindakan pada sistem kendali (genset/PLC)
 * wajib diverifikasi, mendapat otorisasi komandan, dan dicatat.
 */

export type PlaybookPhase = { title: string; steps: string[] }

export type Playbook = {
  id: string
  title: string
  summary: string
  /** Taktik ATT&CK yang ditangani (nama Inggris, seperti pada `incident.tactics`). */
  tactics: string[]
  /** Id aturan yang kuat menandakan playbook ini (bobot lebih tinggi dari taktik). */
  ruleHints?: string[]
  phases: PlaybookPhase[]
}

const PHASE_IMMEDIATE = 'Tindakan segera (saat insiden)'
const PHASE_RECOVER = 'Pemulihan & investigasi (pasca)'
const PHASE_PREVENT = 'Pencegahan agar tidak berulang'

export const PLAYBOOKS: Playbook[] = [
  {
    id: 'phishing-apk',
    title: 'Berkas/aplikasi berbahaya dari pesan (phishing)',
    summary: 'Personel menerima dokumen ber-makro, pintasan, atau APK lewat WhatsApp/Telegram dari akun yang tampak tepercaya.',
    tactics: ['Initial Access', 'Execution'],
    ruleHints: ['sigap-win-macro-doc-from-messaging', 'sigap-win-office-spawn-shell'],
    phases: [
      { title: PHASE_IMMEDIATE, steps: [
        'Jangan buka/jalankan berkas. Minta pengguna berhenti berinteraksi dengan perangkat.',
        'Putuskan perangkat dari jaringan (cabut kabel / matikan Wi-Fi), jangan dimatikan.',
        'Konfirmasi ke pengirim lewat saluran lain (telepon/tatap muka) apakah ia benar mengirim berkas.',
      ] },
      { title: PHASE_RECOVER, steps: [
        'Hitung hash berkas dan periksa di Triase SIGAP (APK/URL) sebelum menyimpulkan.',
        'Cari host lain yang menerima berkas atau menghubungi domain/IP yang sama (Triase → Pencocokan IOC).',
        'Bila berkas terbukti berbahaya, bersihkan/instal ulang perangkat dan reset kata sandi akun pengguna dari perangkat bersih.',
      ] },
      { title: PHASE_PREVENT, steps: [
        'Edukasi personel: jangan buka lampiran dari pesan, verifikasi via jalur resmi.',
        'Ekspor daftar blokir IOC dan terapkan domain/IP ke DNS/firewall satuan.',
        'Batasi pemasangan aplikasi dari luar sumber resmi pada perangkat dinas.',
      ] },
    ],
  },
  {
    id: 'account-takeover',
    title: 'Akun WhatsApp/pesan diambil alih',
    summary: 'Akun pesan personel dibajak (mis. lewat pembajakan OTP) lalu dipakai menyebar berkas berbahaya ke kontak satuan.',
    tactics: ['Initial Access'],
    ruleHints: ['sigap-win-macro-doc-from-messaging'],
    phases: [
      { title: PHASE_IMMEDIATE, steps: [
        'Umumkan ke kontak/grup satuan agar mengabaikan pesan & berkas dari akun tersebut.',
        'Minta pemilik akun keluar dari semua sesi dan aktifkan verifikasi dua langkah.',
        'Kumpulkan bukti: tangkapan layar pesan, nomor/akun pengirim, waktu kejadian.',
      ] },
      { title: PHASE_RECOVER, steps: [
        'Pulihkan akun lewat prosedur resmi penyedia; ganti PIN/kata sandi terkait.',
        'Periksa perangkat penerima berkas dengan playbook "berkas berbahaya dari pesan".',
        'Catat daftar penerima untuk pemantauan lanjutan.',
      ] },
      { title: PHASE_PREVENT, steps: [
        'Wajibkan verifikasi dua langkah pada aplikasi pesan personel.',
        'Jangan pernah membagikan kode OTP; sosialisasikan modus pembajakan OTP.',
      ] },
    ],
  },
  {
    id: 'endpoint-malware',
    title: 'Malware/eksekusi mencurigakan di endpoint',
    summary: 'PowerShell ter-encode, dump kredensial, proteksi dimatikan, atau tugas terjadwal mencurigakan pada sebuah PC.',
    tactics: ['Execution', 'Defense Evasion', 'Persistence', 'Credential Access', 'Command and Control'],
    ruleHints: ['sigap-win-ps-encoded', 'sigap-win-lsass-dump-comsvcs', 'sigap-win-defender-tamper', 'sigap-win-schtask-create', 'sigap-win-ps-download-cradle'],
    phases: [
      { title: PHASE_IMMEDIATE, steps: [
        'Isolasi host dari jaringan (jangan dimatikan agar bukti memori tetap ada).',
        'Catat proses, perintah, dan waktu dari temuan SIGAP; amankan berkas dump (.dmp) bila ada.',
        'Anggap seluruh akun yang pernah login di host ini bocor; prioritaskan akun admin & layanan.',
      ] },
      { title: PHASE_RECOVER, steps: [
        'Reset kata sandi akun terdampak dari perangkat bersih.',
        'Aktifkan kembali proteksi (Defender), periksa folder yang dikecualikan, nonaktifkan tugas terjadwal mencurigakan setelah bukti diamankan.',
        'Bersihkan/instal ulang host; verifikasi tidak ada mekanisme bertahan (tugas, layanan, akun baru).',
      ] },
      { title: PHASE_PREVENT, steps: [
        'Blokir domain/IP C2 di firewall/DNS (Ekspor daftar blokir IOC).',
        'Aktifkan audit pembuatan proses + perekaman baris perintah pada endpoint.',
        'Batasi penggunaan PowerShell dan hak admin lokal.',
      ] },
    ],
  },
  {
    id: 'lateral-movement',
    title: 'Pergerakan lateral / kompromi server',
    summary: 'Tebak kata sandi, akses share admin, atau layanan jarak jauh (PsExec) menandakan penyerang berpindah antar host.',
    tactics: ['Lateral Movement', 'Credential Access'],
    ruleHints: ['sigap-native-failed-logon-burst', 'sigap-win-admin-share', 'sigap-win-psexec-service'],
    phases: [
      { title: PHASE_IMMEDIATE, steps: [
        'Identifikasi host sumber (lewat logon tipe 3 pada waktu yang sama) dan isolasi.',
        'Nonaktifkan akun yang dipakai untuk berpindah; kunci sementara akun yang jadi sasaran.',
        'Isolasi server yang dituju bila tidak ada pemeliharaan terjadwal.',
      ] },
      { title: PHASE_RECOVER, steps: [
        'Reset kata sandi akun admin & layanan yang terlibat.',
        'Periksa host lain yang diakses dari sumber yang sama; cari layanan/akun baru.',
        'Pulihkan server dari cadangan bersih bila integritasnya diragukan.',
      ] },
      { title: PHASE_PREVENT, steps: [
        'Batasi akses share administratif dan logon jarak jauh antar segmen.',
        'Terapkan kata sandi kuat/unik dan pemantauan rentetan logon gagal.',
      ] },
    ],
  },
  {
    id: 'ot-disruption',
    title: 'Gangguan sistem kendali (OT/genset)',
    summary: 'Pengintaian register Modbus atau perintah ke PLC/genset dari host di luar HMI/engineering.',
    tactics: ['Impair Process Control', 'Impact', 'Discovery'],
    ruleHints: ['sigap-native-modbus-discovery', 'sigap-win-rdp-to-ot-host'],
    phases: [
      { title: PHASE_IMMEDIATE, steps: [
        'Siagakan operator HMI untuk memantau kondisi FISIK genset/PLC secara langsung.',
        'Identifikasi host sumber dan putuskan aksesnya ke segmen OT; jangan ubah setpoint tanpa otorisasi.',
        'Batasi akses ke port 502 (Modbus) hanya dari HMI/engineering yang sah.',
      ] },
      { title: PHASE_RECOVER, steps: [
        'Verifikasi parameter proses (tegangan/RPM/coil) kembali ke nilai aman — tindakan OT wajib otorisasi komandan dan dicatat.',
        'Periksa log HMI/engineering untuk akses jarak jauh yang tidak dikenal.',
        'Audit konfigurasi PLC terhadap baseline yang tersimpan.',
      ] },
      { title: PHASE_PREVENT, steps: [
        'Pisahkan jaringan OT dari IT; izinkan Modbus hanya dari host terdaftar.',
        'Nonaktifkan akses jarak jauh (RDP) langsung ke host HMI/engineering.',
        'Jadwalkan latihan tanggap gangguan OT bersama operator.',
      ] },
    ],
  },
  {
    id: 'exfiltration',
    title: 'Pencurian/eksfiltrasi data',
    summary: 'Pengarsipan terenkripsi lalu volume unggahan besar ke tujuan eksternal menandakan data dibawa keluar.',
    tactics: ['Collection', 'Exfiltration'],
    ruleHints: ['sigap-native-large-upload', 'sigap-win-archive-password'],
    phases: [
      { title: PHASE_IMMEDIATE, steps: [
        'Blokir alamat tujuan di firewall bila tidak dikenal; putuskan host sumber dari jaringan.',
        'Amankan berkas arsip (.7z/.rar) sebagai barang bukti sebelum dihapus.',
        'Identifikasi data yang mungkin dikirim dan tingkat kerahasiaannya.',
      ] },
      { title: PHASE_RECOVER, steps: [
        'Periksa log firewall untuk host lain yang menghubungi tujuan yang sama.',
        'Laporkan potensi kebocoran data sesuai prosedur satuan.',
        'Susun paket bukti SIGAP (ZIP + hash) untuk eskalasi ke PUSSIBERAD.',
      ] },
      { title: PHASE_PREVENT, steps: [
        'Terapkan ambang pemantauan volume keluar dan daftar tujuan yang diizinkan.',
        'Batasi utilitas arsip & enkripsi pada host yang menyimpan data sensitif.',
      ] },
    ],
  },
]

export const PLAYBOOK_BY_ID = new Map(PLAYBOOKS.map((p) => [p.id, p]))

/** Playbook yang relevan untuk sebuah insiden, diurutkan dari paling cocok. */
export function recommendPlaybooks(incident: { tactics: string[]; ruleIds: string[] }): Playbook[] {
  const tset = new Set(incident.tactics)
  const rset = new Set(incident.ruleIds)
  return PLAYBOOKS
    .map((pb) => ({ pb, score: (pb.ruleHints ?? []).reduce((n, r) => n + (rset.has(r) ? 2 : 0), 0) + pb.tactics.reduce((n, t) => n + (tset.has(t) ? 1 : 0), 0) }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score || a.pb.title.localeCompare(b.pb.title))
    .map((x) => x.pb)
}

/** Langkah berurutan dengan id stabil untuk pelacakan progres pada sebuah kasus. */
export function playbookSteps(pb: Playbook): { id: string; text: string; phase: string }[] {
  return pb.phases.flatMap((ph, pi) => ph.steps.map((s, si) => ({ id: `pb:${pb.id}#${pi}-${si}`, text: s, phase: ph.title })))
}
