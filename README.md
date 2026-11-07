<p align="center">
  <img src="public/favicon.svg" width="76" alt="Logo SIGAP" />
</p>

<h1 align="center">SIGAP</h1>

<p align="center">
  <b>Sistem Investigasi &amp; Penanganan Awal Insiden Siber Satuan</b><br/>
  Perangkat tanggap awal insiden siber yang berjalan <b>offline</b>, untuk satuan TNI AD tanpa analis khusus.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Offline--first-inti%20tanpa%20internet-22c55e" alt="Offline-first" />
  <img src="https://img.shields.io/badge/kategori-Penangkalan-f59e0b" alt="Penangkalan" />
  <img src="https://img.shields.io/badge/tes-369%20lulus-38bdf8" alt="369 tests" />
  <img src="https://img.shields.io/badge/React%2019-Vite%208-TypeScript-0ea5e9" alt="stack" />
  <img src="https://img.shields.io/badge/data-sintetis%20%26%20fiktif-a78bfa" alt="synthetic data" />
</p>

<p align="center">
  Entri <b>Kartika Cyber Hackathon 2026</b> (PUSSIBERAD × CODEPOLITAN) · Tim <b>Pengen Seblak</b> · Kategori <b>Penangkalan</b>
</p>

---

## 🎯 Apa itu SIGAP?

Banyak satuan tidak punya analis keamanan siber. Saat terjadi insiden — ponsel terkena phishing,
server diretas, atau genset dimatikan dari jarak jauh — operator biasa harus bisa memahami **apa
yang terjadi** dan **apa yang harus dilakukan**.

SIGAP adalah **kit penanganan awal** yang berjalan sepenuhnya di satu laptop, tanpa internet:

1. **Impor log** dari PC Windows, server web & Linux (VPS atau cPanel), firewall, sensor jaringan,
   dan pengendali OT (genset/PLC).
2. **Deteksi** aktivitas berbahaya dengan 62 aturan (Sigma + agregasi), lintas IT, web, dan OT, dan katakan
   terus terang **apa yang tidak dapat dilihat** dari log yang ada.
3. **Korelasi** semua temuan menjadi satu **insiden** dengan penilaian (indikasi kuat, perlu konfirmasi, atau hanya
   percobaan), lengkap dengan cerita & graf, lalu **terjemahkan ke dampak fisik**: apa yang terjadi pada genset, dan
   titik mana yang bisa memutus serangan.
4. **Respons** dengan playbook Bahasa Indonesia dan daftar blokir IOC untuk firewall/DNS.
5. **Laporan & bukti**: laporan siap cetak + paket bukti bertanda tangan untuk eskalasi ke PUSSIBERAD.
6. **Latihan**: personel berlatih mengambil keputusan pada tiap fase penanganan, dengan soal dari insiden itu sendiri.

SIGAP dapat dipasang sebagai **aplikasi** dengan jendela dan ikon sendiri, dan kit offline langsung membukanya seperti
itu. Tidak ada kecerdasan buatan di dalamnya: setiap temuan berasal dari aturan yang dapat dibaca dan diperiksa, dan
seluruh alur di atas berjalan tanpa internet.

> **Kategori Penangkalan** — rulebook: *"Teknologi untuk mendeteksi, mencegah, dan merespons
> ancaman siber."* SIGAP **mendeteksi** (aturan), **merespons** (playbook, laporan, kasus), dan
> **mencegah** yang berikutnya (ekspor daftar blokir IOC + pengerasan).

SIGAP melindungi sistem milik satuan sendiri — bukan memantau warga sipil. Semua data demo bersifat
sintetis dan fiktif; tidak ada malware nyata.

---

## 📸 Tampilan

| Ringkasan insiden | Graf investigasi |
|---|---|
| ![Ringkasan](docs/screenshots/ringkasan.jpg) | ![Graf](docs/screenshots/graf.jpg) |

| Triase (pemeriksa APK) | Laporan insiden |
|---|---|
| ![Triase APK](docs/screenshots/triase-apk.jpg) | ![Laporan](docs/screenshots/laporan.jpg) |

| Log Explorer | Pengaturan |
|---|---|
| ![Log Explorer](docs/screenshots/log-explorer.jpg) | ![Pengaturan](docs/screenshots/pengaturan.jpg) |

| Lintas IT-OT: putar ulang serangan | Uji pemutusan: genset tetap normal |
|---|---|
| ![Serangan sampai ke genset](docs/screenshots/lintas-it-ot.jpg) | ![Jalur diputus](docs/screenshots/lintas-it-ot-putus.jpg) |

| Rekonstruksi proses | Reputasi alamat |
|---|---|
| ![Rekonstruksi proses](docs/screenshots/rekonstruksi-proses.jpg) | ![Reputasi alamat](docs/screenshots/reputasi.jpg) |

<p align="center"><img src="docs/screenshots/latihan.jpg" width="70%" alt="Mode Latihan" /></p>

<p align="center"><img src="docs/screenshots/playbook.jpg" width="80%" alt="Playbook penanganan" /></p>

---

## ✨ Fitur

- 📥 **Impor fleksibel** — **berkas `.evtx` langsung**, tanpa konversi dan tanpa Windows, atau JSON dari
  pengumpul SIGAP, `Get-WinEvent`/`Get-EventLog`, Winlogbeat, evtx_dump, EvtxECmd; firewall (FortiGate key=value,
  **MikroTik**, pfSense, Cisco ASA/FTD); Zeek (conn/dns/modbus); **access log web** (Apache/Nginx/LiteSpeed/cPanel/
  Plesk/**IIS**, termasuk `.gz`); dan **log Linux** (`auth.log`/`secure`, `journalctl -o json`, **auditd**).
  Deteksi BOM & UTF-16/UTF-8 otomatis. ZIP dapat diimpor langsung; bila memuat `MANIFEST-SHA256.txt`, isinya
  dicocokkan dahulu. Zona waktu log tanpa zona dipilih saat impor (WIB, WITA, WIT, UTC).
  Panduan mengambil log web: [docs/PANDUAN_LOG_WEB.md](docs/PANDUAN_LOG_WEB.md).
- 🔍 **Deteksi** — 62 aturan: 53 bergaya **Sigma** + 9 aturan agregasi, termasuk tanda ransomware, temuan
  Microsoft Defender (aktif tanpa Sysmon), pencurian kredensial, worm USB, dan halaman judi online yang tersisip.
  Dipetakan ke **MITRE ATT&CK** & **ATT&CK for ICS**. Tiap aturan menyatakan seberapa banyak yang dibuktikannya:
  `kuat`, `ambigu` (juga wajar pada pekerjaan admin), atau `percobaan` (belum ada tanda berhasil).
- 👁️ **Cakupan analisis** — berapa aturan yang punya data, log apa yang kurang, dan cara mendapatkannya. "Tidak ada
  temuan" tidak pernah ditampilkan sebagai "aman".
- 🧩 **Korelasi** — temuan yang berbagi entitas dalam 24 jam digabung menjadi satu insiden, dengan **penilaian** yang
  menentukan judulnya dan **skor prioritas** `1 − Π(1 − bobot)` yang dapat dijelaskan. Skor mengurutkan penanganan; ia
  bukan peluang bahwa serangan terjadi. Percobaan dari satu sumber dilipat menjadi satu temuan, sehingga pemindai yang
  bising tidak menenggelamkan yang lain.
- 🏭 **Lintas IT-OT** — dari lalu lintas Modbus, SIGAP menyusun apa yang terjadi pada peralatan: siapa memberi perintah,
  apakah perintahnya terlihat berlaku pada pembacaan HMI berikutnya, berapa lama nilainya di luar batas aman, dan nilai
  normal terakhir yang harus dikembalikan. Ada **jendela respons** (waktu dari temuan pertama sampai OT tersentuh),
  **putar ulang serangan** di peta zona TI/OT, **uji pemutusan** untuk melihat host atau jalur mana yang menghentikan
  serangan sebelum sampai ke peralatan, dan aturan firewall MikroTik/iptables siap salin. Bila profil belum diisi, host
  yang biasa dan batas normal dipelajari dari log. Semuanya aritmetika atas log yang dapat ditelusuri, tanpa AI.
- 📊 **Ringkasan & graf** — cerita insiden urut waktu, aksi prioritas, dan graf entitas (dagre).
- 🔎 **Log Explorer** — telusuri semua event, termasuk yang tidak memicu aturan: cari teks atau `kolom:nilai`
  (`host:WS-MIN-03 EventID:4688`), saring menurut sumber, host, dan waktu, lalu lompat dari temuan ke baris lognya.
- 🗂️ **Kasus** — satu kasus per insiden: status, petugas, catatan, tindak lanjut, riwayat.
- 🩺 **Triase** — analisis URL (heuristik struktural), **pesan mencurigakan** seperti penipuan lewat WhatsApp,
  pencocokan IOC terhadap log, dan **pemeriksa APK** (mengurai `AndroidManifest.xml` biner tanpa menjalankan aplikasi:
  izin, layanan aksesibilitas, penerima SMS, dan alamat bot Telegram, yang lazim pada pencuri OTP berkedok "undangan").
- 🌐 **Reputasi alamat** — **daftar indikator lokal** yang diimpor satuan (berkas hosts, RPZ, CSV, atau daftar polos)
  dicocokkan dengan log dan URL tanpa internet. Bila server menyediakannya, **Google Safe Browsing** memeriksa alamat
  lewat awalan hash sehingga alamatnya sendiri tidak terkirim. Tersedia juga tautan ke VirusTotal dan Google
  Transparency Report. Alamat internal dan domain milik satuan tidak diperiksa ke layanan luar.
- 🎓 **Mode Latihan** — soal per fase (Deteksi, Analisis, Containment, Recovery) yang disusun dari insiden, termasuk
  keputusan khusus OT, lengkap dengan skor, waktu, dan riwayat tiap personel. Berjalan tanpa internet.
- 🖥️ **Aplikasi** — dapat dipasang dari Edge atau Chrome, dengan jendela dan ikon sendiri; jumlah kasus terbuka tampil
  pada ikonnya. Kit offline membukanya di jendela aplikasi secara langsung.
- 📒 **Playbook** — 8 panduan respons Bahasa (fase pra/saat/pasca), termasuk ransomware dan situs disusupi, yang
  **direkomendasikan otomatis** per insiden; langkah dapat dicentang dan tersimpan di kasus.
- 🚫 **Ekspor daftar blokir IOC** — IP/domain/hash eksternal untuk firewall/DNS. Yang berasal dari temuan belum
  terkonfirmasi, domain `.mil.id`/`.go.id`/milik satuan, dan layanan umum dipisahkan sebagai "perlu ditinjau" dan tidak
  ikut dimuat.
- 📝 **Laporan** — disusun otomatis dari data kasus, dengan penilaian, cakupan, dan penandaan klasifikasi dari profil
  satuan; cetak/simpan sebagai PDF.
- 🔐 **Paket bukti** — ZIP berisi laporan HTML, JSON, berkas asli, catatan penanganan berantai-hash, MANIFEST
  SHA-256, dan **tanda tangan ECDSA** dengan kunci yang tidak dapat disalin keluar dari browser, plus **verifikator**
  bawaan. Daftarkan sidik jari kunci kepada penerima lewat jalur lain sebelum terjadi insiden.
- 📴 **Offline-first** — browser hanya berbicara dengan asalnya sendiri (CSP `connect-src 'self'` pada build produksi).
  Setelah dibuka sekali, aplikasi tetap terbuka walau server tidak terjangkau; ada juga **kit offline** yang berjalan
  tanpa server, dan di dalamnya pemeriksaan online memang tidak ada.
- 🛡️ **SIGAP Pos Jaga** (purwarupa) — versi server yang membaca log web/Linux **saat ditulis** dengan
  mesin yang sama, lalu memberi peringatan sambil serangan berjalan. Satu berkas Node, hanya membaca,
  tanpa jaringan. Lihat [docs/POS_JAGA.md](docs/POS_JAGA.md).

---

## 🚀 Menjalankan (pengembangan)

Butuh **Node.js 22+**.

```bash
npm install
```

```bash
npm run dev
```

Buka http://localhost:5173, lalu **Impor Data → Muat skenario contoh** untuk mencoba alur lengkap
dengan dua serangan fiktif: rantai IT→OT dan peretasan portal web satuan (6.296 event → 41 temuan →
2 insiden berpenilaian "Indikasi kuat"). Skenario ini ditulis bersama aturannya, jadi hasilnya menunjukkan mesin
berjalan benar, bukan akurasi pada log nyata.

| Perintah | Fungsi |
|---|---|
| `npm run dev` | Server pengembangan di :5173 |
| `npm run build` | Typecheck + build produksi ke `dist/` |
| `npm run preview` | Menyajikan hasil build |
| `npm run serve` | Menyajikan `dist/` beserta API Safe Browsing di :8080, dengan kunci dari `.env` |
| `npm test` | Tes unit (Vitest) |
| `npm run build:agent` | Build SIGAP Pos Jaga (agen server) ke `dist-agent/pos-jaga.mjs` |
| `npm run build:kit` | Build semuanya dan menyusun kit offline ke `dist-kit/sigap-kit.zip` |
| `npm run typecheck` | `tsc --noEmit` |

### Sebelum memakai log nyata

Saat pertama dibuka, SIGAP menanyakan nama operator; nama ini dicatat pada setiap impor, tindakan
kasus, dan paket bukti. Nama diisi sendiri dan tidak diverifikasi.

Bawaannya adalah profil contoh fiktif (lencana **PROFIL CONTOH**). Isi profil jaringan satuan di
**Pengaturan**: segmen OT, host yang boleh mengirim perintah Modbus, ambang unggahan, aset, domain milik satuan,
titik kendali genset, dan penandaan laporan. Aturan deteksi langsung memakai nilai ini, dan semua temuan dihitung
ulang saat disimpan. Ekspor profil ke
`profil-satuan.json` lalu bagikan kepada personel lain (**Muat dari JSON**) atau pakai untuk Pos Jaga
(`--profil`). Nama operator dan profil tersimpan per browser, dan tidak ikut terhapus oleh
**Hapus data lokal**. Skenario contoh ditulis untuk profil contoh, jadi hasilnya berbeda bila dimuat
dengan profil lain.

### Google Safe Browsing (opsional)

Salin `.env.example` menjadi `.env`, lalu isi `SAFE_BROWSING_API`. Kunci dibaca server dan tidak pernah sampai ke
browser, baik pada `npm run dev` maupun `npm run serve`. Tanpa `.env`, pemeriksaan ini tidak muncul dan semua yang lain
tetap berjalan. Aktifkan di **Pengaturan > Layanan Online**.

---

## 💻 Kit dua laptop (latihan serang–pertahan)

Untuk demo "nyata" tanpa data buatan:

- `tools/sigap-drill.ps1` — sisi **penyerang**: aksi tak berbahaya tapi nyata yang meninggalkan
  jejak log Windows asli ([tools/README.md](tools/README.md)).
- `collector/sigap-collect.ps1` — sisi **pertahanan**: pengumpul log **read-only** → ZIP + hash,
  siap diimpor ke SIGAP ([collector/README.md](collector/README.md)).

SIGAP-lah pihak yang bertahan: data mengalir satu arah (penyerang → log → SIGAP).

---

## 🏗️ Arsitektur

Plain **React 19 + Vite + Tailwind v4 + TypeScript**. Seluruh analisis berjalan di browser, tanpa backend.

- `src/core/` — mesin murni (tanpa React), teruji unit: `ingest/` (parser, termasuk pembaca `.evtx`), `detect/`
  (Sigma + native), `correlate/` (insiden, penilaian, skor, kasus), `report/` (narasi, IOC), `triage/` (URL/IOC/AXML/
  pesan/Safe Browsing), `ot/` (rekonstruksi proses, jendela respons, uji pemutusan), `evidence/` (hash, rantai bukti, tanda tangan, paket), `coverage.ts` (apa yang dapat dilihat aturan), `indicators.ts` (daftar indikator lokal), `drill.ts` (soal
  latihan).
- `server/` — satu-satunya bagian yang memegang kunci dan berbicara dengan Google Safe Browsing, tanpa dependensi.
  Opsional: tanpanya aplikasi tetap lengkap, dan kit offline tidak memuatnya.
- `src/workers/ingest.worker.ts` — pipeline impor → deteksi → korelasi di luar thread UI.
- `src/db/` — Dexie (IndexedDB): event, temuan, insiden, kasus, artefak, blob asli, rantai bukti.
- `src/features/<halaman>/` — satu folder per layar · `src/components/ui/` — komponen bersama.
- `src/data/` — rule pack, katalog ATT&CK, profil unit, generator skenario, playbook, sampel APK.
- `src/sw/` — service worker agar aplikasi tetap terbuka saat server tidak terjangkau.
- `collector/` — pengumpul log Windows · `kit/` + `scripts/build-kit.mjs` — kit offline.

---

## 🔒 Keamanan & privasi

- **Offline-first**: browser hanya menghubungi asalnya sendiri; font Inter di-host sendiri.
- **Log tidak pernah keluar**: log, kasus, dan bukti tersimpan di IndexedDB browser pengguna.
- **Pengecualian yang tertulis jelas**: bila server menyediakan Safe Browsing dan operator mengizinkannya, tiap klik
  pemeriksaan mengirim ke Google hanya 4 byte awal hash alamat. Tautan VirusTotal dan Google Transparency Report membuka
  situs itu di tab baru, sehingga situs tersebut melihat nama domainnya.
- **Kunci hanya di server**: dibaca dari lingkungan saat berjalan, tidak ada di bundel, image Docker, atau kit.
- **Data sintetis**: nama, IP (RFC 5737/3849), domain (`.example`), dan hash semuanya fiktif.
- **Tanpa malware nyata**; sampel APK dibuat sendiri tanpa payload.

---

## ⚠️ Keterbatasan

SIGAP adalah alat bantu tanggap awal, bukan pengganti analis, EDR, atau SIEM.

- **Hanya sebatas log yang ada.** Pada Windows bawaan tanpa Sysmon dan tanpa audit proses, sebagian besar aturan
  Windows tidak punya data. Halaman **Cakupan Analisis** menunjukkannya, tetapi tidak bisa menciptakan log yang tidak
  pernah dicatat. Pasang Sysmon dan aktifkan audit **sebelum** terjadi insiden.
- **Belum diuji pada log satuan nyata.** Akurasi yang tampil dihitung pada skenario buatan. Tingkat alarm palsu pada
  jaringan nyata belum diketahui, dan aturan berbasis pola dapat dihindari penyerang yang mengenalnya.
- **Penilaian otomatis tetap perlu dikonfirmasi.** Skor mengurutkan penanganan, bukan menyatakan peluang.
- **Paket bukti bukan bukti forensik.** Log dikumpulkan dari komputer yang mungkin sudah disusupi, nama operator diisi
  sendiri, dan waktu berasal dari jam komputer. Tanda tangan menunjukkan perangkat asal paket, dan hanya berarti bila
  sidik jarinya dicocokkan lewat jalur lain. ZIP tidak terenkripsi. Untuk proses hukum atau disiplin, serahkan kepada
  pemeriksa forensik yang berwenang.
- **OT masih terbatas.** Hanya Modbus/TCP, perlu sensor Zeek pada port mirror, dan titik kendali harus diisi per
  pengendali. Aturan tidak mengenal perangkat yang tidak terhubung lewat IP. Rekonstruksi proses perlu plugin
  ICSNPP-Modbus (`modbus_detailed.log`), dan belum diuji pada PLC nyata: skenario contoh ditulis bersama mesinnya.
- **Rekonstruksi bukan pengukuran.** Nilainya adalah yang dilaporkan pengendali lewat jaringan, dan perubahan dari panel
  tidak meninggalkan perintah. Uji pemutusan hanya memakai jalur yang tercatat di log, jadi hasilnya perkiraan.
- **Pemeriksa APK hanya statis.** Skor rendah bukan berarti aman.
- **Daftar reputasi tidak lengkap.** Tidak tercantum di Safe Browsing atau daftar lokal bukan berarti aman. Google Safe
  Browsing hanya untuk pemakaian non-komersial.
- **Rilis aturan baru berarti membangun ulang aplikasi.** Belum ada saluran pembaruan aturan atau impor aturan Sigma
  komunitas saat aplikasi berjalan.
- **Satu browser, satu salinan data.** Kasus tidak terbagi otomatis, dan membersihkan data browser menghapusnya.

---

## 📦 Deployment

Bisa di-host di VPS dengan Docker, layanan statis, atau dibawa sebagai kit offline untuk jaringan air-gapped. **Wajib
HTTPS, kecuali di `localhost`**: lewat HTTP biasa, browser menonaktifkan fungsi hash sehingga impor gagal.

**Untuk log satuan yang sesungguhnya, pakai kit offline atau server internal satuan, bukan VPS komersial.** Log memang
tidak dikirim ke server, tetapi siapa pun yang menguasai server dapat mengganti kode yang berjalan di browser tiap
personel. Lihat panduan lengkap: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

```bash
npm run build:kit
```

```bash
docker build -t sigap .
```

```bash
docker run --rm -p 8080:8080 --env-file .env sigap
```

Buka http://localhost:8080. Tanpa `--env-file .env`, server berjalan tanpa Safe Browsing.

---

## 📜 Atribusi & lisensi

Aturan ditulis dengan format **Sigma** (SigmaHQ, DRL 1.1); pemetaan **MITRE ATT&CK®** milik
The MITRE Corporation. Daftar lengkap pustaka & lisensi: **[NOTICE.md](NOTICE.md)**.

Dibuat oleh **Tim Pengen Seblak** untuk Kartika Cyber Hackathon 2026.
