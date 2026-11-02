<p align="center">
  <img src="public/favicon.svg" width="76" alt="Logo SIGAP" />
</p>

<h1 align="center">SIGAP</h1>

<p align="center">
  <b>Sistem Investigasi &amp; Penanganan Awal Insiden Siber Satuan</b><br/>
  Perangkat tanggap awal insiden siber yang berjalan <b>offline</b>, untuk satuan TNI AD tanpa analis khusus.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Offline--first-100%25-22c55e" alt="Offline-first" />
  <img src="https://img.shields.io/badge/kategori-Penangkalan-f59e0b" alt="Penangkalan" />
  <img src="https://img.shields.io/badge/tes-97%20lulus-38bdf8" alt="97 tests" />
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

1. **Impor log** dari PC Windows, firewall, sensor jaringan, dan pengendali OT (genset/PLC).
2. **Deteksi** aktivitas berbahaya dengan 24 aturan (Sigma + agregasi), lintas IT dan OT.
3. **Korelasi** semua temuan menjadi satu **insiden** berskor, lengkap dengan cerita & graf.
4. **Respons** dengan playbook Bahasa Indonesia dan daftar blokir IOC untuk firewall/DNS.
5. **Laporan & bukti**: laporan siap cetak + paket bukti tahan-rusak untuk eskalasi ke PUSSIBERAD.

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

<p align="center"><img src="docs/screenshots/playbook.jpg" width="80%" alt="Playbook penanganan" /></p>

---

## ✨ Fitur

- 📥 **Impor fleksibel** — log Windows (Sysmon/Security/System/PowerShell), ekspor PowerShell
  (`Get-WinEvent`/`Get-EventLog`), Winlogbeat, evtx_dump, EvtxECmd, firewall (key=value), Zeek
  (conn/dns/modbus). Deteksi BOM & UTF-16/UTF-8 otomatis.
- 🔍 **Deteksi** — 24 aturan: 21 bergaya **Sigma** (ditulis sendiri) + 3 aturan agregasi
  (rentetan logon gagal, unggahan besar, pemindaian Modbus). Dipetakan ke **MITRE ATT&CK** &
  **ATT&CK for ICS**.
- 🧩 **Korelasi** — temuan yang berbagi entitas dalam 24 jam digabung menjadi satu insiden,
  dengan skor yang dapat dijelaskan `1 − Π(1 − bobot)` + bonus kill-chain & multi-sumber.
- 📊 **Ringkasan & graf** — cerita insiden urut waktu, aksi prioritas, dan graf entitas (dagre).
- 🗂️ **Kasus** — satu kasus per insiden: status, petugas, catatan, tindak lanjut, riwayat.
- 🩺 **Triase** — analisis URL (heuristik struktural), pencocokan IOC terhadap log, dan
  **pemeriksa APK** (mengurai `AndroidManifest.xml` biner untuk membaca izin & paket, tanpa menjalankan).
- 📒 **Playbook** — 6 panduan respons Bahasa (fase pra/saat/pasca) yang **direkomendasikan otomatis**
  per insiden; langkah dapat dicentang dan tersimpan di kasus.
- 🚫 **Ekspor daftar blokir IOC** — IP/domain/hash eksternal untuk diterapkan ke firewall/DNS.
- 📝 **Laporan** — disusun otomatis dari data kasus; cetak/simpan sebagai PDF.
- 🔐 **Paket bukti** — ZIP tahan-rusak (laporan HTML, JSON, berkas asli, rantai bukti berantai-hash,
  MANIFEST SHA-256) + **verifikator** bawaan.
- 📴 **Offline-first** — tidak ada permintaan ke luar; CSP `connect-src 'self'` pada build produksi.

---

## 🚀 Menjalankan (pengembangan)

Butuh **Node.js 20+**.

```bash
npm install
npm run dev
```

Buka http://localhost:5173, lalu **Impor Data → Muat skenario contoh** untuk mencoba alur lengkap
dengan satu serangan IT→OT fiktif (4.650 event → 24 temuan → 1 insiden berskor 99%).

| Perintah | Fungsi |
|---|---|
| `npm run dev` | Server pengembangan di :5173 |
| `npm run build` | Typecheck + build produksi ke `dist/` |
| `npm run preview` | Menyajikan hasil build |
| `npm test` | 97 tes unit (Vitest) |
| `npm run typecheck` | `tsc --noEmit` |

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

Plain **React 19 + Vite + Tailwind v4 + TypeScript**, tanpa backend.

- `src/core/` — mesin murni (tanpa React), teruji unit: `ingest/` (parser), `detect/` (Sigma +
  native), `correlate/` (insiden, skor, kasus), `report/` (narasi, IOC), `triage/` (URL/IOC/AXML),
  `evidence/` (hash, rantai bukti, paket).
- `src/workers/ingest.worker.ts` — pipeline impor → deteksi → korelasi di luar thread UI.
- `src/db/` — Dexie (IndexedDB): event, temuan, insiden, kasus, artefak, blob asli, rantai bukti.
- `src/features/<halaman>/` — satu folder per layar · `src/components/ui/` — komponen bersama.
- `src/data/` — rule pack, katalog ATT&CK, profil unit, generator skenario, playbook, sampel APK.

Detail & peta jalan: [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md).

---

## 🔒 Keamanan & privasi

- **Offline-first**: tak ada request ke host eksternal; font Inter di-host sendiri.
- **Tidak ada data yang keluar**: semua tersimpan di IndexedDB browser pengguna.
- **Data sintetis**: nama, IP (RFC 5737/3849), domain (`.example`), dan hash semuanya fiktif.
- **Tanpa malware nyata**; sampel APK dibuat sendiri tanpa payload.

---

## 📦 Deployment

Build statis — bisa di-host di layanan statis, Docker (nginx), atau USB air-gapped.
Lihat panduan lengkap: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

```bash
npm run build          # -> dist/
docker build -t sigap . && docker run --rm -p 8080:80 sigap
```

---

## 📜 Atribusi & lisensi

Aturan ditulis dengan format **Sigma** (SigmaHQ, DRL 1.1); pemetaan **MITRE ATT&CK®** milik
The MITRE Corporation. Daftar lengkap pustaka & lisensi: **[NOTICE.md](NOTICE.md)**.

Dibuat oleh **Tim Pengen Seblak** untuk Kartika Cyber Hackathon 2026.
