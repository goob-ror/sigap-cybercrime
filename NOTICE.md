# Atribusi (NOTICE)

SIGAP dibuat oleh **Tim Pengen Seblak** untuk Kartika Cyber Hackathon 2026
(PUSSIBERAD × CODEPOLITAN). Berikut pihak ketiga yang digunakan beserta lisensinya.

## Standar & kerangka kerja

- **Sigma** — format aturan deteksi (SigmaHQ, Detection Rule License 1.1). Aturan di
  `src/data/rules/*.yml` ditulis khusus untuk SIGAP mengikuti konvensi komunitas Sigma;
  tidak menyalin aturan komunitas.
- **MITRE ATT&CK®** dan **MITRE ATT&CK® for ICS** — © The MITRE Corporation, dipakai sesuai
  MITRE Terms of Use. ATT&CK adalah merek dagang terdaftar milik The MITRE Corporation.

## Pustaka perangkat lunak

| Pustaka | Kegunaan | Lisensi |
|---|---|---|
| React, React DOM | Antarmuka | MIT |
| Vite, @vitejs/plugin-react | Build tooling | MIT |
| Tailwind CSS, @tailwindcss/vite | Styling | MIT |
| Dexie, dexie-react-hooks | Penyimpanan IndexedDB | Apache-2.0 |
| js-yaml | Membaca aturan Sigma | MIT |
| @dagrejs/dagre | Tata letak graf | MIT |
| JSZip | Paket ZIP (ekspor) | MIT / GPLv3 |
| lucide-react | Ikon | ISC |
| @fontsource-variable/inter (font Inter) | Tipografi (self-hosted) | SIL Open Font License 1.1 |
| TypeScript, Vitest | Bahasa & pengujian | Apache-2.0 / MIT |

## Layanan pihak ketiga (opsional)

Hanya dipakai bila server diberi kunci dan operator mengizinkannya, atau bila operator menekan tautannya. Tidak ada
di kit offline. Setiap satuan memakai akun dan kuncinya sendiri, serta tunduk pada ketentuan layanan masing-masing.

- **Google Safe Browsing API** — pemeriksaan reputasi alamat, khusus pemakaian non-komersial. Advisory provided by
  Google: [lihat keterangan](https://developers.google.com/safe-browsing/v4/advisory). Google cannot guarantee that its
  information is comprehensive and error-free.
- **VirusTotal** dan **Google Transparency Report** — hanya tautan yang dibuka operator di tab baru. SIGAP tidak
  memanggil API-nya.
- **Daftar indikator** seperti URLhaus tidak disertakan. Satuan mengunduhnya sendiri sesuai lisensi sumbernya.

## Data

Seluruh data demo (skenario, nama, alamat IP, domain, hash) bersifat **sintetis dan fiktif**.
Alamat memakai rentang dokumentasi RFC 5737 (TEST-NET), RFC 3849 (IPv6), dan domain `.example`.
Tidak ada data pribadi nyata, tidak ada malware nyata.

## Bantuan AI

Sebagian kode, aturan, dan dokumentasi SIGAP dikembangkan dengan bantuan asisten AI (Claude Code, Anthropic).
