# Atribusi (NOTICE)

SIGAP dibuat oleh **Tim Pengen Seblak** untuk Kartika Cyber Hackathon 2026
(PUSSIBERAD × CODEPOLITAN). Berikut pihak ketiga yang digunakan beserta lisensinya.

## Standar & kerangka kerja

- **Sigma** — format aturan deteksi (SigmaHQ, Detection Rule License 1.1). Aturan di
  `src/data/rules/*.yml` ditulis sendiri oleh tim mengikuti konvensi komunitas Sigma;
  tidak menyertakan aturan komunitas apa pun.
- **MITRE ATT&CK®** dan **MITRE ATT&CK® for ICS** — © The MITRE Corporation, dipakai sesuai
  MITRE Terms of Use. ATT&CK adalah merek dagang terdaftar milik The MITRE Corporation.

## Pustaka perangkat lunak

| Pustaka | Kegunaan | Lisensi |
|---|---|---|
| React, React DOM | Antarmuka | MIT |
| Vite, @vitejs/plugin-react | Build tooling | MIT |
| Tailwind CSS, @tailwindcss/vite | Styling | MIT |
| Dexie | Penyimpanan IndexedDB | Apache-2.0 |
| @dagrejs/dagre | Tata letak graf | MIT |
| JSZip | Paket ZIP (ekspor) | MIT / GPLv3 |
| lucide-react | Ikon | ISC |
| @fontsource-variable/inter (font Inter) | Tipografi (self-hosted) | SIL Open Font License 1.1 |
| TypeScript, Vitest | Bahasa & pengujian | Apache-2.0 / MIT |

## Data

Seluruh data demo (skenario, nama, alamat IP, domain, hash) bersifat **sintetis dan fiktif**.
Alamat memakai rentang dokumentasi RFC 5737 (TEST-NET), RFC 3849 (IPv6), dan domain `.example`.
Tidak ada data pribadi nyata, tidak ada malware nyata.
