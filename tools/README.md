# Latihan dua laptop (serang → pertahankan)

Alat bantu untuk mendemonstrasikan SIGAP dengan log Windows yang **benar-benar
terjadi**, bukan hanya data skenario bawaan.

- **Laptop penyerang** menjalankan `sigap-drill.ps1`: menghasilkan jejak log
  Windows yang nyata lewat aksi-aksi **benign** (tidak merusak, lokal, reversible).
- **Laptop pertahanan** menjalankan **SIGAP**: mengimpor log tersebut lalu
  mendeteksi, mengaitkan, memberi skor, dan menyusun laporan.

Arah datanya satu arah: log berpindah dari laptop penyerang ke laptop
pertahanan lewat USB (tetap offline). SIGAP-lah pihak yang "bertahan"; tidak ada
skrip pertahanan terpisah, karena itu justru pekerjaan SIGAP.

```
  [Laptop A — penyerang]            USB            [Laptop B — pertahanan]
  sigap-drill.ps1  ──►  log-latihan.json  ──►  Impor ke SIGAP ──► deteksi+laporan
```

> Satu laptop pun cukup: jalankan drill, ekspor log, lalu impor ke SIGAP di
> mesin yang sama. Dua laptop hanya membuat ceritanya lebih hidup saat demo.

---

## Yang dilakukan `sigap-drill.ps1`

Setiap aksi menghasilkan peristiwa Windows **asli** (ditulis auditing Windows /
Sysmon), yang masing-masing memicu satu aturan SIGAP:

| Aksi      | Peristiwa          | Aturan SIGAP yang menyala            |
|-----------|--------------------|--------------------------------------|
| `akun`    | 4720               | Akun lokal/domain baru dibuat        |
| `logon`   | 4625 ×6            | Rentetan logon gagal (brute force)   |
| `layanan` | 7045               | Layanan PsExec/mencurigakan dipasang |
| `encoded` | 4688 / Sysmon 1    | PowerShell dengan perintah ter-encode|
| `schtask` | 4688 / 4698        | Tugas terjadwal dibuat               |
| `archive` | 4688 (perlu 7-Zip) | Arsip terenkripsi dibuat             |

Semua objek dummy diberi tanda **`SIGAP-DRILL`** dan dibuat oleh skrip sendiri,
sehingga `-Cleanup` dapat menghapusnya dengan pasti.

### Sengaja TIDAK dilakukan

Beberapa aturan SIGAP mendeteksi teknik yang benar-benar berbahaya kalau
dijalankan sungguhan. Ini **tidak** ada di skrip latihan — hanya muncul di
skenario sintetis bawaan SIGAP:

- Dump memori LSASS (`comsvcs MiniDump`) — benar-benar mencuri kredensial
- Mematikan Microsoft Defender — penurunan keamanan nyata
- Menghapus Event Log (1102 / 104) — memusnahkan barang bukti
- `certutil` / koneksi keluar — memerlukan jaringan nyata

---

## Langkah demo

Jalankan **sebagai Administrator** di laptop latihan/lab Anda sendiri.

1. **(Sekali saja) aktifkan audit proses**, agar aksi berbasis proses tercatat
   bila Sysmon belum terpasang:
   ```powershell
   .\sigap-drill.ps1 -EnableAudit -Yes
   ```
2. **Jalankan latihan:**
   ```powershell
   .\sigap-drill.ps1
   ```
   atau sebagian: `.\sigap-drill.ps1 -Only akun,logon,layanan`
3. **Ekspor log** ke JSON (format yang sama dengan yang diterima SIGAP):
   ```powershell
   Get-WinEvent -LogName Security,System,'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5000 -ErrorAction SilentlyContinue | ConvertTo-Json | Out-File log-latihan.json
   ```
4. **Pindahkan** `log-latihan.json` ke laptop pertahanan lewat USB.
5. **Impor** berkas itu di halaman **Impor Data** SIGAP, lalu buka **Ringkasan**,
   **Graf Investigasi**, **Kasus**, dan **Laporan**.
6. **Bersihkan** objek dummy (dan kembalikan konfigurasi audit):
   ```powershell
   .\sigap-drill.ps1 -Cleanup
   ```

Log peristiwa tidak ikut dihapus pada `-Cleanup` — log itu justru barang bukti
yang diimpor ke SIGAP.

---

## Catatan

- Perlu Windows PowerShell 5.1+ dan hak Administrator untuk aksi `akun`,
  `layanan`, dan `-EnableAudit`.
- Skrip menolak berjalan di Domain Controller dan meminta konfirmasi (lewati
  dengan `-Yes`).
- Tanpa Sysmon maupun audit proses, aksi `encoded` / `schtask` / `archive` bisa
  tidak tercatat; `akun` (4720), `logon` (4625), dan `layanan` (7045) tetap
  tercatat karena memakai log Security/System bawaan.
- `collector/sigap-collect.ps1` (sisi pertahanan, pengekspor log read-only)
  menyusul di Fase 3.
