# Pengumpul Log Windows

Mengambil log peristiwa dari sebuah komputer Windows dan menyimpannya sebagai satu ZIP yang dapat
langsung diimpor ke SIGAP. Perlu Windows PowerShell 5.1 (bawaan Windows 10/11 dan Server 2016 ke atas).

**Hanya membaca.** Skrip tidak mengubah atau menghapus log, tidak mengubah kebijakan audit, tidak memasang
apa pun, dan tidak membuat koneksi jaringan. Satu-satunya yang ditulis adalah ZIP hasilnya.

## Pemakaian

1. Salin folder ini ke komputer yang diperiksa, misalnya dari USB.
2. Klik kanan **`Kumpulkan-Log.cmd`**, lalu pilih **Run as administrator**.
3. Tunggu sampai selesai. ZIP tersimpan di Desktop dan SHA-256-nya tampil di layar.
4. Catat SHA-256 itu pada berita acara, lalu pindahkan ZIP dengan USB.
5. Di SIGAP, buka **Impor Data** dan tarik ZIP ke halaman itu. Tidak perlu dibongkar.

> **Jalankan sebagai Administrator.** Tanpa itu log Security tidak terbaca, sehingga logon, pembuatan akun,
> dan pembuatan proses tidak terlihat di SIGAP. Skrip memperingatkan bila hasilnya tidak lengkap, dan SIGAP mencantumkan
> log yang tidak terbaca di **Cakupan Analisis** setelah ZIP diimpor.

Komputernya mati atau tidak boleh dijalankan skrip? Salin berkas `.evtx` dari `C:\Windows\System32\winevt\Logs`
(mis. dari disk yang dilepas) dan impor langsung ke SIGAP. Tidak perlu konversi.

Lewat PowerShell, dengan pilihan tambahan:

```powershell
powershell -ExecutionPolicy Bypass -File .\sigap-collect.ps1 -Days 30 -MaxEvents 50000 -OutputDir E:\bukti
```

| Pilihan | Bawaan | Arti |
|---|---|---|
| `-Days` | 7 | Rentang waktu yang diambil |
| `-MaxEvents` | 20000 | Batas per log, yang terbaru lebih dahulu. Skrip memberi tahu bila batas tercapai |
| `-OutputDir` | Desktop | Folder hasil, boleh USB |
| `-Channels` | lihat di bawah | Log yang diambil |

`-ExecutionPolicy Bypass` hanya berlaku untuk proses itu; pengaturan Windows tidak berubah.

## Log yang diambil

| Log | Untuk mendeteksi |
|---|---|
| `Security` | Logon, pembuatan akun, proses (4688), penghapusan log |
| `System` | Pemasangan layanan |
| `Microsoft-Windows-Sysmon/Operational` | Proses, koneksi, DNS, berkas (bila Sysmon terpasang) |
| `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell` | Skrip PowerShell |
| `Microsoft-Windows-Windows Defender/Operational` | Temuan dan perubahan Defender |
| `Microsoft-Windows-TaskScheduler/Operational` | Tugas terjadwal (sering nonaktif secara bawaan) |

Log yang tidak ada di komputer itu dilewati. Skrip **tidak** menyalakan audit yang nonaktif: bila baris
perintah proses (4688) atau Sysmon belum aktif sebelum kejadian, jejak itu memang tidak ada.

## Isi ZIP

| Berkas | Isi |
|---|---|
| `<nama-log>.json` | Satu berkas per log, dengan kolom bernama dari XML tiap peristiwa |
| `info-pengumpulan.json` | Komputer, akun yang menjalankan, waktu, dan status tiap log. SIGAP membacanya saat impor |
| `MANIFEST-SHA256.txt` | SHA-256 berkas-berkas di atas |

Saat mengimpor, SIGAP mencocokkan isi ZIP dengan manifest dan **menolak** ZIP bila ada berkas yang berubah,
hilang, atau tambahan. Manifest membuktikan isi tidak berubah sejak ZIP dibuat hanya bila SHA-256 ZIP dicatat
terpisah, karena pihak yang mengubah isi juga dapat menulis ulang manifest. Karena itu catat SHA-256 ZIP dari
layar (atau dari berkas `.sha256` di sebelah ZIP) pada berita acara.

## Catatan

- Log dapat memuat nama akun, nama komputer, dan isi skrip. Perlakukan ZIP sebagai data sensitif.
- Pesan peristiwa dipotong sampai 1.000 karakter agar ukuran terkendali; kolom di `EventData` tetap utuh.
- Untuk server web dan Linux, lihat [`docs/PANDUAN_LOG_WEB.md`](../docs/PANDUAN_LOG_WEB.md).
