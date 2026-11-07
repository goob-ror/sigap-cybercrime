# Panduan Deployment

Server SIGAP hanya mengirim berkas aplikasi, ditambah API kecil bila [Google Safe Browsing](#google-safe-browsing-opsional) dipakai.
Log dan kasus diproses dan disimpan di browser tiap personel (IndexedDB), dan tidak pernah sampai ke server. Akibatnya:

- Server tidak perlu basis data, dan tidak ada data kasus yang perlu dicadangkan di sana.
- Kasus tidak otomatis terbagi antarpersonel. Berbagi dilakukan dengan **paket bukti** (Laporan > Paket Bukti).
- Membersihkan data browser menghapus kasus di browser itu. Mengganti domain membuat data lama tertinggal di
  alamat lama, jadi **pilih domain final sebelum dipakai**.

| Cara | Cocok untuk | Syarat |
|---|---|---|
| [Kit offline](#kit-offline) | **Log satuan yang sesungguhnya**, air-gapped, atau cadangan saat server tidak terjangkau | Windows atau Python 3 |
| [VPS](#vps-dengan-https) | Demo dan latihan dengan data contoh. Untuk log nyata hanya bila servernya milik dan dikelola satuan | Domain, Docker |
| [Hosting statis](#hosting-statis-lain) | Demo tanpa mengelola server | Layanan dengan HTTPS |

> **HTTPS wajib, kecuali di `localhost`.** Lewat `http://<ip>` halaman tetap terbuka, tetapi browser
> menonaktifkan fungsi hash sehingga setiap impor gagal. SIGAP menampilkan peringatan bila dibuka seperti itu.

> **Jangan memproses log satuan lewat VPS komersial.** Log memang tidak dikirim ke server, tetapi server menentukan
> kode yang berjalan di browser. Siapa pun yang menguasai server atau penyedianya dapat menyajikan kode yang mengirim
> log kembali ke server yang sama (CSP `connect-src 'self'` tidak menghalangi ini), dan service worker menyimpan kode
> itu di browser. Pakai kit offline yang SHA-256-nya diperiksa, atau server internal satuan.

## VPS dengan HTTPS

Langkah untuk Ubuntu/Debian. Arahkan domain ke alamat IP VPS terlebih dahulu. Di bawah ini ganti
`sigap.example.id` dengan domain Anda.

**1. Bangun dan jalankan aplikasi.** Port 8080 sengaja hanya terbuka untuk VPS itu sendiri, karena port yang
diterbitkan Docker dapat melewati `ufw`.

```bash
sudo apt update && sudo apt install -y docker.io git
```

```bash
git clone https://github.com/goob-ror/sigap-cybercrime.git && cd sigap-cybercrime
```

```bash
sudo docker build -t sigap .
```

```bash
sudo docker run -d --name sigap --restart unless-stopped --read-only --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:8080:8080 sigap
```

Perintah ini berjalan tanpa Safe Browsing. Untuk memakainya, lihat [Google Safe Browsing](#google-safe-browsing-opsional).
Opsi `--read-only`, `--cap-drop ALL`, dan `no-new-privileges` melarang kontainer menulis berkas atau menaikkan haknya.
SIGAP tidak membutuhkan keduanya, jadi bila server web itu disusupi, penyerang lebih sulit menetap di dalamnya.

Untuk mencoba sebelum domain siap, buat terowongan dari laptop Anda, lalu buka `http://localhost:8080`. Tanpa HTTPS,
hanya `localhost` yang membuat impor berjalan.

```bash
ssh -L 8080:127.0.0.1:8080 pengguna@alamat-vps
```

**2. Pasang HTTPS dan kata sandi dengan Caddy.** Ikuti [panduan pemasangan Caddy](https://caddyserver.com/docs/install#debian-ubuntu-raspbian),
sebab paket bawaan Ubuntu dapat terlalu lama untuk konfigurasi di bawah. Sertifikat HTTPS diurus otomatis.

```bash
caddy hash-password
```

Tulis ke `/etc/caddy/Caddyfile`:

```
sigap.example.id {
    basic_auth {
        personel <tempel-hash-di-sini>
    }
    reverse_proxy 127.0.0.1:8080
}
```

```bash
sudo systemctl reload caddy
```

**3. Buka hanya port yang diperlukan.**

```bash
sudo ufw allow OpenSSH && sudo ufw allow 80,443/tcp && sudo ufw enable
```

**4. Periksa.** Buka `https://sigap.example.id`, lalu **Impor Data > Muat skenario contoh**. Hasilnya harus
`2 insiden · 41 temuan dari 6.296 event`, dan halaman **Lintas IT-OT** menunjukkan jendela respons 19 menit serta
setpoint di luar batas selama 3 jam 29 menit. Bersihkan dengan **Hapus data lokal**.

### Memperbarui

Dari folder `sigap-cybercrime`:

```bash
git pull && sudo docker build -t sigap . && sudo docker rm -f sigap && sudo docker run -d --name sigap --restart unless-stopped --read-only --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:8080:8080 sigap
```

Tambahkan `--env-file .env` sebelum `sigap` yang terakhir bila Safe Browsing dipakai.

Kasus di browser personel tidak terpengaruh. Versi baru aktif saat halaman dibuka lagi.

### Google Safe Browsing (opsional)

Pemeriksaan ini berjalan lewat server, sehingga kunci tidak pernah sampai ke browser. Tanpa kunci, pemeriksaan ini
tidak muncul dan semua yang lain tetap berjalan.

**1. Buat `.env` di folder `sigap-cybercrime`**, dari `.env.example`, lalu batasi aksesnya. Berkas ini tidak ikut ke
git atau ke image Docker.

```bash
cp .env.example .env && chmod 600 .env
```

**2. Jalankan dengan kuncinya.**

```bash
sudo docker rm -f sigap; sudo docker run -d --name sigap --restart unless-stopped --read-only --cap-drop ALL --security-opt no-new-privileges --env-file .env -p 127.0.0.1:8080:8080 sigap
```

**3. Izinkan di tiap browser**, lewat **Pengaturan > Layanan Online**. Bawaannya mati. Setelah diizinkan pun tidak ada
yang terkirim sampai operator menekan tombol pemeriksaan.

Sebelum memakainya, perhatikan:

- **Hanya untuk pemakaian non-komersial.** Peringatannya wajib tampil dengan kata-kata dan atribusi yang sudah diatur
  SIGAP; jangan mengubahnya.
- **Batasi kuncinya di Google Cloud Console:** hanya untuk Safe Browsing API, dan hanya dari alamat IP VPS. Jangan
  memakai pembatasan HTTP referrer, karena permintaannya datang dari server, bukan browser.
- **Tetap pasang kata sandi Caddy.** API menolak permintaan dari situs lain dan membatasi pemakaian per jam
  (`SAFE_BROWSING_LIMIT_PER_HOUR`), tetapi tanpa kata sandi siapa pun yang tahu alamatnya dapat menghabiskan kuota itu.
- **Reverse proxy lain harus meneruskan header `Host`.** Caddy melakukannya otomatis. Tanpa itu, API menolak permintaan
  dengan status 403. Pada nginx, tambahkan `proxy_set_header Host $host;`.

Untuk `nginx.conf` dan hosting statis, `/api/` tidak ada, sehingga pemeriksaan ini tidak muncul.

### Kata sandi dan VPN

Kata sandi Caddy adalah satu kata sandi bersama: ia membatasi siapa yang dapat mengunduh aplikasi, tetapi tidak
mengenali individu, dan nama operator di SIGAP tetap diisi sendiri. Bila satuan punya VPN (WireGuard, Tailscale),
sajikan SIGAP hanya lewat VPN itu dan kata sandi tidak lagi diperlukan.

### Bila server tidak terjangkau

Setelah pernah dibuka sekali, browser menyimpan salinan aplikasi, sehingga SIGAP dan kasus di dalamnya tetap
terbuka saat VPS atau internet mati. Yang tidak berfungsi hanya pembaruan versi. Komputer yang **belum pernah**
membukanya memerlukan kit offline. Statusnya terlihat di **Pengaturan > Pemakaian Offline**.

## Kit offline

Satu ZIP berisi aplikasi, peluncur, pengumpul log, panduan, dan Pos Jaga, tanpa perlu internet. Skrip latihan sisi
penyerang (`tools/sigap-drill.ps1`) sengaja tidak disertakan.

```bash
npm ci
```

```bash
npm run build:kit
```

Hasilnya `dist-kit/sigap-kit.zip` beserta berkas `.sha256`. Image Docker di atas juga menyajikannya, dengan tombol
unduh di **Pengaturan > Pemakaian Offline**.

Personel membongkarnya, lalu menjalankan `Buka-SIGAP.cmd` di Windows atau `sh buka-sigap.sh` di Linux/macOS (perlu
Python 3). SIGAP terbuka di jendelanya sendiri lewat Edge atau Chrome bila ada, di `http://localhost:48173`; petunjuk lengkapnya ada di `README-KIT.txt` dalam ZIP.

Kit tidak memuat kunci, server, atau Safe Browsing, dan seluruh analisisnya berjalan tanpa internet. Mode Latihan tetap
tersedia. Reputasi alamat dilakukan dengan daftar indikator lokal, yang diimpor di **Pengaturan**.

- **Berikan SHA-256 lewat jalur terpisah** dari ZIP-nya, agar penerima dapat memastikan kitnya tidak diubah.
- **Data tersimpan di browser komputer itu, bukan di USB.** Port peluncur sengaja tetap, sebab port lain akan
  tampak seperti SIGAP yang kosong. Jangan mengubah `-Port` bila sudah ada kasus tersimpan.
- `app/index.html` tidak dapat dibuka langsung dari folder, karena browser menolaknya di `file://`.
- Kit dan VPS adalah alamat berbeda, jadi datanya pun terpisah. Pindahkan kasus dengan paket bukti.

## Hosting statis lain

Hasil `npm run build` di folder `dist/` dapat disajikan layanan statis apa pun yang punya HTTPS, termasuk dari
subfolder. Jalankan `npm run build:kit` bila kit ingin ikut tersedia. Pastikan `sw.js` tidak di-cache lama oleh CDN,
agar versi baru sampai ke browser.

## Menyiapkan satuan

1. **Isi profil jaringan** di **Pengaturan**: segmen OT, host yang boleh mengirim perintah Modbus, ambang unggahan,
   aset, domain milik satuan, titik kendali genset, dan penandaan laporan. Tanpa ini lencana **PROFIL CONTOH** tetap
   tampil dan aturan OT menilai host berdasarkan alamat fiktif. Untuk halaman **Lintas IT-OT**, isi juga register status
   RUN dan register yang dipantau, misalnya `1=Tegangan keluaran (V)`, dan impor `modbus_detailed.log` dari plugin
   ICSNPP-Modbus pada Zeek. Tanpa plugin itu, hanya siapa yang berbicara dengan perangkat OT yang terlihat.
2. **Ekspor profil** ke `profil-satuan.json`, lalu bagikan lewat jalur yang aman: berkas ini adalah peta jaringan
   satuan. Tiap personel memuatnya sekali lewat **Muat dari JSON**, sebab profil tersimpan per browser dan server tidak
   dapat mendorongnya.
3. **Nyalakan log sebelum dibutuhkan.** Pasang Sysmon, atau aktifkan "Audit Process Creation" dan "Include command
   line in process creation events" lewat Group Policy. Tanpa itu sebagian besar aturan Windows tidak punya data, dan
   log yang tidak pernah dicatat tidak dapat dipulihkan saat insiden. Periksa hasilnya di **Cakupan Analisis**.
4. **Daftarkan sidik jari kunci.** Tiap browser punya kunci tanda tangan sendiri (**Pengaturan**). Catat sidik jarinya
   pada berita acara dan serahkan kepada penerima paket bukti, sebelum terjadi insiden.
5. **Berikan kepada personel:** kit offline atau alamat HTTPS, kata sandi bila dipakai, dan pengumpul log
   (`collector/`, juga ada di dalam kit).
6. **Latih satu putaran** dengan skenario contoh sebelum dipakai pada insiden nyata.

## Tanpa Docker

Dengan Node.js 22 atau lebih baru, jalankan `npm run build:kit`, lalu `npm run serve`. Server membaca `.env` bila ada,
dan mendengarkan di port 8080 (`PORT`). Letakkan HTTPS di depannya.

Bila memakai nginx langsung, salin `dist/` ke server dan pakai `nginx.conf` dari repositori ini sebagai `server` block.
Cara ini tanpa Safe Browsing. HTTPS tetap perlu dipasang, misalnya dengan Certbot.
