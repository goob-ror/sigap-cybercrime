# SIGAP Pos Jaga

> **Purwarupa.** Belum diuji pada lalu lintas produksi. Uji di server non-kritis terlebih dahulu.

Pos Jaga memakai mesin deteksi SIGAP di server: ia membaca log web dan log auth Linux **saat ditulis**, lalu
menampilkan peringatan selagi serangan berjalan, tanpa perlu mengunduh log ke laptop.

**Hanya membaca.** Pos Jaga tidak mengubah server, tidak memblokir apa pun, dan tidak mengirim data keluar.
Yang ditulisnya hanya folder datanya sendiri.

Hanya log **server** yang dibaca: untuk log Windows, pakai [pengumpul log](../collector/README.md).

## Memasang

Perlu Node.js 20 atau lebih baru di server. Tidak perlu `npm install` maupun internet, sebab semuanya ada dalam
satu berkas `pos-jaga.mjs`. Berkas itu ada di kit offline (`pos-jaga/`), atau buat sendiri:

```bash
npm run build:agent
```

Hasilnya `dist-agent/pos-jaga.mjs`. Salin ke server, misalnya ke `/opt/sigap/`.

## Mencoba dengan data fiktif

Di satu terminal, putar ulang log serangan fiktif:

```bash
node pos-jaga.mjs putar-ulang ./log-demo
```

Di terminal lain, jaga folder itu:

```bash
node pos-jaga.mjs jaga ./log-demo --data ./data-demo
```

Peringatan muncul selagi "serangan" berjalan. Hapus kedua folder itu setelah selesai.

## Perintah

| Perintah | Fungsi |
|---|---|
| `jaga <berkas\|folder>...` | Terus berjaga dan menampilkan peringatan. Berhenti dengan Ctrl+C |
| `periksa <berkas\|folder>...` | Membaca yang baru sekali lalu keluar, cocok untuk cron |
| `putar-ulang <folder>` | Demo: menulis log serangan fiktif secara bertahap |

Sebuah folder berarti semua berkas langsung di dalamnya, tidak termasuk subfolder dan berkas `.gz`.

| Pilihan | Bawaan | Arti |
|---|---|---|
| `--data <folder>` | `./sigap-pos-jaga` | Tempat posisi baca, jendela event, dan peringatan |
| `--host <nama>` | hostname | Nama server, untuk access log yang namanya tidak memuat host |
| `--tingkat <level>` | `high` | Tingkat minimum peringatan: `critical`, `high`, `medium`, `low` |
| `--interval <detik>` | 2 | Jeda antarpembacaan |
| `--dari-akhir` | mati | Berkas yang baru terlihat dibaca dari akhirnya, mengabaikan isi lama |
| `--profil <json>` | profil contoh | `profil-satuan.json` dari **SIGAP > Pengaturan** |

**Pakai `--profil` di server sungguhan.** Tanpa itu Pos Jaga memakai profil contoh fiktif. Profil yang tidak
valid ditolak saat mulai, disertai alasannya.

Pakai `--dari-akhir` saat pertama memasang di server yang lognya sudah besar, agar riwayat lama tidak
membanjiri layar dengan peringatan.

## Menjalankan sebagai layanan (systemd)

Pos Jaga perlu izin membaca log, tetapi tidak perlu root. Di Debian/Ubuntu, grup `adm` sudah cukup.

```bash
sudo useradd --system --no-create-home --groups adm sigap-jaga
```

```bash
sudo install -d -o sigap-jaga /var/lib/sigap-pos-jaga
```

Tulis ke `/etc/systemd/system/sigap-pos-jaga.service`:

```ini
[Unit]
Description=SIGAP Pos Jaga
After=network.target

[Service]
User=sigap-jaga
ExecStart=/usr/bin/node /opt/sigap/pos-jaga.mjs jaga /var/log/nginx /var/log/auth.log --data /var/lib/sigap-pos-jaga --profil /etc/sigap/profil-satuan.json --dari-akhir
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sigap-pos-jaga
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now sigap-pos-jaga
```

```bash
journalctl -u sigap-pos-jaga -f
```

## Yang ditulis ke folder data

| Berkas | Isi |
|---|---|
| `peringatan.jsonl` | Setiap temuan dan perkembangan insiden, satu JSON per baris. Mudah diteruskan ke alat lain |
| `ringkasan.json` | Keadaan terakhir: jumlah event, temuan, dan insiden aktif |
| `posisi.json` | Sampai mana tiap berkas sudah dibaca, sehingga aman dimulai ulang |
| `jendela.jsonl` | Event dalam jendela korelasi |

Folder ini dapat memuat alamat IP dan nama akun, jadi batasi aksesnya.

## Keterbatasan

- **Peringatan hanya tampil di terminal dan berkas.** Belum ada pengiriman ke WhatsApp, surel, atau server pusat,
  jadi seseorang harus memeriksanya atau meneruskan `peringatan.jsonl` sendiri.
- **Jendela korelasi 24 jam**, paling banyak 200.000 event di memori. Yang lebih lama dibuang dari jendela.
- **Berkas `.gz` dilewati**, karena isinya sudah terbaca sebelum dipadatkan. Untuk riwayat lama, pakai
  [Impor Data](PANDUAN_LOG_WEB.md).
- **Penyerang yang menguasai server dapat menghentikan atau mengelabui Pos Jaga**, sebab ia berjalan di server
  yang sama. Ia menambah visibilitas, bukan pengganti penyimpanan log terpusat.
- **Log auth tanpa tahun dan zona waktu** dibaca sebagai tahun berjalan dan WIB (+07:00).
