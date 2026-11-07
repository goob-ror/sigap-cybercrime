# Panduan Mengambil Log Server Web dan Linux

SIGAP membaca **access log web** (format *combined* atau *common*, dipakai Apache, Nginx, LiteSpeed, cPanel,
dan Plesk) dan **log auth Linux**. Berkas `.gz` tidak perlu dibongkar, dan beberapa berkas boleh dijadikan satu ZIP.

Selalu **salin** log, jangan memindahkannya, dan jangan mengeditnya: SIGAP mencatat SHA-256 berkas sebagai bukti.

## Beri nama berkas sesuai servernya

Access log tidak mencatat nama server, jadi SIGAP mengambilnya dari **nama berkas**. Nama ini yang mengaitkan
serangan web dengan aktivitas lain di server yang sama.

| Nama berkas | Dikenali sebagai |
|---|---|
| `web-satuan-01-access.log` | `WEB-SATUAN-01` |
| `web-satuan-01-nginx-access.log.2.gz` | `WEB-SATUAN-01` |
| `access.log` | Tidak ada nama server. Ganti namanya dahulu |

## VPS atau server sendiri

Sambil masuk lewat SSH, kumpulkan salinan ke satu folder. Ganti `web-satuan-01` dengan nama server Anda.

```bash
mkdir -p ~/sigap-log
```

**Nginx:**

```bash
sudo sh -c 'for f in /var/log/nginx/access.log*; do cp "$f" "$1/web-satuan-01-nginx-$(basename "$f")"; done' _ ~/sigap-log
```

**Apache (Debian/Ubuntu: `/var/log/apache2/`, RHEL/AlmaLinux: `/var/log/httpd/`, lalu sesuaikan nama berkasnya):**

```bash
sudo sh -c 'for f in /var/log/apache2/access.log*; do cp "$f" "$1/web-satuan-01-apache-$(basename "$f")"; done' _ ~/sigap-log
```

**Login SSH dan sudo (Debian/Ubuntu: `/var/log/auth.log`, RHEL/AlmaLinux/cPanel: `/var/log/secure`):**

```bash
sudo sh -c 'for f in /var/log/auth.log*; do cp "$f" "$1/web-satuan-01-$(basename "$f")"; done' _ ~/sigap-log
```

Lalu jadikan milik Anda, buat ZIP, dan catat SHA-256-nya:

```bash
sudo chown -R "$USER" ~/sigap-log && cd ~/sigap-log && zip -r ~/sigap-log.zip . && sha256sum ~/sigap-log.zip
```

Unduh `sigap-log.zip` ke laptop (misalnya dengan `scp`), lalu tarik ke **SIGAP > Impor Data**.

## cPanel

**Tanpa akses root:** buka **Metrics > Raw Access**, lalu unduh arsip tiap domain (`.gz`). Bila ada pilihan
"Archive logs in your home directory", aktifkan agar riwayat yang lebih lama tersimpan.

**Dengan akses root/SSH:** log per domain ada di `/usr/local/apache/domlogs/` atau `/etc/apache2/logs/domlogs/`.

Nama berkas Raw Access memuat nama domain, misalnya `portal.satuan.example-Nov-2026.gz`, dan SIGAP memakainya
sebagai nama server.

## Plesk

Buka **Websites & Domains > Logs** dan unduh berkasnya. Lewat SSH, log ada di
`/var/www/vhosts/system/<domain>/logs/` (`access_log`, `access_ssl_log`, dan rotasinya). Ganti namanya agar
memuat nama server, misalnya `web-satuan-01-access_ssl_log`.

## Hal yang perlu diperhatikan

- **Tahun dan zona waktu.** Log auth Linux klasik tidak mencatat tahun ataupun zona waktu, jadi SIGAP memakai
  tahun berjalan dan **WIB (+07:00)**. Untuk server di WITA, WIT, atau UTC, jam yang tampil akan bergeser;
  access log web tidak terpengaruh karena mencatat zona waktunya sendiri.
- **Rotasi.** Log lama sering dipadatkan (`access.log.2.gz`) dan dihapus setelah beberapa minggu. Salin
  secepatnya setelah insiden diketahui, termasuk berkas rotasinya.
- **Format khusus.** Bila server memakai `log_format` buatan sendiri, baris yang tidak cocok dihitung sebagai
  "gagal" di halaman Impor Data. Periksa jumlahnya: temuan dari log yang sebagian gagal terbaca tidak lengkap.
- **Berkas yang sama diimpor dua kali** tidak menggandakan data, sebab dikenali dari SHA-256-nya.

Untuk memantau log server terus-menerus tanpa mengunduhnya, lihat [POS_JAGA.md](POS_JAGA.md).
