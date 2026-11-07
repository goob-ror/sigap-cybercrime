SIGAP - Kit Offline
===================

Kit ini berjalan tanpa internet dan tanpa server. Pakai bila komputer tidak dapat
menghubungi server SIGAP, atau untuk jaringan yang terputus dari luar.

MEMBUKA SIGAP
-------------
1. Bongkar seluruh ZIP ini ke sebuah folder. Jangan dijalankan dari dalam ZIP.
2. Windows: klik dua kali Buka-SIGAP.cmd
   Linux/macOS: jalankan  sh buka-sigap.sh  (perlu Python 3)
3. SIGAP terbuka di jendelanya sendiri, memakai Edge atau Chrome bila ada, atau di browser
   biasa bila tidak ada. Alamatnya http://localhost:48173
4. Biarkan jendela hitam tetap terbuka selama memakai SIGAP.

Agar punya ikon sendiri: Pengaturan > Aplikasi dan Pemakaian Offline, atau menu browser > Pasang.

Jangan membuka app/index.html langsung dari folder: browser akan menolaknya.

Bila Windows SmartScreen memperingatkan: pastikan kit berasal dari sumber resmi satuan
Anda dan cocok dengan SHA-256 yang diberikan bersamanya.

PENTING: DI MANA DATA TERSIMPAN
-------------------------------
Log dan kasus tersimpan di browser komputer ini, BUKAN di folder kit atau USB.
- Memindahkan USB ke komputer lain tidak membawa kasusnya. Pindahkan kasus dengan paket
  bukti (halaman Laporan > Paket Bukti).
- Membersihkan data browser menghapus kasusnya.
- Browser yang berbeda punya data yang berbeda.

SEBELUM MEMAKAI LOG NYATA
-------------------------
Buka Pengaturan dan isi profil jaringan satuan, atau muat profil-satuan.json dari admin
satuan Anda. Selama lencana PROFIL CONTOH tampil, aturan OT menilai host berdasarkan
alamat fiktif.

ISI KIT
-------
app/            Aplikasi SIGAP.
pengumpul-log/  Pengumpul log Windows yang hanya membaca. Lihat README.md di dalamnya.
                Klik kanan Kumpulkan-Log.cmd > Run as administrator, lalu tarik ZIP
                hasilnya ke SIGAP > Impor Data.
panduan/        Cara mengambil log server web dan Linux.
pos-jaga/       Pemantau log server terus-menerus (purwarupa; perlu Node.js 20+).
                Lihat POS_JAGA.md di dalamnya.

LINTAS IT-OT, LATIHAN, DAN REPUTASI ALAMAT
------------------------------------------
Halaman Lintas IT-OT menunjukkan apa yang terjadi pada peralatan dari lalu lintas Modbus, dan
titik mana yang bisa memutus serangan. Perlu log Zeek modbus_detailed dari plugin ICSNPP-Modbus.
Halaman Latihan melatih personel dengan soal dari insiden yang ada di SIGAP.
Untuk memeriksa alamat berbahaya tanpa internet, impor daftar indikator di Pengaturan. Unduh
daftarnya dari komputer yang terhubung, sesuai lisensi sumbernya, lalu bawa ke sini.
Google Safe Browsing tidak ada di kit ini: kit tidak mengirim apa pun ke luar.

KETERBATASAN
------------
- "Tidak ada temuan" bukan berarti aman. SIGAP hanya melihat apa yang tercatat di log.
  Periksa Cakupan Analisis: pada Windows tanpa Sysmon, sebagian besar aturan tidak punya data.
- Nama operator diisi sendiri dan tidak diverifikasi.
- Paket bukti ditandatangani dengan kunci di browser ini, tetapi ZIP tidak terenkripsi, dan
  tanda tangan hanya berarti bila sidik jari kunci dicocokkan penerima lewat jalur lain.
- Ini bahan tanggap awal, bukan bukti forensik. Untuk proses hukum atau disiplin, serahkan
  kepada pemeriksa forensik yang berwenang.
