#requires -Version 5.1
<#
================================================================================
 SIGAP — Generator Telemetri Latihan (sisi "laptop penyerang")
================================================================================
 Skrip ini BUKAN malware dan BUKAN alat serang. Tujuannya satu: menghasilkan
 jejak log Windows yang NYATA (ditulis oleh auditing Windows / Sysmon itu
 sendiri) supaya SIGAP punya sesuatu yang benar-benar terjadi untuk dideteksi,
 dikorelasikan, diberi skor, dan dilaporkan di laptop pertahanan.

 Semua aksi di sini:
   - BENIGN (tidak merusak): hanya menyentuh objek dummy yang dibuat skrip ini
     sendiri, semuanya ditandai "SIGAP-DRILL".
   - LOKAL: tidak ada koneksi jaringan, tidak ada DNS, tidak ada unduhan.
   - REVERSIBLE: jalankan dengan -Cleanup untuk menghapus semua objek dummy.
   - TRANSPARAN: "payload" yang ter-encode hanyalah perintah cetak teks.

 SENGAJA TIDAK DILAKUKAN (terlalu berbahaya walau "hanya untuk log"; ini hanya
 ada di skenario sintetis bawaan SIGAP, tidak pernah dijalankan sungguhan):
   - Dump memori LSASS (comsvcs MiniDump)   -> benar-benar mencuri kredensial
   - Mematikan Microsoft Defender            -> penurunan keamanan nyata
   - Menghapus Event Log (1102 / 104)        -> memusnahkan barang bukti
   - certutil / koneksi keluar               -> butuh jaringan nyata

 Jalankan HANYA di laptop latihan/lab milik Anda sendiri. Jangan di komputer
 operasional, server, atau domain controller.

 Pemakaian:
   .\sigap-drill.ps1 -List                 # lihat daftar aksi
   .\sigap-drill.ps1                        # jalankan semua aksi yang didukung
   .\sigap-drill.ps1 -Only akun,logon       # jalankan sebagian saja
   .\sigap-drill.ps1 -Cleanup               # hapus semua objek dummy
   .\sigap-drill.ps1 -EnableAudit           # aktifkan audit proses dulu (opsional)
   .\sigap-drill.ps1 -Yes                    # lewati konfirmasi interaktif

 Setelah menjalankan, ekspor lognya dengan perintah yang sama seperti di SIGAP:
   Get-WinEvent -LogName Security,System,'Microsoft-Windows-Sysmon/Operational' `
     -MaxEvents 5000 -ErrorAction SilentlyContinue | ConvertTo-Json |
     Out-File log-latihan.json
 lalu impor log-latihan.json ke SIGAP di laptop pertahanan.
================================================================================
#>

[CmdletBinding()]
param(
  [switch]$Cleanup,
  [switch]$List,
  [string[]]$Only,
  [switch]$EnableAudit,
  [switch]$Yes
)

$ErrorActionPreference = 'Stop'

# --- Nama objek dummy (semuanya diawali agar mudah dikenali & dibersihkan) ----
$TAG      = 'SIGAP-DRILL'
$DrillUser = 'sigap.latihan'
$DrillSvc  = 'SIGAPDrillSvc'
$DrillTask = 'SIGAP-Drill-OnLogon'
$WorkDir   = Join-Path $env:TEMP 'sigap-drill'
$AuditState = Join-Path $WorkDir 'audit-sebelumnya.txt'

# --- Util ---------------------------------------------------------------------
function Write-Step($msg){ Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg){   Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "  [!] $msg" -ForegroundColor Yellow }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-SafeMachine {
  # Tolak domain controller / server peran penting.
  try {
    $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
    # 4 = Backup DC, 5 = Primary DC
    if ($role -eq 4 -or $role -eq 5) {
      throw "Mesin ini terdeteksi sebagai Domain Controller. Skrip latihan dibatalkan."
    }
  } catch [System.Management.Automation.RuntimeException] { throw }
  catch { } # Jika CIM tak tersedia, lanjut; pengguna tetap diminta konfirmasi.
}

function Confirm-Run {
  if ($Yes) { return }
  Write-Host ""
  Write-Host "Skrip ini akan membuat objek dummy bertanda '$TAG' di komputer INI" -ForegroundColor Yellow
  Write-Host "untuk menghasilkan log latihan. Semua dapat dihapus dengan -Cleanup." -ForegroundColor Yellow
  $ans = Read-Host "Lanjutkan di komputer latihan ini? (ketik: ya)"
  if ($ans -ne 'ya') { throw "Dibatalkan oleh pengguna." }
}

# --- Audit proses (opsional, reversible) --------------------------------------
# EventID 4688 (pembuatan proses) + baris perintah tidak aktif secara default.
# Tanpa Sysmon, aksi berbasis proses (-enc, schtasks, 7z) tak akan tercatat.
function Enable-ProcessAudit {
  if (-not (Test-Admin)) { throw "Perlu hak Administrator untuk -EnableAudit." }
  New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
  Write-Step "Menyimpan konfigurasi audit saat ini ke $AuditState"
  (auditpol /get /subcategory:"Process Creation") | Out-File $AuditState -Encoding utf8
  Write-Step "Mengaktifkan 'Audit Process Creation' (Success)"
  auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
  $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
  New-Item -Path $key -Force | Out-Null
  Write-Step "Mengaktifkan perekaman baris perintah pada EventID 4688"
  New-ItemProperty -Path $key -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
  Write-Ok "Audit proses aktif. Jalankan lagi dengan -Cleanup untuk mengembalikannya."
}

function Restore-ProcessAudit {
  if (-not (Test-Admin)) { Write-Warn2 "Lewati pemulihan audit (perlu Administrator)."; return }
  $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
  if (Test-Path $key) {
    Remove-ItemProperty -Path $key -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
  }
  # Kembalikan ke default aman: nonaktifkan Success untuk Process Creation.
  auditpol /set /subcategory:"Process Creation" /success:disable | Out-Null
  Write-Ok "Konfigurasi audit proses dikembalikan ke default."
}

# --- AKSI LATIHAN -------------------------------------------------------------
# Tiap aksi menghasilkan satu/lebih peristiwa Windows NYATA yang cocok dengan
# aturan SIGAP. Nama aksi dipakai pada parameter -Only.

function Do-Account {
  # -> EventID 4720 (akun baru). Aturan: sigap-win-account-created.
  if (-not (Test-Admin)) { throw "Perlu Administrator untuk membuat akun lokal." }
  if (Get-LocalUser -Name $DrillUser -ErrorAction SilentlyContinue) {
    Write-Warn2 "Akun $DrillUser sudah ada, dilewati."
    return
  }
  Write-Step "Membuat akun lokal dummy '$DrillUser'"
  $pw = ConvertTo-SecureString ("Drill!" + [guid]::NewGuid().ToString('N').Substring(0,10)) -AsPlainText -Force
  New-LocalUser -Name $DrillUser -Password $pw -FullName "SIGAP Drill ($TAG)" `
    -Description "Akun latihan SIGAP - aman dihapus" -PasswordNeverExpires | Out-Null
  Write-Ok "Akun dibuat (EventID 4720)."
}

function Do-Logon {
  # -> EventID 4625 x6 (logon gagal). Aturan: sigap-native-failed-logon-burst.
  Write-Step "Mensimulasikan 6 percobaan kata sandi salah ke akun dummy"
  $code = @'
using System;
using System.Runtime.InteropServices;
public static class DrillLogon {
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool LogonUser(string user, string domain, string pass,
    int logonType, int logonProvider, out IntPtr token);
}
'@
  if (-not ('DrillLogon' -as [type])) { Add-Type -TypeDefinition $code }
  $tok = [IntPtr]::Zero
  for ($i = 0; $i -lt 6; $i++) {
    # LOGON32_LOGON_NETWORK = 3  -> menghasilkan 4625 bertipe logon 3 (seperti brute force).
    [DrillLogon]::LogonUser($DrillUser, $env:COMPUTERNAME, "SalahPassword_$i", 3, 0, [ref]$tok) | Out-Null
    Start-Sleep -Milliseconds 300
  }
  Write-Ok "6 logon gagal tercatat (EventID 4625)."
}

function Do-Service {
  # -> EventID 7045 (layanan dipasang). Aturan: sigap-win-psexec-service.
  if (-not (Test-Admin)) { throw "Perlu Administrator untuk memasang layanan." }
  if (Get-Service -Name $DrillSvc -ErrorAction SilentlyContinue) {
    Write-Warn2 "Layanan $DrillSvc sudah ada, dilewati."
    return
  }
  Write-Step "Memasang layanan dummy '$DrillSvc' (binary benign: cmd.exe /c rem)"
  # binPath mengandung 'cmd.exe /c' sehingga cocok aturan; isinya 'rem' (tak melakukan apa pun).
  New-Service -Name $DrillSvc -BinaryPathName "cmd.exe /c rem $TAG" `
    -DisplayName "SIGAP Drill Service ($TAG)" -StartupType Manual | Out-Null
  Write-Ok "Layanan dipasang (EventID 7045). Tidak dijalankan."
}

function Do-Encoded {
  # -> proses powershell -enc. Aturan: sigap-win-ps-encoded.
  # Payload-nya transparan: hanya mencetak teks. Tidak ada -w hidden, tidak ada aksi tersembunyi.
  $plain = "Write-Host '${TAG}: perintah ter-encode yang sepenuhnya benign'"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($plain))
  Write-Step "Menjalankan 'powershell.exe -EncodedCommand' dengan payload cetak-teks"
  & powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
  Write-Ok "Proses PowerShell ter-encode tercatat (butuh Sysmon atau audit 4688)."
}

function Do-Schtask {
  # -> schtasks -create (4688) + EventID 4698. Aturan: sigap-win-schtask-create.
  Write-Step "Membuat tugas terjadwal dummy '$DrillTask' (aksi benign: cmd /c rem)"
  & schtasks.exe /create /tn $DrillTask /tr "cmd.exe /c rem $TAG" /sc onlogon /f | Out-Null
  Write-Ok "Tugas terjadwal dibuat. Tidak akan membahayakan saat login."
}

function Do-Archive {
  # -> 7z a -p (4688). Aturan: sigap-win-archive-password. Hanya jika 7-Zip terpasang.
  $sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $sevenZip) { Write-Warn2 "7-Zip tidak ditemukan, aksi 'archive' dilewati."; return }
  New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
  $dummy = Join-Path $WorkDir 'dokumen-latihan.txt'
  "Berkas latihan $TAG - isi tidak rahasia." | Out-File $dummy -Encoding utf8
  $out = Join-Path $WorkDir 'arsip-latihan.7z'
  Write-Step "Membuat arsip terenkripsi dummy dengan 7-Zip"
  & $sevenZip a -p"Drill123" $out $dummy | Out-Null
  Write-Ok "Arsip ber-password dibuat (EventID 4688)."
}

# Peta aksi: nama -> fungsi
$Actions = [ordered]@{
  'akun'    = { Do-Account }
  'logon'   = { Do-Logon }
  'layanan' = { Do-Service }
  'encoded' = { Do-Encoded }
  'schtask' = { Do-Schtask }
  'archive' = { Do-Archive }
}

$ActionDesc = [ordered]@{
  'akun'    = 'Akun lokal baru dibuat               -> 4720  -> sigap-win-account-created'
  'logon'   = '6 logon gagal ke akun dummy          -> 4625  -> sigap-native-failed-logon-burst'
  'layanan' = 'Layanan dummy dipasang (cmd /c)      -> 7045  -> sigap-win-psexec-service'
  'encoded' = 'PowerShell -EncodedCommand (benign)  -> 4688/Sysmon1 -> sigap-win-ps-encoded'
  'schtask' = 'Tugas terjadwal dummy dibuat         -> 4688/4698 -> sigap-win-schtask-create'
  'archive' = 'Arsip ber-password via 7-Zip (opsi)  -> 4688  -> sigap-win-archive-password'
}

# --- Cleanup ------------------------------------------------------------------
function Invoke-Cleanup {
  Write-Host "Membersihkan objek latihan '$TAG'..." -ForegroundColor Cyan
  # Layanan
  if (Get-Service -Name $DrillSvc -ErrorAction SilentlyContinue) {
    try { Stop-Service $DrillSvc -ErrorAction SilentlyContinue } catch {}
    & sc.exe delete $DrillSvc | Out-Null
    Write-Ok "Layanan $DrillSvc dihapus."
  }
  # Tugas terjadwal
  if (& schtasks.exe /query /tn $DrillTask 2>$null) {
    & schtasks.exe /delete /tn $DrillTask /f | Out-Null
    Write-Ok "Tugas $DrillTask dihapus."
  }
  # Akun
  if (Get-LocalUser -Name $DrillUser -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $DrillUser
    Write-Ok "Akun $DrillUser dihapus."
  }
  # Berkas kerja
  if (Test-Path $WorkDir) {
    if (Test-Path $AuditState) { Restore-ProcessAudit }
    Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Folder kerja dibersihkan."
  }
  Write-Host ""
  Write-Host "Selesai. Log peristiwa SENGAJA tidak dihapus - itulah barang bukti" -ForegroundColor Green
  Write-Host "yang akan diimpor ke SIGAP." -ForegroundColor Green
}

# --- Main ---------------------------------------------------------------------
Write-Host ""
Write-Host "=== SIGAP - Generator Telemetri Latihan ===" -ForegroundColor White

if ($List) {
  Write-Host "`nAksi yang tersedia (pakai -Only <nama,nama>):`n"
  foreach ($k in $ActionDesc.Keys) {
    "{0,-9} {1}" -f $k, $ActionDesc[$k] | Write-Host
  }
  Write-Host ""
  return
}

if ($Cleanup) { Invoke-Cleanup; return }

Test-SafeMachine
Confirm-Run
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

if ($EnableAudit) { Enable-ProcessAudit }

$hasSysmon = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
if (-not $hasSysmon -and -not $EnableAudit) {
  Write-Warn2 "Sysmon tidak terpasang dan audit proses mungkin nonaktif."
  Write-Warn2 "Aksi berbasis proses (encoded/schtask/archive) bisa TIDAK tercatat."
  Write-Warn2 "Jalankan sekali dengan -EnableAudit (sebagai Administrator) agar EventID 4688 aktif."
}

$selected = if ($Only) { $Only } else { $Actions.Keys }
Write-Host "`nMenjalankan aksi: $($selected -join ', ')`n" -ForegroundColor White

foreach ($name in $selected) {
  if (-not $Actions.Contains($name)) { Write-Warn2 "Aksi '$name' tidak dikenal, dilewati."; continue }
  try { & $Actions[$name] }
  catch { Write-Warn2 "Aksi '$name' gagal: $($_.Exception.Message)" }
}

Write-Host ""
Write-Host "Latihan selesai. Langkah berikutnya:" -ForegroundColor White
Write-Host "  1) Ekspor log (lihat header skrip) ke sebuah berkas JSON." -ForegroundColor Gray
Write-Host "  2) Pindahkan berkas ke laptop pertahanan (USB - tetap offline)." -ForegroundColor Gray
Write-Host "  3) Impor ke SIGAP, lihat deteksi & laporannya." -ForegroundColor Gray
Write-Host "  4) Jalankan '.\sigap-drill.ps1 -Cleanup' untuk menghapus objek dummy." -ForegroundColor Gray
Write-Host ""
