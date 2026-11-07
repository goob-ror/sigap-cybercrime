#requires -Version 5.1
<#
================================================================================
 SIGAP - Pengumpul Log Windows (sisi pertahanan)
================================================================================
 Membaca log peristiwa Windows di komputer ini dan menyimpannya sebagai satu ZIP
 yang dapat langsung diimpor ke SIGAP.

 HANYA MEMBACA. Skrip ini:
   - tidak mengubah, menghapus, atau mengosongkan log apa pun;
   - tidak mengubah kebijakan audit atau pengaturan Windows;
   - tidak memasang apa pun dan tidak membuat koneksi jaringan;
   - hanya menulis ke folder hasilnya sendiri.

 Pemakaian (Log Security hanya terbaca sebagai Administrator):
   .\sigap-collect.ps1                     # 7 hari terakhir, hasil di Desktop
   .\sigap-collect.ps1 -Days 30            # rentang lebih panjang
   .\sigap-collect.ps1 -MaxEvents 50000    # batas per log (terbaru lebih dahulu)
   .\sigap-collect.ps1 -OutputDir E:\bukti # simpan ke USB

 Hasil: <OutputDir>\sigap-log-<KOMPUTER>-<waktu>.zip beserta berkas .sha256-nya.
================================================================================
#>

[CmdletBinding()]
param(
  [ValidateRange(1, 3650)][int]$Days = 7,
  [ValidateRange(1, 1000000)][int]$MaxEvents = 20000,
  [string]$OutputDir = [Environment]::GetFolderPath('Desktop'),
  [string[]]$Channels = @(
    'Security',
    'System',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Windows PowerShell',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational'
  )
)

$ErrorActionPreference = 'Stop'

# Pesan bawaan sering sangat panjang; isinya sudah ada sebagai kolom di EventData.
$MaxMessageLength = 1000

function Write-Ok($msg)   { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "  [-] $msg" -ForegroundColor DarkGray }
function Write-Warn2($msg){ Write-Host "  [!] $msg" -ForegroundColor Yellow }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Kolom bernama dari XML peristiwa. <EventData> memakai <Data Name="...">, sedangkan <UserData>
# (mis. 1102 log dihapus) punya satu elemen pembungkus berisi kolom-kolomnya.
function Read-NamedData($node) {
  $out = @{}
  if ($null -eq $node) { return $out }
  $i = 0
  foreach ($child in $node.ChildNodes) {
    if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
    $i++
    $name = $child.GetAttribute('Name')
    if (-not $name) { $name = if ($child.LocalName -eq 'Data') { "param$i" } else { $child.LocalName } }
    $out[$name] = $child.InnerText
  }
  return $out
}

function Convert-Event($e) {
  $eventData = @{}
  $userData = @{}
  try {
    $xml = [xml]$e.ToXml()
    $eventData = Read-NamedData $xml.Event.EventData
    if ($xml.Event.UserData -and $xml.Event.UserData.FirstChild) { $userData = Read-NamedData $xml.Event.UserData.FirstChild }
  } catch {
    # XML yang tidak valid (jarang): nilai tetap diambil, tanpa nama kolom aslinya.
    $i = 0
    foreach ($p in $e.Properties) { $i++; $eventData["param$i"] = [string]$p.Value }
  }

  $message = $null
  try { $message = $e.Message } catch { }
  if ($message -and $message.Length -gt $MaxMessageLength) { $message = $message.Substring(0, $MaxMessageLength) }

  $record = [ordered]@{
    EventID       = [int]$e.Id
    Channel       = $e.LogName
    Computer      = $e.MachineName
    TimeCreated   = $e.TimeCreated.ToUniversalTime().ToString('o')
    ProviderName  = $e.ProviderName
    EventRecordID = [string]$e.RecordId
    Level         = [int]$e.Level
    EventData     = $eventData
    Message       = $message
  }
  if ($userData.Count) { $record['UserData'] = $userData }
  return $record
}

# Tanpa filter waktu, sebab -FilterHashtable melaporkan akses yang ditolak sebagai "tidak ada event",
# yang akan terbaca seolah log Security bersih. Memakai kode galat, karena teksnya mengikuti bahasa Windows.
function Get-ChannelState([string]$channel) {
  try {
    Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop | Out-Null
    return 'ok'
  } catch {
    if ($_.Exception -is [System.UnauthorizedAccessException]) { return 'perlu-administrator' }
    if ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { return 'tidak-ada' }
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return 'kosong' }
    throw
  }
}

# Ditulis satu per satu sebagai satu array JSON, sehingga log besar tidak perlu muat di memori.
function Export-Channel([string]$channel, [string]$path, [datetime]$since) {
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $writer = New-Object System.IO.StreamWriter($path, $false, $encoding)
  $count = 0
  try {
    $writer.Write('[')
    try {
      Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
        if ($count) { $writer.Write(",`n") }
        $writer.Write((Convert-Event $_ | ConvertTo-Json -Depth 4 -Compress))
        $count++
      }
    } catch {
      if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
    $writer.Write(']')
  } finally {
    $writer.Dispose()
  }
  return $count
}

Write-Host ""
Write-Host "=== SIGAP - Pengumpul Log Windows (hanya membaca) ===" -ForegroundColor White

$isAdmin = Test-Admin
if (-not $isAdmin) { Write-Warn2 "Tidak berjalan sebagai Administrator: log Security tidak akan terbaca." }

$startedAt = Get-Date
$since = $startedAt.AddDays(-$Days)
$stamp = $startedAt.ToString('yyyyMMdd-HHmmss')
$name = "sigap-log-$($env:COMPUTERNAME)-$stamp"

if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$workDir = Join-Path $OutputDir $name
New-Item -ItemType Directory -Path $workDir | Out-Null

Write-Host "Mengumpulkan $Days hari terakhir (maks. $MaxEvents event per log):`n"

$results = @()
foreach ($channel in $Channels) {
  $fileName = ($channel -replace '[\\/:*?"<>| ]', '-') + '.json'
  $path = Join-Path $workDir $fileName
  $entry = [ordered]@{ channel = $channel; file = $null; events = 0; status = 'ok'; terpotong = $false }
  try {
    $entry.status = Get-ChannelState $channel
    if ($entry.status -eq 'ok') {
      $entry.events = Export-Channel $channel $path $since
      if (-not $entry.events) { $entry.status = 'kosong' }
    }
  } catch {
    $entry.status = "gagal: $($_.Exception.Message)"
  }
  if ($entry.events) { $entry.file = $fileName } elseif (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
  if ($entry.events -ge $MaxEvents) { $entry.terpotong = $true }

  switch -Wildcard ($entry.status) {
    'ok' {
      Write-Ok ("{0,-48} {1,7} event" -f $channel, $entry.events)
      if ($entry.terpotong) { Write-Warn2 ("{0,-48} batas tercapai; event yang lebih lama tidak ikut (naikkan -MaxEvents)" -f '') }
    }
    'kosong' { Write-Skip ("{0,-48} tidak ada event dalam rentang ini" -f $channel) }
    'tidak-ada' { Write-Skip ("{0,-48} tidak ada di komputer ini" -f $channel) }
    'perlu-administrator' { Write-Warn2 ("{0,-48} TIDAK TERBACA: perlu hak Administrator" -f $channel) }
    default { Write-Warn2 ("{0,-48} {1}" -f $channel, $entry.status) }
  }
  $results += New-Object PSObject -Property $entry
}

$unread = @($results | Where-Object { $_.status -ne 'ok' -and $_.status -ne 'kosong' -and $_.status -ne 'tidak-ada' })
$total = ($results | Measure-Object -Property events -Sum).Sum
if (-not $total) {
  Remove-Item -LiteralPath $workDir -Recurse -Force
  Write-Host ""
  Write-Warn2 "Tidak ada event yang terbaca. Coba jalankan sebagai Administrator atau perpanjang -Days."
  exit 1
}

$info = [ordered]@{
  alat         = 'SIGAP sigap-collect.ps1'
  komputer     = $env:COMPUTERNAME
  dijalankanOleh = "$env:USERDOMAIN\$env:USERNAME"
  administrator = $isAdmin
  mulai        = $startedAt.ToUniversalTime().ToString('o')
  selesai      = (Get-Date).ToUniversalTime().ToString('o')
  zonaWaktu    = [TimeZoneInfo]::Local.Id
  rentangHari  = $Days
  maksEvent    = $MaxEvents
  log          = $results
}
$encoding = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $workDir 'info-pengumpulan.json'), ($info | ConvertTo-Json -Depth 4), $encoding)

# Format sha256sum; SIGAP mencocokkannya saat mengimpor ZIP ini.
$manifest = Get-ChildItem -LiteralPath $workDir -File | Sort-Object Name | ForEach-Object {
  "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
[IO.File]::WriteAllText((Join-Path $workDir 'MANIFEST-SHA256.txt'), (($manifest -join "`n") + "`n"), $encoding)

$zipPath = "$workDir.zip"
Compress-Archive -Path (Join-Path $workDir '*') -DestinationPath $zipPath -CompressionLevel Optimal
Remove-Item -LiteralPath $workDir -Recurse -Force

$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText("$zipPath.sha256", "$zipHash  $name.zip`n", $encoding)

Write-Host ""
Write-Host "Selesai: $total event." -ForegroundColor Green
Write-Host "  Berkas : $zipPath"
Write-Host "  SHA-256: $zipHash"
Write-Host ""
if ($unread.Count) {
  Write-Warn2 "HASIL TIDAK LENGKAP. Tidak terbaca: $(($unread | ForEach-Object { $_.channel }) -join ', ')."
  Write-Warn2 "Aktivitas di log tersebut tidak akan terlihat di SIGAP. Ulangi sebagai Administrator bila bisa."
  Write-Host ""
}
Write-Host "Langkah berikutnya:" -ForegroundColor White
Write-Host "  1) Catat SHA-256 di atas pada berita acara, lalu pindahkan ZIP dengan USB."
Write-Host "  2) Buka SIGAP > Impor Data, lalu tarik ZIP ini ke halaman itu (tidak perlu dibongkar)."
Write-Host ""
