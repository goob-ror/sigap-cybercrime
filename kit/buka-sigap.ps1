#requires -Version 5.1
<#
 SIGAP - Kit Offline: menyajikan aplikasi di komputer ini saja, tanpa internet.

 Browser hanya menjalankan SIGAP lewat HTTPS atau localhost, sehingga index.html tidak dapat
 dibuka langsung dari folder. Skrip ini server kecil yang hanya menerima koneksi dari komputer ini.

 Portnya tetap: browser menyimpan data per alamat, sehingga port lain akan tampak seperti SIGAP
 yang kosong. Data kasus tersimpan di browser komputer ini, bukan di folder kit.
#>
param(
  [int]$Port = 48173,
  [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'app'))
if (-not (Test-Path -LiteralPath (Join-Path $root 'index.html'))) {
  Write-Host "Folder 'app' tidak ditemukan di $PSScriptRoot. Bongkar seluruh ZIP kit terlebih dahulu." -ForegroundColor Red
  exit 1
}

$mime = @{
  '.html' = 'text/html; charset=utf-8'
  '.webmanifest' = 'application/manifest+json'
  '.js'   = 'text/javascript; charset=utf-8'
  '.mjs'  = 'text/javascript; charset=utf-8'
  '.css'  = 'text/css; charset=utf-8'
  '.json' = 'application/json'
  '.svg'  = 'image/svg+xml'
  '.png'  = 'image/png'
  '.jpg'  = 'image/jpeg'
  '.ico'  = 'image/x-icon'
  '.woff' = 'font/woff'
  '.woff2' = 'font/woff2'
  '.txt'  = 'text/plain; charset=utf-8'
}

$url = "http://localhost:$Port/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
try {
  $listener.Start()
} catch {
  Write-Host "Port $Port sedang dipakai." -ForegroundColor Yellow
  Write-Host "Bila SIGAP sudah berjalan di jendela lain, buka $url di browser."
  Write-Host "Bila dipakai aplikasi lain, tutup aplikasi itu lalu jalankan lagi."
  exit 1
}

# Membuka SIGAP di jendelanya sendiri, tanpa bilah alamat, bila Edge atau Chrome ada. Urutannya tetap,
# karena browser yang berbeda menyimpan data yang berbeda.
function Open-AppWindow([string]$address) {
  $browsers = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
  )
  foreach ($browser in $browsers) {
    if (Test-Path -LiteralPath $browser) {
      Start-Process -FilePath $browser -ArgumentList "--app=$address"
      return
    }
  }
  Start-Process $address
}

function Send-Status($response, [int]$code) {
  $response.StatusCode = $code
  $response.ContentLength64 = 0
}

function Send-Request($context) {
  $request = $context.Request
  $response = $context.Response
  try {
    if ($request.HttpMethod -ne 'GET' -and $request.HttpMethod -ne 'HEAD') { Send-Status $response 405; return }
    $path = [Uri]::UnescapeDataString($request.Url.AbsolutePath)
    if ($path -eq '/') { $path = '/index.html' }
    # Menolak jalur keluar dari folder app, misalnya /../rahasia.txt.
    $full = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $path.TrimStart('/', '\')))
    if (-not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($full)) {
      Send-Status $response 404
      return
    }
    $extension = [IO.Path]::GetExtension($full).ToLowerInvariant()
    $response.ContentType = if ($mime.ContainsKey($extension)) { $mime[$extension] } else { 'application/octet-stream' }
    $response.Headers['X-Content-Type-Options'] = 'nosniff'
    # Berkas di assets/ memuat hash isinya pada namanya, jadi tidak pernah berubah.
    $response.Headers['Cache-Control'] = if ($path.StartsWith('/assets/')) { 'public, max-age=31536000, immutable' } else { 'no-cache' }
    $bytes = [IO.File]::ReadAllBytes($full)
    $response.ContentLength64 = $bytes.Length
    if ($request.HttpMethod -eq 'GET') { $response.OutputStream.Write($bytes, 0, $bytes.Length) }
  } catch [System.ArgumentException], [System.NotSupportedException], [System.IO.PathTooLongException] {
    Send-Status $response 400
  } catch {
    # Browser menutup koneksi di tengah pengiriman: bukan masalah.
  } finally {
    try { $response.Close() } catch { }
  }
}

Write-Host ""
Write-Host "SIGAP berjalan di $url" -ForegroundColor Green
Write-Host "Biarkan jendela ini terbuka selama memakai SIGAP. Tutup jendela ini untuk berhenti."
Write-Host "Hanya dapat diakses dari komputer ini. Data tersimpan di browser komputer ini."
Write-Host ""
if (-not $NoBrowser) { Open-AppWindow $url }

try {
  while ($listener.IsListening) {
    # Menunggu berselang-seling agar Ctrl+C tetap berfungsi.
    $pending = $listener.GetContextAsync()
    while (-not $pending.Wait(250)) { }
    Send-Request $pending.Result
  }
} finally {
  $listener.Close()
}
