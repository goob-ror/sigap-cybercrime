@echo off
rem Menjalankan pengumpul log. Klik kanan lalu "Run as administrator" agar log Security terbaca.
rem ExecutionPolicy Bypass hanya berlaku untuk proses ini; pengaturan Windows tidak diubah.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sigap-collect.ps1" %*
pause
