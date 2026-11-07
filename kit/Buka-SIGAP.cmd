@echo off
rem Membuka SIGAP tanpa internet. ExecutionPolicy Bypass hanya berlaku untuk proses ini; pengaturan Windows tidak diubah.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0buka-sigap.ps1" %*
if errorlevel 1 pause
