#!/bin/sh
# SIGAP - Kit Offline untuk Linux/macOS: menyajikan aplikasi di komputer ini saja, tanpa internet.
# Portnya tetap: browser menyimpan data per alamat, sehingga port lain akan tampak seperti SIGAP yang kosong.
PORT=48173
URL="http://localhost:$PORT/"

cd "$(dirname "$0")/app" || { echo "Folder 'app' tidak ditemukan. Bongkar seluruh ZIP kit terlebih dahulu."; exit 1; }

if command -v python3 >/dev/null 2>&1; then PYTHON=python3
elif command -v python >/dev/null 2>&1; then PYTHON=python
else echo "Perlu Python 3 untuk menjalankan kit ini."; exit 1
fi

echo "SIGAP berjalan di $URL"
echo "Biarkan jendela ini terbuka selama memakai SIGAP. Tekan Ctrl+C untuk berhenti."
echo "Hanya dapat diakses dari komputer ini. Data tersimpan di browser komputer ini."

# Di jendelanya sendiri, tanpa bilah alamat, bila ada browser yang mendukungnya.
open_app() {
  for browser in microsoft-edge google-chrome chromium chromium-browser; do
    if command -v "$browser" >/dev/null 2>&1; then "$browser" --app="$URL" >/dev/null 2>&1; return; fi
  done
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1
  elif command -v open >/dev/null 2>&1; then open "$URL"
  fi
}

if [ -z "$SIGAP_NO_BROWSER" ]; then (sleep 1; open_app) & fi

exec "$PYTHON" -m http.server "$PORT" --bind 127.0.0.1
