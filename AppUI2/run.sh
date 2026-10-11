#!/usr/bin/env bash
# GC2-Sheet Web UI — quick start
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create venv if not exists
if [ ! -d ".venv" ]; then
  echo "[*] Creating virtual environment…"
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "[*] Installing dependencies…"
pip install -q -r requirements.txt

if [ ! -f "credentials.json" ]; then
  echo ""
  echo "  ⚠️  credentials.json not found!"
  echo "  Place your Google OAuth2 client secret (credentials.json) in:"
  echo "  $SCRIPT_DIR"
  echo ""
fi

echo ""
echo "  ╔══════════════════════════════════╗"
echo "  ║   GC2-Sheet Web UI               ║"
echo "  ║   http://127.0.0.1:5000          ║"
echo "  ╚══════════════════════════════════╝"
echo ""

python app.py
