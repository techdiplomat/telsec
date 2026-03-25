#!/bin/bash
# TelSec postCreate.sh — runs inside the devcontainer after creation
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  TelSec — Dev Container Post-Create Setup               ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ── 1. Python deps ────────────────────────────────────────────
echo "[1/4] Installing Python deps..."
pip install -q fastapi "uvicorn[standard]" python-multipart requests pydantic \
  streamlit plotly pandas pyyaml 2>/dev/null || true

# ── 2. System tools ───────────────────────────────────────────
echo "[2/4] Installing system tools..."
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y -qq \
  nmap tshark curl whois dnsutils git \
  2>/dev/null || true

# ── 3. Try to install Docker (for Kali container mode) ───────
echo "[3/4] Installing Docker..."
curl -fsSL https://get.docker.com | sudo sh 2>/dev/null || true
sudo usermod -aG docker vscode 2>/dev/null || true

# ── 4. Auto-start TelSec API ─────────────────────────────────
echo "[4/4] Starting TelSec API..."
API_DIR="/workspaces/telsec/kali_backend"
if [ -f "$API_DIR/main.py" ]; then
  cd "$API_DIR"
  export TELSEC_API_KEY="telsec-kali-2024"
  nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 \
    > /tmp/telsec-api.log 2>&1 &
  sleep 3
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "[✓] TelSec API running on port 8000"
  else
    echo "[!] API starting — check /tmp/telsec-api.log"
  fi
fi

echo ""
echo "✅ Dev container ready!"
echo "📡 API: https://${CODESPACE_NAME}-8000.app.github.dev"
echo "🔑 Key: telsec-kali-2024"
echo ""
echo "Run: bash setup-kali.sh   ← for full Kali tool install"
