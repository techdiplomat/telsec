#!/bin/bash
# ============================================================
# TelSec — Backend Setup v5.0
# Auto-detects Docker availability:
#   - WITH Docker: runs tools inside kalilinux/kali-rolling container
#   - WITHOUT Docker: installs tools directly on Ubuntu Codespace host
# ============================================================
set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  TelSec — Backend Setup v5.0                           ║"
echo "║  Auto-mode: Docker container OR direct host install    ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ── Detect mode ───────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  MODE="docker"
  echo "[✓] Docker detected — using Kali container mode"
else
  MODE="direct"
  echo "[!] Docker not available — using direct host install mode (Ubuntu)"
fi

# ══════════════════════════════════════════════════════════════
#  DOCKER MODE (original behaviour)
# ══════════════════════════════════════════════════════════════
if [ "$MODE" = "docker" ]; then

  echo "[1/6] Preparing telsec-kali container..."
  docker pull kalilinux/kali-rolling

  if docker ps -a --format '{{.Names}}' | grep -q '^telsec-kali$'; then
    echo "  → Removing existing telsec-kali container..."
    docker stop telsec-kali 2>/dev/null || true
    docker rm   telsec-kali 2>/dev/null || true
  fi

  docker run -d \
    --name telsec-kali \
    --restart unless-stopped \
    -p 8000:8000 \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    kalilinux/kali-rolling tail -f /dev/null
  sleep 3

  echo "[2/6] Installing core tools in container..."
  docker exec telsec-kali bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
      python3 python3-pip git curl wget \
      nmap hping3 tshark lksctp-tools libsctp-dev libpcap-dev \
      aircrack-ng hydra sipvicious sipsak dnsrecon whois zmap \
      gr-gsm kalibrate-rtl \
      erlang openjdk-17-jre kamailio kamailio-utils \
      cmake build-essential 2>/dev/null || true
    pip3 install --break-system-packages \
      fastapi "uvicorn[standard]" scapy requests pydantic pyshark 2>/dev/null || true
  '

  echo "[3/6] Cloning telecom tools..."
  docker exec telsec-kali bash -c '
    mkdir -p /opt/tools && cd /opt/tools
    [ -d SigPloit ]      || git clone --depth 1 https://github.com/SigPloiter/SigPloit.git
    [ -d GTScan ]        || git clone --depth 1 https://github.com/SigPloiter/GTScan.git
    [ -d ss7MAPer ]      || git clone --depth 1 https://github.com/P1sec/ss7MAPer.git
    [ -d safeseven ]     || git clone --depth 1 https://github.com/akibsayyed/safeseven.git
    [ -d sigshark ]      || git clone --depth 1 https://github.com/shotsan/sigshark.git
    [ -d scat ]          || git clone --depth 1 https://github.com/fgsect/scat.git
    [ -d lucid-ddos ]    || git clone --depth 1 https://github.com/doriguzzi/lucid-ddos.git
    [ -d MobiWatch ]     || git clone --depth 1 https://github.com/5GSEC/MobiWatch.git 2>/dev/null || true
    [ -d 5Greplay ]      || git clone --depth 1 https://github.com/5GSEC/5Greplay.git 2>/dev/null || true
    [ -d SigFW ]         || git clone --depth 1 https://github.com/P1sec/SigFW.git 2>/dev/null || true
    [ -d 5GBaseChecker ] || git clone --depth 1 https://github.com/SyNSec-den/5GBaseChecker.git 2>/dev/null || true
    pip3 install --break-system-packages -r /opt/tools/SigPloit/requirements.txt 2>/dev/null || true
    echo "[✓] Tools ready"
  '

  echo "[4/6] Deploying TelSec API..."
  docker exec telsec-kali mkdir -p /opt/telsec_api
  docker cp kali_backend/main.py telsec-kali:/opt/telsec_api/main.py

  docker exec -d telsec-kali bash -c \
    'cd /opt/telsec_api && TELSEC_API_KEY=telsec-kali-2024 python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1'
  sleep 4

fi

# ══════════════════════════════════════════════════════════════
#  DIRECT MODE (no Docker — install on Ubuntu Codespace host)
# ══════════════════════════════════════════════════════════════
if [ "$MODE" = "direct" ]; then

  echo "[1/5] Installing system packages on Codespace host..."
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -qq 2>/dev/null || true
  sudo apt-get install -y -qq \
    python3 python3-pip git curl wget \
    nmap hping3 tshark \
    dnsrecon whois lksctp-tools \
    sipvicious sipsak kamailio kamailio-utils \
    hydra aircrack-ng \
    gr-gsm kalibrate-rtl \
    zmap 2>/dev/null || true

  # Nuclei (Go binary)
  if ! command -v nuclei &>/dev/null; then
    echo "  → Installing Nuclei..."
    sudo apt-get install -y -qq golang 2>/dev/null || true
    export GOPATH=/opt/go
    sudo -E go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
    sudo ln -sf /opt/go/bin/nuclei /usr/local/bin/nuclei 2>/dev/null || true
  fi

  # Metasploit
  if ! command -v msfconsole &>/dev/null; then
    echo "  → Installing Metasploit..."
    curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/metasploit-framework.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] https://apt.metasploit.com/ bullseye main" | \
      sudo tee /etc/apt/sources.list.d/metasploit-framework.list 2>/dev/null || true
    sudo apt-get update -qq 2>/dev/null || true
    sudo apt-get install -y -qq metasploit-framework 2>/dev/null || true
  fi

  echo "[2/5] Installing Python dependencies..."
  python3 -m pip install --user \
    fastapi "uvicorn[standard]" scapy requests pydantic pyshark 2>/dev/null || true

  echo "[3/5] Cloning telecom tools..."
  mkdir -p /tmp/telsec_tools && cd /tmp/telsec_tools
  [ -d SigPloit ]      || git clone --depth 1 https://github.com/SigPloiter/SigPloit.git 2>/dev/null || true
  [ -d GTScan ]        || git clone --depth 1 https://github.com/SigPloiter/GTScan.git 2>/dev/null || true
  [ -d ss7MAPer ]      || git clone --depth 1 https://github.com/P1sec/ss7MAPer.git 2>/dev/null || true
  [ -d safeseven ]     || git clone --depth 1 https://github.com/akibsayyed/safeseven.git 2>/dev/null || true
  [ -d sigshark ]      || git clone --depth 1 https://github.com/shotsan/sigshark.git 2>/dev/null || true
  [ -d scat ]          || git clone --depth 1 https://github.com/fgsect/scat.git 2>/dev/null || true
  [ -d lucid-ddos ]    || git clone --depth 1 https://github.com/doriguzzi/lucid-ddos.git 2>/dev/null || true
  [ -d MobiWatch ]     || git clone --depth 1 https://github.com/5GSEC/MobiWatch.git 2>/dev/null || true
  [ -d 5Greplay ]      || git clone --depth 1 https://github.com/5GSEC/5Greplay.git 2>/dev/null || true
  [ -d 5GBaseChecker ] || git clone --depth 1 https://github.com/SyNSec-den/5GBaseChecker.git 2>/dev/null || true
  # Create symlink so backend can find tools at /opt/tools
  sudo mkdir -p /opt/tools
  sudo ln -sfn /tmp/telsec_tools/* /opt/tools/ 2>/dev/null || true
  cd /workspaces/telsec

  pip3 install --break-system-packages \
    -r /tmp/telsec_tools/SigPloit/requirements.txt 2>/dev/null || true

  echo "[4/5] Starting TelSec API directly on host..."
  pkill -f "uvicorn main:app" 2>/dev/null || true
  sleep 1
  cd /workspaces/telsec/kali_backend
  TELSEC_API_KEY=telsec-kali-2024 \
    nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 \
    > /tmp/telsec_api.log 2>&1 &
  sleep 4
  cd /workspaces/telsec

fi

# ── Step Final: Port + health check (both modes) ─────────────
echo "[Final] Configuring port visibility..."
CODESPACE_URL="https://${CODESPACE_NAME}-8000.app.github.dev"
echo "$CODESPACE_URL" > .kali_url

gh codespace ports visibility 8000:public -c "$CODESPACE_NAME" 2>/dev/null || \
  echo "  → Manually set port 8000 to 'Public' in the Ports tab (Ctrl+Shift+P → Ports)"

sleep 2
echo ""
if curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null; then
  echo ""
  STATUS="✅ ONLINE"
else
  STATUS="⚠️  Not responding yet — check /tmp/telsec_api.log"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  TelSec Backend v5.0 — $STATUS"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Mode    : $MODE"
echo "║  API URL : $CODESPACE_URL"
echo "║  Key     : telsec-kali-2024                             ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "👉  Add to Streamlit Secrets:"
echo "    KALI_API_URL = \"$CODESPACE_URL\""
echo "    TELSEC_API_KEY = \"telsec-kali-2024\""
echo ""
echo "📋  Logs: tail -f /tmp/telsec_api.log"
