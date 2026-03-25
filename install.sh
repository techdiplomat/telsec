#!/bin/bash
# ============================================================
# TelSec - One-Command Installer
# Usage: bash install.sh
# ============================================================
# LEGAL NOTICE: This tool is for authorized security auditing
# only. By running this installer, you confirm that you have
# written authorization from the network operator.
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
echo -e "${CYAN}"
cat << 'EOF'
  _____    _ _____           
 |_   _|__| / ____|         
   | |/ _ \ \__ \  ___  ___ 
   | |  __/ |__) |/ _ \/ __|
   |_|\___|_|____/\___/\___| v1.0.0
   Telecom Security Audit Framework
EOF
echo -e "${NC}"
}

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

# ---- Legal disclaimer ----
banner
echo -e "${RED}============================================================"
echo " LEGAL DISCLAIMER"
echo "============================================================"
echo " This tool performs telecom network security testing."
echo " It MUST only be used on networks you are authorized to test."
echo " Unauthorized use is illegal and unethical."
echo " By continuing, you confirm you have written authorization."
echo -e "============================================================${NC}"
read -rp "Do you accept the terms and have authorization? (yes/no): " ACCEPT
if [[ "$ACCEPT" != "yes" ]]; then
    err "Installation cancelled — authorization not accepted."
    exit 1
fi

# ---- Detect OS ----
OS=""
if [[ -f /etc/kali_version ]]; then
    OS="kali"
    log "Detected Kali Linux"
elif [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS="$ID"
    log "Detected: $PRETTY_NAME"
else
    warn "Unknown OS — proceeding with best effort"
fi

# ---- System packages ----
log "Installing system packages..."
sudo apt-get update -q

PACKAGES=(
    python3 python3-pip python3-venv
    nmap wireshark-common tshark
    git curl wget
    libssl-dev libffi-dev
    build-essential
)

# Telecom-specific packages (may not be available on all distros)
TELECOM_PACKAGES=(
    gr-gsm
    osmocom-nitb
    erlang
    default-jdk
)

sudo apt-get install -y "${PACKAGES[@]}" 2>/dev/null || warn "Some base packages failed"

for pkg in "${TELECOM_PACKAGES[@]}"; do
    if sudo apt-get install -y "$pkg" 2>/dev/null; then
        log "Installed: $pkg"
    else
        warn "Could not install $pkg — module will be degraded (not fatal)"
    fi
done

# ---- Python virtual environment ----
log "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

log "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
log "Python dependencies installed"

# ---- Clone SigPloit ----
if [[ ! -d deps/sigploit ]]; then
    log "Cloning SigPloit (SS7/Diameter attack framework)..."
    git clone --depth=1 https://github.com/SigPloiter/SigPloit deps/sigploit 2>/dev/null || \
        warn "SigPloit clone failed — SS7/Diameter modules will be degraded"
else
    log "SigPloit already present"
fi

# ---- Clone ss7MAPer ----
if [[ ! -d deps/ss7maper ]]; then
    log "Cloning ss7MAPer..."
    git clone --depth=1 https://github.com/ernw/ss7MAPer deps/ss7maper 2>/dev/null || \
        warn "ss7MAPer clone failed — SS7 MAP fuzzing unavailable"
else
    log "ss7MAPer already present"
fi

# ---- Clone IMSI-catcher ----
if [[ ! -d deps/imsi-catcher ]]; then
    log "Cloning IMSI-catcher (passive lab use only)..."
    git clone --depth=1 https://github.com/Oros42/IMSI-catcher deps/imsi-catcher 2>/dev/null || \
        warn "IMSI-catcher clone failed"
fi

# ---- Clone Open5GS ----
if [[ ! -d deps/open5gs ]]; then
    log "Cloning Open5GS (5G Core)..."
    git clone --depth=1 https://github.com/open5gs/open5gs deps/open5gs 2>/dev/null || \
        warn "Open5GS clone failed — 5GC local mode unavailable"
fi

# ---- Docker images ----
if command -v docker &>/dev/null; then
    log "Pulling srsRAN Docker images..."
    docker pull softwareradiosystems/srsran_4g:latest 2>/dev/null || \
        warn "srsRAN 4G image pull failed"
    docker pull softwareradiosystems/srsran-project:latest 2>/dev/null || \
        warn "srsRAN 5G image pull failed"
    log "Docker images ready"
else
    warn "Docker not found — RF simulation modules will be unavailable"
    warn "Install Docker: https://docs.docker.com/get-docker/"
fi

# ---- Create reports directory ----
mkdir -p reports/

# ---- Create .env template ----
if [[ ! -f .env ]]; then
cat > .env << 'EOF'
# TelSec Environment Variables
# Copy this to .env and fill in real values
NGROK_AUTH_TOKEN=
NVD_API_KEY=
FIREBASE_PROJECT=
TELEAUDIT_DB=teleaudit.db
EOF
    log "Created .env template"
fi

# ---- Run tests ----
log "Running unit tests..."
source venv/bin/activate
python -m pytest tests/ -q --tb=short 2>/dev/null || warn "Some tests failed — check tests/ directory"

echo ""
log "Installation complete!"
echo ""
echo -e "${CYAN}=========================================="
echo " To start TelSec:"
echo "   source venv/bin/activate"
echo "   streamlit run app.py"
echo ""
echo " For Docker deployment:"
echo "   docker-compose up"
echo ""
echo " For Google Colab:"
echo "   Open colab_launcher.ipynb"
echo -e "==========================================${NC}"
