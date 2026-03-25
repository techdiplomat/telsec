#!/bin/bash
# ============================================================
# TelSec — Auto-start Kali container + FastAPI backend
# Runs on every Codespace start/wake via devcontainer.json
# ============================================================
set -e

echo "=== TelSec: Starting Kali Cloud Backend ==="

# Start the Kali container if it exists
if docker ps -a --format '{{.Names}}' | grep -q telsec-kali; then
  echo "[1/3] Starting telsec-kali container..."
  docker start telsec-kali 2>/dev/null || true
  sleep 2
else
  echo "[1/3] telsec-kali container not found — pulling and creating..."
  docker run -d \
    --name telsec-kali \
    -p 8000:8000 \
    -v /opt/telsec_api:/opt/telsec_api \
    kalilinux/kali-rolling \
    tail -f /dev/null
  sleep 5
fi

# Start the FastAPI backend inside the container
echo "[2/3] Starting FastAPI backend on port 8000..."
docker exec -d telsec-kali bash -c \
  'cd /opt/telsec_api && TELSEC_API_KEY=telsec-kali-2024 python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1'

sleep 3

# Update the Streamlit secrets.toml with the current Codespace URL
CODESPACE_URL="https://${CODESPACE_NAME}-8000.app.github.dev"
echo "[3/3] Updating .streamlit/secrets.toml with URL: $CODESPACE_URL"

# Update .kali_url (fallback read by kali_connector.py)
echo "$CODESPACE_URL" > /workspaces/telsec/.kali_url

# Update the secrets file in the repo (local only, not committed)
cat > /workspaces/telsec/.streamlit/secrets.toml <<EOF
[general]
KALI_API_URL = "${CODESPACE_URL}"
TELSEC_API_KEY = "telsec-kali-2024"
EOF

# Also push the URL update to GitHub so Streamlit Cloud picks it up
cd /workspaces/telsec
git add .streamlit/secrets.toml
git commit -m "auto: update KALI_API_URL to $CODESPACE_URL [skip ci]" 2>/dev/null || true
git push origin main 2>/dev/null || true

# Health check
echo "=== Checking API health ==="
for i in 1 2 3 4 5; do
  if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Kali API is ONLINE at $CODESPACE_URL"
    curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || true
    exit 0
  fi
  echo "  Waiting for API... (attempt $i/5)"
  sleep 3
done

echo "⚠️ API may still be starting. Check: docker logs telsec-kali"
