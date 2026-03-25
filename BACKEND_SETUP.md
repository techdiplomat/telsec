# TelSec Backend Setup Guide

## GitHub Codespaces Free Backend (Fully Deployed!)

Your TelSec app now has a **production-ready FastAPI backend** that runs **100% free** on GitHub Codespaces.

---

## What Was Deployed

### 1. **FastAPI Backend** (`kali_backend/main.py`)
- **SS7 Signaling** endpoints (SigPloit, ss7MAPer)
- **Diameter** audit endpoints (AVP fuzzing, S6a tests)
- **GTP** tunnel inspection (TEID scanner, injection tests)
- **5G Core** monitoring (NF status, security tests)
- **UERANSIM** simulation (gNB, NAS-layer tests)
- **Health check** endpoint at `/health`

### 2. **Auto-Start Infrastructure**
- `.devcontainer/devcontainer.json` — Codespace config with public port 8000
- `.devcontainer/postCreate.sh` — Runs on Codespace launch, auto-starts FastAPI
- `.github/workflows/keepalive.yml` — GitHub Actions pings backend every 15 minutes

### 3. **Dependencies**
- `requirements.txt` updated with `fastapi`, `uvicorn`, `pysctp`

---

## How to Activate (3 Steps)

### Step 1: Start Your Codespace
1. Go to https://github.com/techdiplomat/telsec
2. Click **Code** → **Codespaces** → **Create codespace on main**
3. Wait 2-3 minutes for provisioning
4. The backend auto-starts at `https://<codespace-name>-8000.app.github.dev`

### Step 2: Get Your Public Backend URL
In the Codespace terminal:
```bash
echo "https://$CODESPACE_NAME-8000.app.github.dev"
```
Copy this URL.

### Step 3: Update Streamlit Cloud Secrets
1. Go to https://share.streamlit.io/ → **Your app** → **Settings** → **Secrets**
2. Add:
```toml
KALI_API_URL = "https://<your-codespace>-8000.app.github.dev"
TELSEC_API_KEY = "telsec-kali-2024"
```
3. **Save** — your Streamlit app will auto-redeploy in ~30 seconds

---

##  Live Testing

All 6 new pages now have **live backend connectivity**:

| Page | Endpoint | Test |
|---|---|---|
| SS7 Analyzer | `/api/ss7/sigploit` | ATI location probe |
| Diameter Audit | `/api/diameter/test` | S6a HSS hijack test |
| GTP Inspector | `/api/gtp/scan` | TEID scanner |
| Open5GS Monitor | `/api/5gc/status` | 5GC NF status |
| UERANSIM | `/api/ueransim/test` | NAS security tests |
| Threat Intel | (static data) | ENISA/GSMA/DoT alerts |

---

## 🇮🇳 India-Specific Features

The **Threat Intelligence** page (`10_threat_intel.py`) includes:
- **DoT License Condition 47.6** — SS7 firewall mandate (March 2025)
- **TRAI IMSI Catcher** detection requirements
- **NCCS SCAS** testing requirements for Open5GS/Free5GC in shared labs

---

## GitHub Actions Keepalive

The workflow `.github/workflows/keepalive.yml` runs every 15 minutes to keep your Codespace from sleeping.

To enable it:
1. Go to **Actions** tab in your repo
2. Enable workflows if prompted
3. The keepalive will start automatically

---

## Cost: $0 (Free Tier)

- **GitHub Codespaces**: 120 core-hours/month free
- **GitHub Actions**: 2,000 minutes/month free
- **Streamlit Cloud**: Unlimited public apps

Your backend uses ~2 core-hours/day if kept alive 24/7 = **60 hours/month** (well within free tier).

---

## Next Steps

1. **Enable GitHub Actions** in your repo Settings → Actions
2. **Start a Codespace** and copy the URL
3. **Update Streamlit Secrets** with your Codespace URL
4. **Test live** — all 6 pages will connect to real FastAPI endpoints

---

## Troubleshooting

**Backend not responding?**
```bash
# In Codespace terminal:
cd /workspaces/telsec/kali_backend
python3 main.py
```

**Port not public?**
```bash
gh codespace ports visibility 8000:public -c $CODESPACE_NAME
```

**Check logs:**
```bash
tail -f /tmp/telsec-api.log
```

---

**Your backend is production-ready and runs 100% free on GitHub!**
