# 🔐 TelSec — Telecom Security Penetration Testing Framework

**2G/GSM → 5G/NR | Authorized auditing only | Cloud-deployable in 5 minutes**

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-ready-blue)](./Dockerfile)
[![Colab](https://img.shields.io/badge/Google%20Colab-launch-orange)](./colab_launcher.ipynb)

---

## 🌐 Deploy on Streamlit Community Cloud (Free — Public URL in 5 min)

> **No credit card. No server. Just GitHub + Streamlit.**  
> Your app gets a permanent URL like `https://yourname-telsec-app-xxxx.streamlit.app`

### Step 1 — Push to GitHub

```powershell
# In PowerShell / WSL, from the teleaudit folder:
cd C:\Users\ADG\Downloads\teleaudit

git init
git add .
git commit -m "Initial TelSec commit"

# Create a repo on github.com (e.g. 'telsec') then:
git remote add origin https://github.com/YOUR_USERNAME/telsec.git
git branch -M main
git push -u origin main
```

### Step 2 — Deploy on Streamlit Cloud

1. Go to **[share.streamlit.io](https://share.streamlit.io)** → Sign in with GitHub
2. Click **"New app"**
3. Select your repo: `YOUR_USERNAME/telsec`
4. Set **Main file path**: `app.py`
5. Click **"Deploy"** → Live in ~2 minutes ✅

Your URL will be:  
```
https://yourname-telsec-app-XXXX.streamlit.app
```

### Step 3 — Open & Test

- The app opens in **Demo Mode** automatically (no hardware required)
- Click **"🎮 Quick Start: Load Demo Findings"** on the Dashboard
- Explore 18 realistic CVE-mapped findings across 2G/3G/4G/5G
- Generate and download PDF/HTML/JSON reports immediately

---

## ⚙️ Environment Variables (Optional)

Set these in Streamlit Cloud → App Settings → Secrets:

```toml
# .streamlit/secrets.toml  (do NOT commit this file)
TELSEC_DEMO = "1"           # Force demo mode (default on cloud)
NVD_API_KEY = "your-key"    # Optional: higher NVD rate limit
FIREBASE_PROJECT = ""       # Optional: cloud audit log sync
```

Or disable demo mode and provide real targets:

```toml
TELSEC_DEMO = "0"
# Then fill in target IPs in the Configuration page
```

---

## 🚀 Other Deployment Options

### Docker (Local or Cloud VPS)
```bash
docker-compose up                    # Core app only
docker-compose --profile 5g up      # + Open5GS 5G core
# App: http://localhost:8501
```

### Google Colab (Free GPU + SDR simulation)
1. Open `colab_launcher.ipynb` in Google Colab
2. Run all cells — public ngrok URL appears in Cell 3
3. Share the URL for remote access

### Kali Linux / Local Install
```bash
bash install.sh          # Full tool installation (Kali recommended)
source venv/bin/activate
streamlit run app.py
```

### Render.com (Free alternative to Streamlit Cloud)
```
Build command:  pip install -r requirements.txt
Start command:  streamlit run app.py --server.port $PORT --server.address 0.0.0.0
```

### Railway.app (Docker, free tier)
```bash
railway up   # Uses Dockerfile automatically
```

---

## 🧪 Demo Mode vs Real Mode

| Feature | Demo Mode (Cloud) | Real Mode (Linux/Lab) |
|---|---|---|
| 18 pre-built findings | ✅ | ✅ |
| CVE mappings & GSMA refs | ✅ | ✅ |
| PDF/HTML/CSV reports | ✅ | ✅ |
| Network topology map | ✅ | ✅ |
| Real GSM scan (gr-gsm/kal) | ❌ needs SDR | ✅ |
| Live SS7 probe (SigPloit) | ❌ needs SS7 GW | ✅ |
| Live 4G/5G testing | ❌ needs EPC/5GC | ✅ |
| nmap / tshark | ✅ (cloud) | ✅ |

---

## 📋 Test Coverage

| Module | Tests | Key Vulnerabilities |
|---|---|---|
| 2G/GSM | GSM-001→006 | A5/0 null cipher, IMSI exposure, rogue BTS |
| 3G/SS7 | SS7-001→010 | Location tracking, SMS/call intercept, auth vectors |
| 4G/LTE | LTE-001→010 | Diameter S6a, GTP-U hijack, EEA0 null cipher |
| 5G/NR  | NR-001→012 | SUCI null scheme, SBA API auth, slice isolation |

---

## ⚖️ Legal Notice

> **TelSec is for authorized security auditing ONLY.**  
> Unauthorized use against production networks is illegal under CFAA, UK CMA, IT Act 2000, and equivalent laws worldwide.  
> The tool enforces a mandatory legal authorization gate before any active test.

---

## 🏗️ Architecture

```
teleaudit/
├── app.py                    # 7-page Streamlit UI
├── demo_data.py              # 18 realistic demo findings
├── modules/
│   ├── gen2/gsm_audit.py     # 2G/GSM tests
│   ├── gen3/ss7_audit.py     # 3G/SS7 tests
│   ├── gen4/lte_audit.py     # 4G/LTE tests
│   └── gen5/nr_audit.py      # 5G/NR tests
├── engines/
│   ├── scanner.py            # nmap wrapper
│   ├── fuzzer.py             # Protocol fuzzer
│   ├── sniffer.py            # tshark capture
│   └── exploiter.py          # MSF + SigPloit
├── reporting/
│   ├── report_engine.py      # GSMA compliance + risk scoring
│   └── pdf_exporter.py       # ReportLab PDF
├── packages.txt              # Streamlit Cloud system packages
└── requirements.txt          # Python dependencies
```
