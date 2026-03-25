"""
TelSec - Main Streamlit Application
=====================================
7-page security audit framework UI.
Covers: Dashboard, Config, Test Runner, Results, Topology, Reports, Tools.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import yaml

# ---------------------------------------------------------------------------
# Bootstrap path so modules resolve correctly
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from modules.base_module import FindingResult, Severity, TestStatus
from utils.logger import get_audit_log, get_logger
from utils.validators import validate_authorization, validate_ip_in_scope

logger = get_logger("app")

# Demo mode: auto-enabled on cloud (no real targets) or via env var
DEMO_MODE: bool = (
    os.environ.get("TELSEC_DEMO", "1").lower() in ("1", "true", "yes")
    or not Path("config/config.yaml").exists()
)

# ============================================================
# Page config
# ============================================================
st.set_page_config(
    page_title="TelSec — Telecom Security Framework",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# Global CSS
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Design Tokens ───────────────────────────────────────────────── */
:root {
  --bg-base:       #070b14;
  --bg-surface:    #0d1321;
  --bg-card:       rgba(13,21,38,0.85);
  --bg-glass:      rgba(255,255,255,0.03);
  --border-subtle: rgba(255,255,255,0.07);
  --border-accent: rgba(99,179,237,0.25);
  --brand:         #3b82f6;
  --brand-dim:     rgba(59,130,246,0.15);
  --crimson:       #ef4444;
  --crimson-dim:   rgba(239,68,68,0.12);
  --amber:         #f59e0b;
  --amber-dim:     rgba(245,158,11,0.12);
  --emerald:       #10b981;
  --emerald-dim:   rgba(16,185,129,0.12);
  --cyan:          #06b6d4;
  --violet:        #8b5cf6;
  --text-primary:  #e2e8f0;
  --text-muted:    #64748b;
  --text-dim:      #475569;
  --sev-critical:  #ef4444;
  --sev-high:      #f97316;
  --sev-medium:    #f59e0b;
  --sev-low:       #3b82f6;
  --sev-info:      #64748b;
  --sev-pass:      #10b981;
  --radius-sm:     6px;
  --radius-md:     10px;
  --radius-lg:     16px;
  --shadow-card:   0 4px 32px rgba(0,0,0,0.5), 0 1px 0 rgba(255,255,255,0.04) inset;
  --shadow-glow:   0 0 24px rgba(59,130,246,0.15);
  --transition:    all 0.2s cubic-bezier(0.4,0,0.2,1);
}

/* ── Base ────────────────────────────────────────────────────────── */
html, body, [class*="css"] { font-family: 'Inter', system-ui, sans-serif !important; }
.stApp { background: var(--bg-base) !important; color: var(--text-primary); }
.stApp::before {
  content:""; position:fixed; inset:0; z-index:-1;
  background: radial-gradient(ellipse 80% 50% at 50% -20%, rgba(59,130,246,0.08) 0%, transparent 70%),
              radial-gradient(ellipse 50% 30% at 90% 80%, rgba(139,92,246,0.05) 0%, transparent 60%);
  pointer-events:none;
}

/* ── Sidebar ─────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background: var(--bg-surface) !important;
  border-right: 1px solid var(--border-subtle) !important;
}
[data-testid="stSidebar"]::before {
  content:""; position:absolute; top:0; left:0; right:0; height:1px;
  background: linear-gradient(90deg, transparent, var(--brand), transparent);
}
.nav-section-label {
  font-size: 0.65rem; font-weight: 700; letter-spacing: 0.1em;
  color: var(--text-dim); text-transform: uppercase;
  padding: 12px 4px 4px; margin-top: 4px;
}
/* ── Page header strip ───────────────────────────────────────────── */
.page-hero {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  padding: 20px 28px;
  margin-bottom: 24px;
  display: flex; align-items: center; gap: 18px;
  position: relative; overflow: hidden;
}
.page-hero::before {
  content:""; position:absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg, var(--brand), var(--violet), var(--cyan));
}
.page-hero-icon {
  font-size: 2rem; line-height:1;
  background: var(--brand-dim); border:1px solid rgba(59,130,246,0.2);
  border-radius: 12px; padding: 10px; min-width:52px; text-align:center;
}
.page-hero-title { font-size: 1.35rem; font-weight: 800; color: var(--text-primary); line-height:1.2; }
.page-hero-sub   { font-size: 0.9rem; color: #94a3b8; margin-top:4px; line-height:1.5; }
/* ── Tool detect cards ───────────────────────────────────────────── */
.tool-card {
  background: var(--bg-card); border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md); padding: 12px 16px;
  display: flex; align-items: center; gap: 10px;
  transition: var(--transition);
}
.tool-card:hover { border-color: var(--border-accent); }
.tool-card.ok  { border-left: 3px solid var(--emerald); }
.tool-card.err { border-left: 3px solid var(--crimson); }
.sidebar-brand {
  display:flex; align-items:center; gap:12px; padding: 20px 4px 16px;
  border-bottom: 1px solid var(--border-subtle);
}
.brand-icon {
  width:36px; height:36px; border-radius:8px;
  background: linear-gradient(135deg, var(--brand), var(--violet));
  display:flex; align-items:center; justify-content:center;
  font-size:1.1rem; box-shadow: 0 4px 12px rgba(59,130,246,0.3);
}
.brand-name { font-size:1.1rem; font-weight:800; color:var(--text-primary); }
.brand-ver  { font-size:0.65rem; color:var(--text-dim); font-family:'JetBrains Mono',monospace; }

/* ── Radio Nav Styling ───────────────────────────────────────────── */
[data-testid="stRadio"] label {
  border-radius: var(--radius-sm) !important;
  padding: 6px 10px !important;
  font-size: 0.82rem !important;
  color: var(--text-muted) !important;
  transition: var(--transition) !important;
  cursor: pointer !important;
}
[data-testid="stRadio"] label:hover {
  background: var(--bg-glass) !important;
  color: var(--text-primary) !important;
}
[data-testid="stRadio"] [aria-checked="true"] label {
  background: var(--brand-dim) !important;
  color: var(--brand) !important;
  font-weight: 600 !important;
  border-left: 2px solid var(--brand) !important;
}

/* ── Glassmorphism Cards ─────────────────────────────────────────── */
.glass-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  padding: 20px 24px;
  box-shadow: var(--shadow-card);
  backdrop-filter: blur(12px);
  transition: var(--transition);
  position: relative; overflow: hidden;
}
.glass-card::before {
  content:""; position:absolute; inset:0; border-radius: inherit;
  background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, transparent 60%);
  pointer-events:none;
}
.glass-card:hover { border-color: var(--border-accent); box-shadow: var(--shadow-card), var(--shadow-glow); }

/* ── Metric Cards ────────────────────────────────────────────────── */
.metric-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 18px 20px;
  box-shadow: var(--shadow-card);
  position: relative; overflow: hidden;
}
.metric-card::after {
  content:""; position:absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg, var(--brand), var(--violet));
}
.metric-label { font-size:0.72rem; color:var(--text-dim); font-weight:500; text-transform:uppercase; letter-spacing:.06em; }
.metric-value { font-size:1.8rem; font-weight:800; color:var(--text-primary); line-height:1; margin-top:4px; }
.metric-sub   { font-size:0.75rem; color:var(--text-muted); margin-top:2px; }

/* ── Severity Badges ─────────────────────────────────────────────── */
.sev-badge {
  display:inline-flex; align-items:center; gap:5px;
  padding:2px 10px; border-radius:4px;
  font-size:0.68rem; font-weight:700; letter-spacing:.05em;
  font-family:'JetBrains Mono',monospace;
}
.sev-CRITICAL { background:var(--crimson-dim); color:var(--sev-critical); border:1px solid rgba(239,68,68,0.3); }
.sev-HIGH     { background:rgba(249,115,22,0.12); color:var(--sev-high); border:1px solid rgba(249,115,22,0.3); }
.sev-MEDIUM   { background:var(--amber-dim); color:var(--sev-medium); border:1px solid rgba(245,158,11,0.3); }
.sev-LOW      { background:var(--brand-dim); color:var(--sev-low); border:1px solid rgba(59,130,246,0.3); }
.sev-INFO     { background:rgba(100,116,139,0.12); color:var(--sev-info); border:1px solid rgba(100,116,139,0.3); }
.sev-PASS     { background:var(--emerald-dim); color:var(--sev-pass); border:1px solid rgba(16,185,129,0.3); }

/* ── Status Pills ────────────────────────────────────────────────── */
.status-online  { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:20px;
  background:var(--emerald-dim); color:var(--emerald); font-size:0.75rem; font-weight:600; border:1px solid rgba(16,185,129,0.25); }
.status-offline { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:20px;
  background:var(--crimson-dim); color:var(--crimson); font-size:0.75rem; font-weight:600; border:1px solid rgba(239,68,68,0.25); }
.status-dot { width:6px; height:6px; border-radius:50%; }
.status-online  .status-dot { background:var(--emerald); box-shadow:0 0 6px var(--emerald); animation:pulse 2s infinite; }
.status-offline .status-dot { background:var(--crimson); }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

/* ── Finding Cards ───────────────────────────────────────────────── */
.finding-card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 14px 18px;
  margin-bottom: 10px;
  display: flex; gap: 14px; align-items: flex-start;
  transition: var(--transition);
}
.finding-card:hover { border-color:var(--border-accent); transform:translateX(2px); }
.finding-bar { width:3px; border-radius:3px; flex-shrink:0; align-self:stretch; }
.finding-bar-CRITICAL { background:var(--sev-critical); }
.finding-bar-HIGH { background:var(--sev-high); }
.finding-bar-MEDIUM { background:var(--sev-medium); }
.finding-bar-LOW { background:var(--sev-low); }
.finding-bar-INFO { background:var(--sev-info); }
.finding-title { font-size:0.88rem; font-weight:600; color:var(--text-primary); }
.finding-module { font-size:0.72rem; color:var(--text-dim); font-family:'JetBrains Mono',monospace; }

/* ── Code / Terminal Blocks ──────────────────────────────────────── */
.stCode, .stCodeBlock, code, pre {
  font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
  font-size: 0.82rem !important;
}
[data-testid="stCode"] {
  background: #0d1117 !important;
  border: 1px solid var(--border-subtle) !important;
  border-radius: var(--radius-md) !important;
}
.terminal-block {
  background: #0d1117;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 16px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: #a3e635;
  white-space: pre-wrap;
  overflow-x: auto;
  position: relative;
}
.terminal-block::before {
  content: "● ● ●";
  display: block;
  color: var(--text-dim);
  font-size: 0.6rem;
  margin-bottom: 10px;
  letter-spacing: 4px;
}

/* ── Section Headers ─────────────────────────────────────────────── */
.section-header {
  display:flex; align-items:center; gap:12px;
  margin: 24px 0 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border-subtle);
}
.section-header-icon {
  width:32px; height:32px;
  background: var(--brand-dim);
  border-radius: 8px;
  display:flex; align-items:center; justify-content:center;
  font-size:0.9rem;
  border: 1px solid rgba(59,130,246,0.2);
}
.section-header-text { font-size:1rem; font-weight:700; color:var(--text-primary); }
.section-header-sub  { font-size:0.75rem; color:var(--text-muted); }

/* ── Legal Box ───────────────────────────────────────────────────── */
.legal-box {
  background: var(--crimson-dim);
  border: 1px solid rgba(239,68,68,0.2);
  border-radius: var(--radius-md);
  padding: 16px 20px;
  margin-bottom: 20px;
}

/* ── Buttons ─────────────────────────────────────────────────────── */
.stButton > button {
  background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
  color: #fff !important; border: none !important;
  border-radius: var(--radius-sm) !important;
  font-weight: 600 !important;
  font-size: 0.82rem !important;
  padding: 8px 20px !important;
  letter-spacing: 0.02em !important;
  box-shadow: 0 2px 8px rgba(37,99,235,0.3) !important;
  transition: var(--transition) !important;
}
.stButton > button:hover {
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important;
  box-shadow: 0 4px 16px rgba(59,130,246,0.4) !important;
  transform: translateY(-1px) !important;
}

/* ── Tables / DataFrames ─────────────────────────────────────────── */
.stDataFrame { border-radius: var(--radius-md) !important; overflow:hidden !important; border:1px solid var(--border-subtle) !important; }
[data-testid="stDataFrame"] th { background: #111827 !important; color:var(--text-muted) !important; font-size:0.75rem !important; text-transform:uppercase !important; letter-spacing:0.05em !important; }
[data-testid="stDataFrame"] td { font-size:0.82rem !important; }

/* ── Misc ────────────────────────────────────────────────────────── */
hr { border-color: var(--border-subtle) !important; margin: 20px 0 !important; }
h1, h2, h3 { color: var(--text-primary) !important; font-weight: 700 !important; }
h1 { font-size: 1.8rem !important; letter-spacing:-0.02em !important; }
h2 { font-size: 1.25rem !important; }
h3 { font-size: 1rem !important; }
.stTabs [data-baseweb="tab-list"] { background: var(--bg-surface) !important; border-radius: var(--radius-md) !important; padding:3px !important; gap:2px !important; border:1px solid var(--border-subtle) !important; }
.stTabs [data-baseweb="tab"] { border-radius: 6px !important; color:var(--text-muted) !important; font-size:0.82rem !important; padding:6px 14px !important; font-weight:500 !important; }
.stTabs [aria-selected="true"] { background: var(--brand-dim) !important; color:var(--brand) !important; font-weight:600 !important; }
.stMetric { background:var(--bg-card) !important; border:1px solid var(--border-subtle) !important; border-radius:var(--radius-md) !important; padding:14px !important; }
.stMetric label { color:var(--text-dim) !important; font-size:0.72rem !important; text-transform:uppercase !important; letter-spacing:.06em !important; }
.stMetric [data-testid="metric-container"] > div:nth-child(2) { color:var(--text-primary) !important; font-size:1.6rem !important; font-weight:800 !important; }
[data-testid="stAlert"] { border-radius:var(--radius-md) !important; border-width:1px !important; }
[data-testid="stExpander"] { border:1px solid var(--border-subtle) !important; border-radius:var(--radius-md) !important; background:var(--bg-card) !important; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# Session state initialization
# ============================================================
def init_state():
    defaults = {
        "authorized": False,
        "auth_ref": "",
        "passive_only": True,
        "findings": [],
        "running": False,
        "config": {},
        "module_enabled": {"2G": True, "3G": True, "4G": True, "5G": True},
        "run_log": [],
        "last_scan": None,
        "cves": [],
        "demo_mode": DEMO_MODE,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ============================================================
# Config loader
# ============================================================
@st.cache_data(ttl=60)
def load_config() -> Dict:
    config_path = Path("config/config.yaml")
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}

cfg = load_config()

# ============================================================
# Sidebar navigation
# ============================================================
with st.sidebar:
    # ── Brand header with live Kali status dot ─────────────────────
    try:
        from kali_connector import health_check as _hc
        _kali_online = _hc().get("online", False)
    except Exception:
        _kali_online = False

    _dot_color = "#10b981" if _kali_online else "#475569"
    _dot_label = "Backend Online" if _kali_online else "Demo Mode"
    _dot_glow  = f"box-shadow:0 0 6px {_dot_color};" if _kali_online else ""

    st.markdown(f"""
    <div class="sidebar-brand">
      <div class="brand-icon">⬡</div>
      <div style="flex:1">
        <div class="brand-name">TelSec</div>
        <div class="brand-ver" style="display:flex;align-items:center;gap:6px;">
          v2.0 · TELECOM SECURITY
          <span style="display:inline-flex;align-items:center;gap:4px;
            background:rgba(255,255,255,.05);border-radius:999px;padding:2px 7px;margin-left:4px">
            <span style="width:5px;height:5px;border-radius:50%;background:{_dot_color};{_dot_glow}"></span>
            <span style="font-size:.58rem;color:{_dot_color}">{_dot_label}</span>
          </span>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Demo toggle (subtle, no alarming banner) ───────────────────
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    st.session_state.demo_mode = st.toggle(
        "🔀 Simulation mode", value=st.session_state.get("demo_mode", True),
        key="demo_toggle", help="Enable to use simulated results without a live Kali backend."
    )



    # ── Navigation (grouped) ──────────────────────────────────────
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

    # Inject sidebar nav button styles
    st.markdown("""
    <style>
    /* Nav section header */
    .nav-group-label {
        font-size: 0.6rem; font-weight: 700; letter-spacing: 0.12em;
        text-transform: uppercase; color: #475569;
        padding: 14px 4px 4px; margin-bottom: 2px;
    }
    /* Make all sidebar buttons look like nav items */
    [data-testid="stSidebar"] .stButton > button {
        background: transparent !important;
        border: none !important;
        color: #94a3b8 !important;
        text-align: left !important;
        width: 100% !important;
        padding: 6px 10px !important;
        border-radius: 6px !important;
        font-size: 0.82rem !important;
        font-weight: 400 !important;
        transition: all 0.15s !important;
        box-shadow: none !important;
        margin: 1px 0 !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        background: rgba(255,255,255,0.05) !important;
        color: #e2e8f0 !important;
    }
    /* Active page button highlight */
    [data-testid="stSidebar"] .stButton > button[data-active="true"],
    [data-testid="stSidebar"] .nav-active button {
        background: rgba(59,130,246,0.12) !important;
        color: #60a5fa !important;
        font-weight: 600 !important;
        border-left: 2px solid #3b82f6 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    _NAV_STRUCTURE = [
        ("🏠 HOME", ["Home"]),
        ("📡 PROTOCOL SECURITY", [
            "SS7 Analyzer", "Diameter Audit", "GTP Inspector",
            "SS7 GT Scanner", "Protocol Lab",
        ]),
        ("🔴 ACTIVE TESTING", [
            "Active Exploits", "SigPloit / SS7 Attack",
            "SIP / VoLTE Testing", "Offensive Toolkit",
        ]),
        ("🚀 5G / NEXT-GEN", [
            "5G Security", "UERANSIM Lab",
            "5G NAS Security", "5G Traffic Replay", "Open5GS Monitor",
        ]),
        ("🛡️ THREAT & DETECTION", [
            "Threat Intel", "Threat Detection",
            "Compliance Mapper", "Recon & Intelligence",
        ]),
        ("🔬 ANALYSIS TOOLS", ["Protocol Fuzzing"]),
        ("⚙️ SYSTEM", ["Tools & Environment"]),
    ]

    _PAGE_ICONS = {
        "Home": "🏠",
        "SS7 Analyzer": "📡", "Diameter Audit": "🔷", "GTP Inspector": "🌐",
        "SS7 GT Scanner": "🗺️", "Protocol Lab": "🧪",
        "Active Exploits": "💣", "SigPloit / SS7 Attack": "⚡",
        "SIP / VoLTE Testing": "📞", "Offensive Toolkit": "🗡️",
        "5G Security": "🚀", "UERANSIM Lab": "📶",
        "5G NAS Security": "🔐", "5G Traffic Replay": "▶️", "Open5GS Monitor": "🧬",
        "Threat Intel": "🛡️", "Threat Detection": "🔍",
        "Compliance Mapper": "📋", "Recon & Intelligence": "🔎",
        "Protocol Fuzzing": "🎯",
        "Tools & Environment": "🛠️",
    }

    for section_label, pages in _NAV_STRUCTURE:
        # Section header — only show header for non-Home sections
        if section_label != "🏠 HOME":
            st.markdown(f'<div class="nav-group-label">{section_label}</div>', unsafe_allow_html=True)
        for pg in pages:
            icon = _PAGE_ICONS.get(pg, "▸")
            label = f"{icon}  {pg}"
            is_active = st.session_state.current_page == pg
            # Apply active style via a wrapper class
            if is_active:
                st.markdown('<div class="nav-active">', unsafe_allow_html=True)
            if st.button(label, key=f"nav_{pg}", use_container_width=True):
                st.session_state.current_page = pg
                st.rerun()
            if is_active:
                st.markdown('</div>', unsafe_allow_html=True)

    page = st.session_state.current_page

    # ── Live stats strip ──────────────────────────────────────────
    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    findings = st.session_state.findings
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL" and f.get("status") == "FAIL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH"     and f.get("status") == "FAIL")
    total    = sum(1 for f in findings if f.get("status") == "FAIL")

    auth_html = (
        '<span class="status-online"><span class="status-dot"></span>Authorized</span>'
        if st.session_state.authorized else
        '<span class="status-offline"><span class="status-dot"></span>Unauthorized</span>'
    )
    last_scan_str = st.session_state.last_scan or '—'
    st.markdown(f"""
    <div style="border-top:1px solid rgba(255,255,255,0.07);margin-top:10px;padding-top:14px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <span style="font-size:0.65rem;color:#475569;text-transform:uppercase;letter-spacing:.1em;font-weight:700">Session</span>
        {auth_html}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:10px">
        <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);
             border-bottom:2px solid #ef4444;border-radius:8px;padding:10px 6px;text-align:center;">
          <div style="font-size:1.15rem;font-weight:800;color:#ef4444;line-height:1">{critical}</div>
          <div style="font-size:0.58rem;color:#64748b;text-transform:uppercase;margin-top:2px;letter-spacing:.05em">Critical</div>
        </div>
        <div style="background:rgba(249,115,22,0.08);border:1px solid rgba(249,115,22,0.2);
             border-bottom:2px solid #f97316;border-radius:8px;padding:10px 6px;text-align:center;">
          <div style="font-size:1.15rem;font-weight:800;color:#f97316;line-height:1">{high}</div>
          <div style="font-size:0.58rem;color:#64748b;text-transform:uppercase;margin-top:2px;letter-spacing:.05em">High</div>
        </div>
        <div style="background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.2);
             border-bottom:2px solid #3b82f6;border-radius:8px;padding:10px 6px;text-align:center;">
          <div style="font-size:1.15rem;font-weight:800;color:#3b82f6;line-height:1">{total}</div>
          <div style="font-size:0.58rem;color:#64748b;text-transform:uppercase;margin-top:2px;letter-spacing:.05em">Total</div>
        </div>
      </div>
      <div style="font-size:0.65rem;color:#475569;margin-bottom:8px;
           font-family:'JetBrains Mono',monospace;">⏱ {last_scan_str}</div>
    </div>
    """, unsafe_allow_html=True)

    # ── New Session button ──
    if st.button("🔄 New Session", use_container_width=True, key="sidebar_new_session",
                 help="Clear all findings and reset session data"):
        st.session_state.findings = []
        st.session_state.last_scan = None
        st.session_state.authorized = False
        st.session_state.auth_ref = ""
        st.rerun()

# ============================================================
# HELPER FUNCTIONS
# ============================================================
SEV_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280",
}

def severity_badge(sev: str) -> str:
    color = SEV_COLORS.get(sev, "#6b7280")
    return f'<span class="sev-badge sev-{sev}">{sev}</span>'

def risk_gauge(score: int):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Risk Score", "font": {"color": "#e0e6f0", "size": 16}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#6b7280"},
            "bar": {"color": "#e94560"},
            "bgcolor": "rgba(15,52,96,0.3)",
            "steps": [
                {"range": [0, 30], "color": "rgba(22,163,74,0.2)"},
                {"range": [30, 70], "color": "rgba(217,119,6,0.2)"},
                {"range": [70, 100], "color": "rgba(220,38,38,0.2)"},
            ],
            "threshold": {
                "line": {"color": "#e94560", "width": 3},
                "thickness": 0.75,
                "value": score,
            },
        },
        number={"font": {"color": "#e0e6f0", "size": 40}},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=250, margin=dict(t=30, b=0, l=30, r=30),
        font={"color": "#e0e6f0"},
    )
    return fig

def calc_risk(findings: List[Dict]) -> int:
    score = sum(
        {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1}.get(f.get("severity", ""), 0)
        for f in findings if f.get("status") == "FAIL"
    )
    return min(100, score)

# NOTE: Former "Dashboard" and other legacy pages logic removed. Handled by modular routing now.

if page == "Tools & Environment":
    st.markdown("""
    <div class="page-hero">
      <div class="page-hero-icon">🛠️</div>
      <div>
        <div class="page-hero-title">Tools & Environment</div>
        <div class="page-hero-sub">Kali Cloud tools status, local tool inventory, system diagnostics, and audit log</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Kali Cloud status pill (always visible at top) ──────────────────────
# ── Compact backend status ribbon (shown on all pages) ──────────────────────
_kali_online_global = False
try:
    from kali_connector import health_check as _kali_health, wake_backend as _wake_backend
    _ks = _kali_health()
    _kali_online_global = _ks.get("online", False)
    if _kali_online_global:
        _tools_count = len(_ks.get('tools', []))
        _latency = _ks.get('latency_ms', '?')
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:10px;padding:8px 16px;
             background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);
             border-radius:8px;margin-bottom:16px;">
          <span style="width:8px;height:8px;border-radius:50%;background:#10b981;
               box-shadow:0 0 8px #10b981;animation:pulse 2s infinite;flex-shrink:0"></span>
          <span style="font-size:0.82rem;color:#10b981;font-weight:600">Kali Cloud: ONLINE</span>
          <span style="font-size:0.78rem;color:#64748b;margin-left:4px">
            {_tools_count} tools · {_latency}ms latency
          </span>
        </div>
        """, unsafe_allow_html=True)
    else:
        _err_msg = _ks.get('error', 'Connection refused')
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:10px;padding:8px 16px;
             background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);
             border-radius:8px;margin-bottom:8px;">
          <span style="width:8px;height:8px;border-radius:50%;background:#ef4444;flex-shrink:0"></span>
          <span style="font-size:0.82rem;color:#ef4444;font-weight:600">Kali Cloud: OFFLINE</span>
          <span style="font-size:0.75rem;color:#64748b;margin-left:4px;font-family:'JetBrains Mono',monospace">{_err_msg}</span>
        </div>
        """, unsafe_allow_html=True)

        col_wake, col_manual = st.columns([1, 2])
        with col_wake:
            if st.button("⚡ Auto-Wake Backend", type="primary", use_container_width=True, key="global_wake_btn"):
                _wake_ph = st.empty()
                _steps = [
                    "🔌 Connecting to Codespace...",
                    "🐳 Starting Kali container...",
                    "⚙️ Initializing backend services...",
                    "📡 Waiting for API to respond...",
                ]
                for _i, _step in enumerate(_steps):
                    _wake_ph.info(f"{_step}  *(step {_i+1}/4)*", icon="⏳")
                    time.sleep(3)
                _wake_ph.info("Sending wake signal...", icon="⏳")
                wake_result = _wake_backend()
                if wake_result["success"]:
                    _wake_ph.success(f"✅ {wake_result['message']}")
                    time.sleep(1)
                    st.rerun()
                else:
                    _wake_ph.error(f"❌ {wake_result['message']}")
        with col_manual:
            st.caption("⏱️ Typical wake time: 30–60 seconds")
            with st.expander("📖 Manual Restart Instructions"):
                st.code(
                    "# Run in your Codespace terminal:\n"
                    "cd /workspaces/telsec/kali_backend\n"
                    "pkill -f uvicorn\n"
                    "TELSEC_API_KEY=telsec-kali-2024 nohup python3 -m uvicorn \\\n"
                    "  main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &",
                    language="bash")
except Exception:
    st.markdown("""
    <div style="display:flex;align-items:center;gap:10px;padding:8px 16px;
         background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);
         border-radius:8px;margin-bottom:16px;">
      <span style="font-size:0.82rem;color:#f59e0b;font-weight:600">⚠️ kali_connector not loaded — simulation mode active</span>
    </div>
    """, unsafe_allow_html=True)


    tab1, tab2, tab3, tab4 = st.tabs([
                "🔧 Installed Tools",
        "☁️ Kali Cloud Tools",
        "💻 System Resources",
        "📜 Audit Log",
    ])

    with tab1:
        tools_manifest = [
            ("Python", "python3", "--version"),
            ("Streamlit", "streamlit", "--version"),
            ("nmap", "nmap", "--version"),
            ("tshark", "tshark", "--version"),
            ("grgsm_livemon (gr-gsm)", "grgsm_livemon", "--help"),
            ("kal (kalibrate-rtl)", "kal", "--help"),
            ("osmo-nitb (osmocom)", "osmo-nitb", "--help"),
            ("msfconsole (Metasploit)", "msfconsole", "--version"),
            ("docker", "docker", "--version"),
            ("nuclei", "nuclei", "-version"),
            ("git", "git", "--version"),
            ("curl", "curl", "--version"),
        ]

        # Group tools into categories
        CLOUD_TOOLS = [
            ("Python",         "python3",        "--version",  "🐍", "Core runtime"),
            ("nmap",           "nmap",            "--version",  "🔍", "Port/service scanner"),
            ("tshark",         "tshark",          "--version",  "🦈", "Packet capture & analysis"),
            ("git",            "git",             "--version",  "📦", "Version control"),
            ("curl",           "curl",            "--version",  "🌐", "HTTP client"),
            ("Streamlit",      "streamlit",       "--version",  "🖥️", "Web UI framework"),
        ]
        KALI_TOOLS = [
            ("gr-gsm",         "grgsm_livemon",   None, "📡", "GSM 2G live capture (SDR required)"),
            ("kalibrate-rtl",  "kal",             None, "📻", "GSM channel scanner (SDR required)"),
            ("Osmocom NITB",   "osmo-nitb",       None, "🏠", "2G core simulation"),
            ("Metasploit",     "msfconsole",      None, "💀", "Exploit framework"),
            ("SigPloit",       "sigploit",        None, "📶", "SS7/Diameter fuzzer"),
            ("Docker",         "docker",          None, "🐳", "Container runtime"),
            ("Nuclei",         "nuclei",          None, "🧬", "Vulnerability scanner"),
            ("aircrack-ng",    "aircrack-ng",     None, "🔓", "Wireless security toolkit"),
        ]

        if st.session_state.demo_mode:
            st.info(
                "🌐 **Cloud Mode** — nmap and tshark are available. RF/SS7 tools require "
                "Docker (`docker-compose up`) or a Kali Linux install (`bash install.sh`).",
                icon="ℹ️"
            )

        # ── Cloud-available tools ──
        st.markdown("#### ✅ Available on Streamlit Cloud")
        cols = st.columns(3)
        for i, (name, cmd, flag, icon, desc) in enumerate(CLOUD_TOOLS):
            path = shutil.which(cmd)
            with cols[i % 3]:
                if path and flag:
                    import subprocess
                    try:
                        res = subprocess.run([cmd, flag], capture_output=True, text=True, timeout=5)
                        ver = (res.stdout + res.stderr).strip().split("\n")[0][:60]
                    except Exception:
                        ver = "installed"
                elif path:
                    ver = "installed"
                else:
                    ver = None

                color = "rgba(22,163,74,0.15)" if ver else "rgba(220,38,38,0.08)"
                border = "#16a34a" if ver else "#dc2626"
                status = f"<code style='font-size:0.7rem;color:#94a3b8'>{ver}</code>" if ver else "<span style='color:#dc2626'>Not found</span>"
                st.markdown(
                    f'<div style="background:{color};border:1px solid {border};border-radius:8px;'
                    f'padding:12px;margin-bottom:8px;">'
                    f'<div style="font-size:1.2rem">{icon} <b>{name}</b></div>'
                    f'<div style="color:#6b7280;font-size:0.78rem;margin:2px 0">{desc}</div>'
                    f'{status}</div>',
                    unsafe_allow_html=True,
                )

        # ── Kali/Docker-only tools ──
        st.markdown("#### 🐳 Requires Docker / Kali Linux")
        st.caption("These tools need a full Linux environment. Use `bash install.sh` or `docker-compose up`.")
        cols2 = st.columns(4)
        for i, (name, cmd, _, icon, desc) in enumerate(KALI_TOOLS):
            path = shutil.which(cmd)
            with cols2[i % 4]:
                color = "rgba(22,163,74,0.12)" if path else "rgba(255,255,255,0.03)"
                border = "#16a34a" if path else "rgba(255,255,255,0.1)"
                badge = "✅ Found" if path else "⬜ Not installed"
                st.markdown(
                    f'<div style="background:{color};border:1px solid {border};border-radius:8px;'
                    f'padding:10px;margin-bottom:8px;text-align:center;">'
                    f'<div style="font-size:1.1rem">{icon}</div>'
                    f'<div style="font-weight:600;font-size:0.85rem">{name}</div>'
                    f'<div style="color:#6b7280;font-size:0.7rem">{desc}</div>'
                    f'<div style="font-size:0.75rem;margin-top:4px">{badge}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

        st.markdown("---")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Quick Install (Linux/Kali):**")
            st.code("bash install.sh", language="bash")
        with c2:
            st.markdown("**Quick Install (Docker):**")
            st.code("docker-compose up", language="bash")

    with tab2:
        # ── Kali Cloud Tools Tab ──────────────────────────────────────────────
        try:
            from kali_connector import (
                health_check, run_tool, render_tool_result,
                run_nmap, run_nuclei, run_tshark, run_sigploit,
                run_aircrack, run_metasploit, run_hydra,
                run_svmap, run_dnsrecon, run_scapy_ss7,
            )
            _kali_ok = False
        except ImportError:
            st.error("kali_connector.py not found — make sure it is committed to the repo.")
            _kali_ok = False
            health_check = None  # type: ignore

        if health_check:
            status = health_check(force=False)
            _kali_ok = status["online"]

            # ── Live status dashboard ──
            st.subheader("☁️ Kali Cloud Health Dashboard")
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Status", "🟢 ONLINE" if _kali_ok else "🔴 OFFLINE")
            sc2.metric("Tools Ready", len(status["tools"]) if _kali_ok else "—")
            sc3.metric("Latency", f"{status['latency_ms']}ms" if _kali_ok else "—")
            sc4.metric("Uptime", f"{status['uptime_s']//60}m" if _kali_ok else "—")

            if _kali_ok:
                st.success(f"Backend URL: `{status['url']}`", icon="✅")
                if status["tools"]:
                    st.markdown("**Available tools:** " + " · ".join(
                        f"`{t}`" for t in status["tools"]
                    ))
                if st.button("🔄 Refresh Status", key="kali_refresh"):
                    health_check(force=True)
                    st.rerun()
            else:
                st.error(
                    f"**Error:** {status['error']}\n\n"
                    "**To restart the Kali backend, run in your Codespace terminal:**\n"
                    "```bash\n"
                    "docker start telsec-kali\n"
                    "docker exec -d telsec-kali bash -c "
                    "'cd /opt/telsec_api && TELSEC_API_KEY=telsec-kali-2024 "
                    "python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 "
                    "> /tmp/api.log 2>&1'\n"
                    "```\n"
                    "Then update **KALI_API_URL** in Streamlit Secrets if the Codespace URL changed.",
                    icon="🔴",
                )

            st.divider()

            # ── Tool runner ──
            st.subheader("🛠 Run Kali Tools")
            if not _kali_ok:
                st.warning("Tool runner disabled while backend is offline.", icon="❌")
            else:
                tool_cat = st.selectbox("Select Tool Category", [
                    "🔍 Scanning (nmap, nuclei)",
                    "🦈 Packet Capture (tshark)",
                    "📶 SS7/Telecom (SigPloit, Scapy-SS7)",
                    "📡 Wireless/SDR (aircrack-ng, gr-gsm, kalibrate-rtl)",
                    "💀 Exploitation (Metasploit, Hydra)",
                    "🌐 OSINT/Recon (svmap, dnsrecon, whois)",
                    "🐳 Osmocom / 2G Core",
                ], key="kc_cat")

                # ── SCANNING ─────────────────────────────────────────────────
                if "Scanning" in tool_cat:
                    st.markdown("#### 🔍 nmap")
                    col_a, col_b = st.columns([2,1])
                    tgt_nmap = col_a.text_input("Target (IP/CIDR/FQDN)", placeholder="192.168.1.0/24", key="kc_nmap_tgt")
                    flags_nmap = col_b.text_input("Flags", value="-sV -T4 --top-ports 100", key="kc_nmap_flags")
                    if st.button("▶ Run nmap", key="kc_nmap_run", type="primary"):
                        with st.spinner("Running nmap..."):
                            res = run_nmap(tgt_nmap, flags_nmap)
                        render_tool_result(res, "nmap")

                    st.markdown("#### 🧬 nuclei")
                    col_c, col_d = st.columns([2,1])
                    tgt_nuc = col_c.text_input("Target URL", placeholder="https://target.com", key="kc_nuc_tgt")
                    tmpl_nuc = col_d.text_input("Templates (blank=all)", placeholder="cves,network", key="kc_nuc_tmpl")
                    if st.button("▶ Run nuclei", key="kc_nuc_run", type="primary"):
                        with st.spinner("Running nuclei (may take 60s+)..."):
                            res = run_nuclei(tgt_nuc, tmpl_nuc)
                        render_tool_result(res, "nuclei")

                # ── PACKET CAPTURE ────────────────────────────────────────────
                elif "Packet" in tool_cat:
                    st.markdown("#### 🦈 tshark live capture")
                    col_e, col_f, col_g = st.columns(3)
                    iface = col_e.text_input("Interface", value="eth0", key="kc_ts_iface")
                    dur   = col_f.slider("Duration (sec)", 5, 60, 10, key="kc_ts_dur")
                    flt   = col_g.text_input("Display filter", placeholder="sctp or diameter", key="kc_ts_flt")
                    if st.button("▶ Capture", key="kc_ts_run", type="primary"):
                        with st.spinner(f"Capturing on {iface} for {dur}s..."):
                            res = run_tshark(iface, dur, flt)
                        render_tool_result(res, "tshark")

                    st.markdown("#### 📂 PCAP Upload & Analyze")
                    pcap_file = st.file_uploader("Upload .pcap / .pcapng", type=["pcap","pcapng"], key="kc_pcap_up")
                    pcap_flt  = st.text_input("Filter", placeholder="map or diameter or gtp", key="kc_pcap_flt")
                    if pcap_file and st.button("▶ Analyze PCAP", key="kc_pcap_run", type="primary"):
                        import base64
                        b64 = base64.b64encode(pcap_file.read()).decode()
                        from kali_connector import run_tshark_pcap
                        with st.spinner("Analyzing PCAP..."):
                            res = run_tshark_pcap(b64, pcap_flt)
                        render_tool_result(res, "tshark (pcap)")

                # ── SS7/TELECOM ───────────────────────────────────────────────
                elif "SS7" in tool_cat:
                    st.markdown("#### 📶 SigPloit")
                    sp_mode = st.selectbox("SigPloit Mode", ["ss7","diameter","gtp","sip"], key="kc_sp_mode")
                    sp_tgt  = st.text_input("Target GT / IP", key="kc_sp_tgt")
                    sp_extra = st.text_input("Extra args", key="kc_sp_extra")
                    if st.button("▶ Run SigPloit", key="kc_sp_run", type="primary"):
                        with st.spinner("Running SigPloit..."):
                            res = run_sigploit(sp_mode, sp_tgt, sp_extra)
                        render_tool_result(res, "SigPloit")

                    st.markdown("#### 📡 Scapy SS7 Probe (MAP ATI / SRI)")
                    ss7_gt  = st.text_input("Attacker GT", placeholder="441234567890", key="kc_ss7_gt")
                    ss7_msisdn = st.text_input("Target MSISDN", placeholder="+919XXXXXXXXX", key="kc_ss7_msisdn")
                    ss7_op  = st.selectbox("Operation", ["ATI","SRI","SRI_SM","SEND_IMSI"], key="kc_ss7_op")
                    if st.button("▶ Run SS7 Probe", key="kc_ss7_run", type="primary"):
                        with st.spinner("Probing via Scapy/SS7..."):
                            res = run_scapy_ss7(ss7_gt, ss7_msisdn, ss7_op)
                        render_tool_result(res, f"Scapy SS7 ({ss7_op})")

                # ── WIRELESS/SDR ──────────────────────────────────────────────
                elif "Wireless" in tool_cat:
                    st.info("SDR tools (gr-gsm, kalibrate-rtl) require a physical RTL-SDR dongle attached to the Codespace — not available in virtual environments.", icon="📡")
                    st.markdown("#### 🔓 aircrack-ng — WPA/WEP handshake analysis")
                    pcap_ac = st.file_uploader("Upload .cap handshake file", type=["cap","pcap"], key="kc_ac_cap")
                    wl_ac   = st.text_input("Wordlist path on Kali (e.g. /usr/share/wordlists/rockyou.txt)", key="kc_ac_wl")
                    if pcap_ac and st.button("▶ Run aircrack-ng", key="kc_ac_run", type="primary"):
                        with st.spinner("Running aircrack-ng..."):
                            res = run_aircrack("/tmp/upload.cap", wl_ac)
                        render_tool_result(res, "aircrack-ng")

                # ── EXPLOITATION ──────────────────────────────────────────────
                elif "Exploit" in tool_cat:
                    st.warning("⚠️ Only use on authorized targets. All actions are logged.", icon="⚠️")
                    st.markdown("#### 💀 Metasploit Module Runner")
                    msf_mod = st.text_input("Module path", placeholder="auxiliary/scanner/portscan/tcp", key="kc_msf_mod")
                    msf_opts_raw = st.text_area("Options (KEY=VALUE per line)", height=80, key="kc_msf_opts")
                    msf_opts = {}
                    for line in msf_opts_raw.strip().splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            msf_opts[k.strip()] = v.strip()
                    if st.button("▶ Run Module", key="kc_msf_run", type="primary"):
                        with st.spinner("Running Metasploit module..."):
                            res = run_metasploit(msf_mod, msf_opts)
                        render_tool_result(res, "Metasploit")

                    st.markdown("#### 🔨 Hydra — Service Brute Force")
                    col_h1, col_h2 = st.columns(2)
                    hy_tgt = col_h1.text_input("Target IP", key="kc_hy_tgt")
                    hy_svc = col_h1.selectbox("Service", ["ssh","ftp","telnet","smtp","http-post-form"], key="kc_hy_svc")
                    hy_usr = col_h2.text_input("Username", key="kc_hy_usr")
                    hy_wl  = col_h2.text_input("Wordlist path", value="/usr/share/wordlists/rockyou.txt", key="kc_hy_wl")
                    if st.button("▶ Run Hydra", key="kc_hy_run", type="primary"):
                        with st.spinner("Running Hydra..."):
                            res = run_hydra(hy_tgt, hy_svc, hy_usr, hy_wl)
                        render_tool_result(res, "Hydra")

                # ── OSINT/RECON ───────────────────────────────────────────────
                elif "OSINT" in tool_cat:
                    st.markdown("#### 📞 svmap — SIP Scanner")
                    svm_tgt = st.text_input("Target IP/Range", key="kc_svm_tgt")
                    if st.button("▶ Run svmap", key="kc_svm_run", type="primary"):
                        with st.spinner("Running svmap..."):
                            res = run_svmap(svm_tgt)
                        render_tool_result(res, "svmap")

                    st.markdown("#### 🌐 dnsrecon")
                    dns_dom = st.text_input("Target Domain", key="kc_dns_dom")
                    dns_typ = st.text_input("Types", value="std,rvl", key="kc_dns_typ")
                    if st.button("▶ Run dnsrecon", key="kc_dns_run", type="primary"):
                        with st.spinner("Running dnsrecon..."):
                            res = run_dnsrecon(dns_dom, dns_typ)
                        render_tool_result(res, "dnsrecon")

                # ── OSMOCOM ───────────────────────────────────────────────────
                elif "Osmocom" in tool_cat:
                    st.info(
                        "Osmocom NITB provides 2G GSM core simulation. Requires a physical BTS (e.g. Motorola C118 or NanoBTS).\n"
                        "In Docker/Codespace mode it can test config generation and SMS routing logic only.",
                        icon="🏠",
                    )
                    if st.button("▶ Test osmo-nitb config", key="kc_osmo_run", type="primary"):
                        with st.spinner("Testing Osmocom config..."):
                            res = run_tool("osmocom", {"mode": "config_test"})
                        render_tool_result(res, "Osmocom NITB")


    with tab3:

        try:
            import psutil
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            c1, c2, c3 = st.columns(3)
            c1.metric("CPU Usage", f"{cpu}%")
            c2.metric("RAM Used", f"{ram.percent}%",
                      f"{ram.used//1024//1024} MB / {ram.total//1024//1024} MB")
            c3.metric("Disk Used", f"{disk.percent}%",
                      f"{disk.used//1024//1024//1024} GB / {disk.total//1024//1024//1024} GB")

            # CPU chart
            fig = go.Figure(go.Bar(
                x=["CPU", "RAM", "Disk"],
                y=[cpu, ram.percent, disk.percent],
                marker_color=["#e94560", "#0f3460", "#533483"],
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e6f0", height=200, showlegend=False,
                yaxis=dict(range=[0, 100], ticksuffix="%"),
            )
            st.plotly_chart(fig, use_container_width=True)
        except ImportError:
            st.warning("psutil not installed — run: pip install psutil")

        st.markdown(f"**Python:** {sys.version}")
        st.markdown(f"**OS:** {platform.system()} {platform.release()}")
        st.markdown(f"**Architecture:** {platform.machine()}")

    with tab3:
        from utils.logger import get_audit_log
        level_filter = st.selectbox("Filter by Level", ["ALL", "INFO", "WARNING", "ERROR"])
        logs = get_audit_log(
            limit=100, level=None if level_filter == "ALL" else level_filter
        )
        if logs:
            log_df = pd.DataFrame(logs)[["ts", "level", "module", "message"]]
            st.dataframe(log_df, use_container_width=True, height=400, hide_index=True)
        else:
            st.info("No audit log entries yet.")

    with tab4:
        st.info("Tab 4 content placeholder - reserved for future features")
# ============================================================
# MODULE ROUTING (all 12 advanced pages)
# ============================================================
import importlib, sys as _sys

_PAGE_MODULE_MAP = {
    "Home":                            "pages.0_home",
    "Mission Control":                 "pages.0_landing",
    # Protocol Security
    "SS7 Analyzer":         "pages.6_ss7_analyzer",
    "Diameter Audit":       "pages.7_diameter_audit",
    "GTP Inspector":        "pages.8_gtp_inspector",
    "SS7 GT Scanner":       "pages.16_ss7_scanner",
    "Protocol Lab":         "pages.19_protocol_lab",
    
    # Active Testing
    "Active Exploits":      "pages.1_active_exploits",
    "SigPloit / SS7 Attack":"pages.13_sigploit_ss7",
    "SIP / VoLTE Testing":  "pages.14_sip_volte",
    "Offensive Toolkit":    "pages.15_offensive_toolkit",
    
    # 5G / Next-Gen
    "5G Security":          "pages.2_5g_security",
    "UERANSIM Lab":         "pages.11_ueransim",
    "5G NAS Security":      "pages.12_5g_nas_security",
    "5G Traffic Replay":    "pages.17_5g_replay",
    "Open5GS Monitor":      "pages.9_open5gs_monitor",
    
    # Threat & Detection
    "Threat Intel":         "pages.10_threat_intel",
    "Threat Detection":     "pages.18_threat_detection",
    "Compliance Mapper":    "pages.5_compliance_mapper",
    "Recon & Intelligence": "pages.3_recon_intelligence",
    
    # Analysis Tools
    "Protocol Fuzzing":     "pages.4_protocol_fuzzing",

    # System
    "Tools & Environment":  "pages.20_tools_environment",
}

_SECTION_SEPARATORS = {
    "── Protocol Security ──",
    "── Active Testing ──",
    "── 5G / Next-Gen ──",
    "── Threat & Detection ──",
    "── Analysis Tools ──",
    "── System ──",
}

if page in _PAGE_MODULE_MAP:
    _mod_name = _PAGE_MODULE_MAP[page]
    _sys.modules.pop(_mod_name, None)
    try:
        _mod = importlib.import_module(_mod_name)
    except Exception as _e:
        st.error(f"❌ Could not load module `{_mod_name}`: {_e}")
        st.exception(_e)
elif page in _SECTION_SEPARATORS:
    _section_label = page.replace("──", "").strip()
    st.markdown(f"""
    <div class="page-hero">
      <div class="page-hero-icon">📂</div>
      <div>
        <div class="page-hero-title">{_section_label}</div>
        <div class="page-hero-sub">Select a module from the sidebar</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# Footer
# ============================================================
st.markdown("""
<div style="text-align:center; color:#64748b; font-size:0.8rem; padding:40px 0 10px;
     border-top:1px solid rgba(255,255,255,0.05); margin-top:40px;">
  TelSec v2.0 &nbsp;·&nbsp;
  <strong style="color:#ef4444;">⚠️ For authorized security testing only</strong> &nbsp;·&nbsp;
  <a href="https://www.gsma.com/security" style="color:#94a3b8;text-decoration:none;">GSMA Security</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/techdiplomat/telsec" style="color:#94a3b8;text-decoration:none;">GitHub</a>
</div>
""", unsafe_allow_html=True)
