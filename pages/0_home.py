"""
pages/0_home.py — TelSec Dashboard & Landing Page
Provides: disclaimer modal, quick-start guide, module card grid, session KPIs
"""
import streamlit as st
from datetime import datetime

# ─────────────────────────────────────────────────────────────────
# CSS — additional home-page styles (builds on app.py globals)
# ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Module category cards */
.module-card {
    background: rgba(13,21,38,0.85);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 14px;
    padding: 20px 18px 16px;
    transition: all 0.2s cubic-bezier(0.4,0,0.2,1);
    position: relative; overflow: hidden;
    height: 100%;
}
.module-card:hover {
    border-color: rgba(99,179,237,0.35);
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(99,179,237,0.1);
}
.module-card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
}
.card-proto::before  { background: linear-gradient(90deg, #3b82f6, #06b6d4); }
.card-active::before { background: linear-gradient(90deg, #ef4444, #f97316); }
.card-5g::before     { background: linear-gradient(90deg, #8b5cf6, #ec4899); }
.card-threat::before { background: linear-gradient(90deg, #10b981, #3b82f6); }
.card-analysis::before { background: linear-gradient(90deg, #f59e0b, #10b981); }
.card-system::before { background: linear-gradient(90deg, #64748b, #94a3b8); }

.module-card-icon {
    font-size: 1.8rem; margin-bottom: 10px; display: block;
}
.module-card-title {
    font-size: 0.95rem; font-weight: 700; color: #e2e8f0; margin-bottom: 4px;
}
.module-card-desc {
    font-size: 0.78rem; color: #64748b; line-height: 1.5; margin-bottom: 10px;
}
.module-card-tools {
    display: flex; flex-wrap: wrap; gap: 4px;
}
.tool-tag {
    font-size: 0.68rem; background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08); border-radius: 4px;
    padding: 2px 7px; color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
}
/* KPI cards */
.kpi-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 28px;
}
.kpi-card {
    background: rgba(13,21,38,0.85);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 12px; padding: 16px 18px;
    position: relative; overflow: hidden;
}
.kpi-card::after {
    content: ""; position: absolute; bottom: 0; left: 0; right: 0; height: 2px;
}
.kpi-critical::after { background: #ef4444; }
.kpi-high::after     { background: #f97316; }
.kpi-total::after    { background: #3b82f6; }
.kpi-auth::after     { background: #10b981; }
.kpi-label { font-size: 0.68rem; color: #475569; text-transform: uppercase; letter-spacing: .08em; font-weight: 600; }
.kpi-value { font-size: 2rem; font-weight: 800; line-height: 1.1; margin-top: 4px; }
.kpi-sub   { font-size: 0.72rem; color: #64748b; margin-top: 2px; }
/* Step guide */
.step-card {
    background: rgba(13,21,38,0.6);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 12px; padding: 16px;
    display: flex; align-items: flex-start; gap: 14px;
}
.step-num {
    width: 32px; height: 32px; border-radius: 50%; flex-shrink: 0;
    background: rgba(59,130,246,0.15); border: 1px solid rgba(59,130,246,0.3);
    display: flex; align-items: center; justify-content: center;
    font-size: 0.9rem; font-weight: 800; color: #60a5fa;
}
.step-title { font-size: 0.88rem; font-weight: 700; color: #e2e8f0; }
.step-desc  { font-size: 0.78rem; color: #64748b; margin-top: 2px; line-height: 1.4; }
/* Disclaimer modal overlay */
.disclaimer-overlay {
    position: fixed; inset: 0; z-index: 9999;
    background: rgba(7,11,20,0.92); backdrop-filter: blur(8px);
    display: flex; align-items: center; justify-content: center;
}
.disclaimer-box {
    background: #0d1321; border: 1px solid rgba(239,68,68,0.3);
    border-radius: 16px; padding: 36px 40px; max-width: 560px; width: 90%;
    box-shadow: 0 20px 60px rgba(0,0,0,0.7), 0 0 0 1px rgba(239,68,68,0.15);
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────
# DISCLAIMER MODAL (first visit)
# ─────────────────────────────────────────────────────────────────
if "disclaimer_accepted" not in st.session_state:
    st.session_state.disclaimer_accepted = False

if not st.session_state.disclaimer_accepted:
    st.markdown("""
    <div style="
        background: rgba(7,11,20,0.95); border: 1px solid rgba(239,68,68,0.3);
        border-radius: 16px; padding: 32px 36px; margin: 40px auto; max-width: 600px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.7);
    ">
      <div style="font-size:2rem; margin-bottom:12px;">⚠️</div>
      <div style="font-size:1.2rem; font-weight:800; color:#f8fafc; margin-bottom:8px;">
        Authorized Use Only
      </div>
      <div style="font-size:0.88rem; color:#94a3b8; line-height:1.7; margin-bottom:20px;">
        TelSec is a professional telecom penetration testing framework. By continuing, you confirm that:
      </div>
      <ul style="font-size:0.85rem; color:#cbd5e1; line-height:2; padding-left:18px; margin-bottom:24px;">
        <li>You have <strong style="color:#f8fafc;">explicit written authorization</strong> from the network operator or system owner.</li>
        <li>All testing is conducted within a <strong style="color:#f8fafc;">controlled, authorized lab or production scope</strong>.</li>
        <li>You understand that unauthorized use of these tools is <strong style="color:#ef4444;">illegal</strong> under applicable law (CFAA, Computer Misuse Act, TRAI regulations, etc.).</li>
        <li>All sessions are <strong style="color:#f8fafc;">automatically logged</strong> for audit purposes.</li>
      </ul>
      <div style="font-size:0.78rem; color:#475569; margin-bottom:20px; padding:12px; background:rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.12); border-radius:8px;">
        📖 GSMA FS.11 · 3GPP TS 33.117 · ETSI TS 102 165-1 — Security testing frameworks applicable.
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_agree, col_decline = st.columns([1, 1])
    with col_agree:
        if st.button("✅ I Agree — Enter TelSec", type="primary", use_container_width=True):
            st.session_state.disclaimer_accepted = True
            st.rerun()
    with col_decline:
        if st.button("❌ Decline — Exit", use_container_width=True):
            st.error("Access denied. Close this browser tab.")
            st.stop()
    st.stop()

# ─────────────────────────────────────────────────────────────────
# MAIN DASHBOARD (post disclaimer)
# ─────────────────────────────────────────────────────────────────

# ── Page hero ────────────────────────────────────────────────────
st.markdown("""
<div style="
    background: linear-gradient(135deg, rgba(59,130,246,0.08) 0%, rgba(139,92,246,0.05) 100%);
    border: 1px solid rgba(255,255,255,0.07); border-radius: 16px;
    padding: 28px 32px; margin-bottom: 28px; position: relative; overflow: hidden;
">
  <div style="position:absolute;top:0;left:0;right:0;height:2px;
    background:linear-gradient(90deg,#3b82f6,#8b5cf6,#06b6d4);"></div>
  <div style="display:flex;align-items:center;gap:20px;">
    <div style="font-size:3rem;line-height:1;">🔐</div>
    <div>
      <div style="font-size:1.6rem;font-weight:800;color:#f8fafc;letter-spacing:-0.02em;">
        TelSec — Telecom Security Framework
      </div>
      <div style="font-size:0.88rem;color:#94a3b8;margin-top:5px;line-height:1.5;">
        Professional penetration testing for SS7, Diameter, GTP, 5G NAS, SIP/VoLTE · 
        Covers 2G through 5G/6G · GSMA FS.11 / 3GPP TS 33.117 aligned
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Session KPI cards ─────────────────────────────────────────────
findings = st.session_state.get("findings", [])
critical = sum(1 for f in findings if f.get("severity") == "CRITICAL" and f.get("status") == "FAIL")
high     = sum(1 for f in findings if f.get("severity") == "HIGH"     and f.get("status") == "FAIL")
total    = sum(1 for f in findings if f.get("status") == "FAIL")
authorized = st.session_state.get("authorized", False)
last_scan  = st.session_state.get("last_scan") or "No scan yet"

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class="kpi-card kpi-critical">
      <div class="kpi-label">Critical Findings</div>
      <div class="kpi-value" style="color:#ef4444;">{critical}</div>
      <div class="kpi-sub">Immediate action required</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="kpi-card kpi-high">
      <div class="kpi-label">High Findings</div>
      <div class="kpi-value" style="color:#f97316;">{high}</div>
      <div class="kpi-sub">High risk vulnerabilities</div>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="kpi-card kpi-total">
      <div class="kpi-label">Total Failures</div>
      <div class="kpi-value" style="color:#3b82f6;">{total}</div>
      <div class="kpi-sub">Last: {last_scan}</div>
    </div>""", unsafe_allow_html=True)

with c4:
    auth_color = "#10b981" if authorized else "#ef4444"
    auth_label = "Authorized" if authorized else "Unauthorized"
    auth_icon  = "✅" if authorized else "🔴"
    st.markdown(f"""
    <div class="kpi-card kpi-auth">
      <div class="kpi-label">Session Status</div>
      <div class="kpi-value" style="color:{auth_color};font-size:1.1rem;padding-top:6px;">
        {auth_icon} {auth_label}
      </div>
      <div class="kpi-sub">Auth ref: {st.session_state.get('auth_ref') or '—'}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

# New session button
col_ns, col_spacer = st.columns([1, 3])
with col_ns:
    if st.button("🔄 New Session", use_container_width=True, help="Clear all findings and reset session data"):
        st.session_state.findings = []
        st.session_state.last_scan = None
        st.session_state.authorized = False
        st.session_state.auth_ref = ""
        st.rerun()

st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

# ── Quick-start guide ─────────────────────────────────────────────
st.markdown("""
<div style="font-size:0.72rem;font-weight:700;color:#475569;text-transform:uppercase;
     letter-spacing:.1em;margin-bottom:12px;">⚡ Quick Start</div>
""", unsafe_allow_html=True)

s1, s2, s3 = st.columns(3)

with s1:
    st.markdown("""
    <div class="step-card">
      <div class="step-num">1</div>
      <div>
        <div class="step-title">Wake the Backend</div>
        <div class="step-desc">Click "⚡ Auto-Wake Backend" if the status strip shows offline. Wait 30–60 seconds for the Kali Cloud container to initialize.</div>
      </div>
    </div>""", unsafe_allow_html=True)

with s2:
    st.markdown("""
    <div class="step-card">
      <div class="step-num">2</div>
      <div>
        <div class="step-title">Select a Module</div>
        <div class="step-desc">Choose a security testing module from the sidebar. Each module maps to a specific protocol layer or attack vector.</div>
      </div>
    </div>""", unsafe_allow_html=True)

with s3:
    st.markdown("""
    <div class="step-card">
      <div class="step-num">3</div>
      <div>
        <div class="step-title">Configure & Launch</div>
        <div class="step-desc">Set target parameters, verify scope authorization, then execute. Results appear inline with CVSS scoring and remediation guidance.</div>
      </div>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

# ── Module overview grid ──────────────────────────────────────────
st.markdown("""
<div style="font-size:0.72rem;font-weight:700;color:#475569;text-transform:uppercase;
     letter-spacing:.1em;margin-bottom:14px;">🗂️ Module Overview</div>
""", unsafe_allow_html=True)

MODULES = [
    {
        "key": "proto",
        "icon": "📡",
        "title": "Protocol Security",
        "desc": "Deep inspection and vulnerability scanning of core 2G–4G signaling protocols using live packet analysis.",
        "tools": ["SS7 Analyzer", "Diameter Audit", "GTP Inspector", "SS7 GT Scanner", "Protocol Lab"],
        "cls": "card-proto",
        "color": "#3b82f6",
    },
    {
        "key": "active",
        "icon": "🔴",
        "title": "Active Testing",
        "desc": "Authorized offensive modules for exploiting SS7 MAP vulnerabilities, SIP attacks, and active network fuzzing.",
        "tools": ["Active Exploits", "SigPloit SS7", "SIP/VoLTE", "Offensive Toolkit"],
        "cls": "card-active",
        "color": "#ef4444",
    },
    {
        "key": "5g",
        "icon": "🚀",
        "title": "5G / Next-Gen",
        "desc": "5G NAS security testing, UERANSIM simulation, N2/N3 interface analysis and Open5GS core monitoring.",
        "tools": ["5G Security", "UERANSIM Lab", "5G NAS Security", "5G Replay", "Open5GS Monitor"],
        "cls": "card-5g",
        "color": "#8b5cf6",
    },
    {
        "key": "threat",
        "icon": "🛡️",
        "title": "Threat & Detection",
        "desc": "Threat intelligence correlation, anomaly detection, GSMA compliance mapping and telecom OSINT recon.",
        "tools": ["Threat Intel", "Threat Detection", "Compliance Mapper", "Recon & Intelligence"],
        "cls": "card-threat",
        "color": "#10b981",
    },
    {
        "key": "analysis",
        "icon": "🔬",
        "title": "Analysis Tools",
        "desc": "Automated protocol fuzzing for SS7, Diameter, GTP and SIP with mutation engine and coverage tracking.",
        "tools": ["Protocol Fuzzing"],
        "cls": "card-analysis",
        "color": "#f59e0b",
    },
    {
        "key": "system",
        "icon": "⚙️",
        "title": "System",
        "desc": "Kali Cloud status dashboard, local tool inventory, system resources, and full audit log review.",
        "tools": ["Tools & Environment"],
        "cls": "card-system",
        "color": "#64748b",
    },
]

# Render 3-column grid
row1 = st.columns(3)
row2 = st.columns(3)
all_cols = row1 + row2

for col, mod in zip(all_cols, MODULES):
    with col:
        tags_html = "".join(f'<span class="tool-tag">{t}</span>' for t in mod["tools"])
        st.markdown(f"""
        <div class="module-card {mod['cls']}">
          <span class="module-card-icon">{mod['icon']}</span>
          <div class="module-card-title">{mod['title']}</div>
          <div class="module-card-desc">{mod['desc']}</div>
          <div class="module-card-tools">{tags_html}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='height:2px'></div>", unsafe_allow_html=True)

st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

# ── Coverage summary ──────────────────────────────────────────────
st.markdown("""
<div style="background:rgba(13,21,38,0.6);border:1px solid rgba(255,255,255,0.06);
     border-radius:12px;padding:20px 24px;display:flex;flex-wrap:wrap;gap:32px;align-items:center;">
  <div style="flex:1;min-width:200px;">
    <div style="font-size:0.72rem;color:#475569;text-transform:uppercase;letter-spacing:.08em;font-weight:700;margin-bottom:8px;">Coverage</div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
      <div style="text-align:center;">
        <div style="font-size:1.4rem;font-weight:800;color:#3b82f6;">21</div>
        <div style="font-size:0.68rem;color:#64748b;">Modules</div>
      </div>
      <div style="text-align:center;">
        <div style="font-size:1.4rem;font-weight:800;color:#10b981;">28+</div>
        <div style="font-size:0.68rem;color:#64748b;">Tools Wired</div>
      </div>
      <div style="text-align:center;">
        <div style="font-size:1.4rem;font-weight:800;color:#8b5cf6;">2G–5G</div>
        <div style="font-size:0.68rem;color:#64748b;">Generations</div>
      </div>
      <div style="text-align:center;">
        <div style="font-size:1.4rem;font-weight:800;color:#f59e0b;">FS.11</div>
        <div style="font-size:0.68rem;color:#64748b;">GSMA Aligned</div>
      </div>
    </div>
  </div>
  <div style="font-size:0.8rem;color:#64748b;max-width:320px;line-height:1.6;">
    All modules operate in <strong style="color:#f59e0b;">Simulation Mode</strong> by default. 
    Connect a Kali Cloud backend to enable live tool execution on authorized targets.
  </div>
</div>
""", unsafe_allow_html=True)
