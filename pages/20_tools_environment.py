"""
pages/tools_and_environment_stub.py — redirects to the main Tools & Environment content.

NOTE: This file is NOT standalone — it is loaded by app.py when the user selects
"Tools & Environment" from the sidebar. The file number does not appear in the nav.
"""
import streamlit as st
import platform, shutil, os
from kali_connector import health_check, run_tool, render_kali_status_banner, render_tool_result, TOOL_ENDPOINTS

# ─────────────────────────────────────────────────────────────────────────────
# Page hero
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
body, .stApp { font-family: 'Inter', sans-serif !important; background:#0a0f1e; }
.page-hero {
    display:flex;align-items:center;gap:16px;
    background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(139,92,246,.04));
    border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:20px 24px;margin-bottom:24px;
}
.page-hero-icon{font-size:2.2rem;} .page-hero-title{font-size:1.4rem;font-weight:700;color:#f8fafc;}
.page-hero-sub{font-size:.85rem;color:#94a3b8;margin-top:2px;}
.setup-step {
    background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);
    border-radius:10px;padding:16px 20px;margin-bottom:10px;
    display:flex;gap:16px;align-items:flex-start;
}
.step-num {
    background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);
    border-radius:50%;width:32px;height:32px;min-width:32px;
    display:flex;align-items:center;justify-content:center;
    font-weight:800;font-size:.9rem;color:#60a5fa;
}
.step-body { flex:1; }
.step-title { font-weight:600;font-size:.9rem;color:#f8fafc;margin-bottom:4px; }
.step-desc  { font-size:.8rem;color:#94a3b8;line-height:1.5; }
.tool-grid {
    display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:8px;
    margin-top:12px;
}
.tool-chip {
    background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
    border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:8px;
    font-size:.8rem;
}
.tool-dot { width:8px;height:8px;border-radius:50%;flex-shrink:0; }
.tool-dot-blue { background:#3b82f6; }
.tool-dot-violet { background:#8b5cf6; }
.tool-dot-emerald { background:#10b981; }
.tool-dot-amber { background:#f59e0b; }
.tool-dot-rose { background:#f43f5e; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">⚙️</div>
  <div>
    <div class="page-hero-title">Tools & Backend Environment</div>
    <div class="page-hero-sub">Kali Cloud status · setup guide · tool inventory · system diagnostics</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
tab_status, tab_setup, tab_tools, tab_diag = st.tabs([
    "☁️ Kali Cloud Status", "🚀 Setup Guide", "🛠️ Tool Inventory", "🖥️ System Info"
])

# ═══════════════════════════════════════════════════════════════════════
# TAB 1 — KALI CLOUD STATUS
# ═══════════════════════════════════════════════════════════════════════
with tab_status:
    st.markdown("#### Kali Cloud Backend Health")

    col_refresh, _ = st.columns([1, 6])
    if col_refresh.button("🔄 Refresh", key="btn_refresh_health"):
        health = health_check(force=True)
    else:
        health = health_check()

    if health["online"]:
        st.markdown(f"""
        <div style='background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25);
          border-radius:12px;padding:20px 24px;display:flex;gap:24px;align-items:center;margin:12px 0'>
          <div style='font-size:2.4rem'>✅</div>
          <div>
            <div style='font-size:1.1rem;font-weight:700;color:#10b981'>Kali Cloud Online</div>
            <div style='font-size:.82rem;color:#94a3b8;margin-top:4px'>
              {len(health['tools'])} tools active · Latency {health['latency_ms']}ms ·
              Uptime {health['uptime_s']//60}m · URL: <code>{health['url']}</code>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style='background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.2);
          border-radius:12px;padding:20px 24px;display:flex;gap:24px;align-items:center;margin:12px 0'>
          <div style='font-size:2.4rem'>🔴</div>
          <div>
            <div style='font-size:1.1rem;font-weight:700;color:#ef4444'>Kali Cloud Offline</div>
            <div style='font-size:.82rem;color:#94a3b8;margin-top:4px'>
              {health.get('error','Unknown error')} — Running in <b>Demo Mode</b>
              (simulated output on all tool pages)
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.info("👉 Head to the **Setup Guide** tab to start your Kali backend in under 2 minutes.", icon="💡")

# ═══════════════════════════════════════════════════════════════════════
# TAB 2 — SETUP GUIDE
# ═══════════════════════════════════════════════════════════════════════
with tab_setup:
    st.markdown("#### How to Connect the Kali Cloud Backend")
    st.caption("Follow these steps to bring all 26 tools online from your GitHub Codespace.")

    steps = [
        (
            "Open your Kali Codespace",
            "Go to <b>github.com/techdiplomat/telsec</b> → Code → Codespaces "
            "and open or resume the <code>telsec-kali</code> Codespace. "
            "It takes ~60 seconds to wake from sleep.",
        ),
        (
            "Start the API server",
            "In the Codespace terminal, run:"
        ),
        (
            "Copy the Codespace URL",
            "The URL looks like: "
            "<code>https://&lt;name&gt;-8000.app.github.dev</code>. "
            "Copy <b>only the base URL</b> (everything before <code>/</code> at the end).",
        ),
        (
            "Set KALI_API_URL in Streamlit Secrets",
            "Go to <b>share.streamlit.io</b> → your app → Settings → Secrets and add:<br>"
            "<code>KALI_API_URL = \"https://&lt;your-codespace-url&gt;-8000.app.github.dev\"</code>"
        ),
        (
            "Reload TelSec",
            "Reload this app — the sidebar will show a <span style='color:#10b981'>●&nbsp;Backend Online</span> "
            "dot and all tool buttons will execute commands on the Kali instance."
        ),
    ]

    for i, (title, desc) in enumerate(steps, 1):
        st.markdown(f"""
        <div class="setup-step">
          <div class="step-num">{i}</div>
          <div class="step-body">
            <div class="step-title">{title}</div>
            <div class="step-desc">{desc}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        if i == 2:
            st.code(
                "cd /workspaces/telsec/kali_backend\n"
                "TELSEC_API_KEY=telsec-kali-2024 \\\n"
                "  python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload",
                language="bash"
            )

    st.markdown("---")
    st.markdown("#### Quick Health Check")
    url_input = st.text_input("Enter KALI_API_URL to test", placeholder="https://xxx-8000.app.github.dev", key="hc_url_input")
    if st.button("🔌 Test Connection", type="primary", key="btn_test_conn"):
        import os
        os.environ["KALI_API_URL"] = url_input.rstrip("/")
        result = health_check(force=True)
        if result["online"]:
            st.success(f"✅ Connected! {len(result['tools'])} tools available. Latency: {result['latency_ms']}ms")
        else:
            st.error(f"❌ Could not connect: {result.get('error')}")

# ═══════════════════════════════════════════════════════════════════════
# TAB 3 — TOOL INVENTORY
# ═══════════════════════════════════════════════════════════════════════
with tab_tools:
    st.markdown("#### All 26 Tool Endpoints — What Goes Live When Backend Connects")

    TOOL_CATALOG = [
        # (name, category, description, color)
        ("nuclei",       "CVE Scanning",    "Nuclei — CVE, misconfig, 5G template scanner",        "rose"),
        ("nmap",         "Reconnaissance",  "Nmap — port/service/version scanning",                "blue"),
        ("tshark",       "Traffic Capture", "TShark — live interface packet capture",              "violet"),
        ("tshark-pcap",  "Traffic Capture", "TShark — offline PCAP analysis with filter",         "violet"),
        ("aircrack",     "Wireless",        "Aircrack-ng — WPA/WEP key cracking from PCAP",       "amber"),
        ("metasploit",   "Exploitation",    "Metasploit — module-based exploit framework",         "rose"),
        ("hydra",        "Brute Force",     "Hydra — credential attacks on SSH, SIP, HTTP",       "rose"),
        ("sigploit",     "SS7/Diameter",    "SigPloit — SS7 MAP/GTP/Diameter attack toolkit",     "blue"),
        ("osmocom",      "GSM/Radio",       "OsmocomBB — 2G baseband radio interaction",          "amber"),
        ("gr-gsm",       "GSM/Radio",       "GR-GSM — Software-defined radio GSM capture",        "amber"),
        ("kalibrate",    "GSM/Radio",       "Kalibrate-RTL — GSM channel frequency scanner",      "amber"),
        ("scapy-ss7",    "SS7 Probing",     "Scapy-SS7 — craft and send raw MAP/SCCP packets",    "blue"),
        ("svmap",        "VoIP/SIP",        "SVMap — SIP endpoint network scanner",               "violet"),
        ("svwar",        "VoIP/SIP",        "SVWar — SIP extension enumerator",                   "violet"),
        ("dnsrecon",     "Recon/OSINT",     "DNSRecon — DNS record and zone enumeration",         "emerald"),
        ("whois",        "Recon/OSINT",     "WHOIS — domain and network registration lookup",     "emerald"),
        ("gtscan",       "SS7 Probing",     "GTScan — SS7 Global Title prefix enumerator",        "blue"),
        ("sigshark",     "SS7 Analysis",    "SigShark — SS7/Diameter deep PCAP analysis",         "blue"),
        ("sctpscan",     "SS7/SIGTRAN",     "SCTPScan — SCTP/M3UA peer discovery scanner",        "violet"),
        ("5greplay",     "5G Testing",      "5GReplay — GTP/NGAP PCAP replay engine",             "emerald"),
        ("scat",         "5G Analysis",     "SCAT — 5G NAS diagnostic log analyzer",               "emerald"),
        ("lucid",        "AI Detection",    "LUCID — CNN-based DDoS & anomaly classifier",         "rose"),
        ("mobiwatch",    "5G NAS",          "Mobiwatch — 5G NAS protocol analyzer",               "emerald"),
        ("zmap",         "Recon/OSINT",     "Zmap — internet-scale port scanner",                 "emerald"),
        ("sigfw",        "Firewall",        "SigFW — SS7/Diameter signaling firewall",             "amber"),
        ("5gbasechecker","5G Security",     "5GBaseChecker — 5G NAS security baseline audit",     "emerald"),
    ]

    # Group by category
    from collections import defaultdict
    groups = defaultdict(list)
    for item in TOOL_CATALOG:
        groups[item[1]].append(item)

    health = health_check()
    live_tools = set(health.get("tools", []))

    for category, tools in sorted(groups.items()):
        st.markdown(f"**{category}**")
        cols = st.columns(3)
        for idx, (name, cat, desc, color) in enumerate(tools):
            is_live = name in live_tools or health["online"]
            status_dot = "🟢" if is_live else "⚫"
            with cols[idx % 3]:
                st.markdown(f"""
                <div class="tool-chip">
                  <div class="tool-dot tool-dot-{color}"></div>
                  <div>
                    <div style="font-weight:600;color:#f8fafc">{status_dot} {name}</div>
                    <div style="font-size:.7rem;color:#64748b">{desc[:55]}…</div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════
# TAB 4 — SYSTEM INFO
# ═══════════════════════════════════════════════════════════════════════
with tab_diag:
    st.markdown("#### Local System Diagnostics")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**Python:** `{platform.python_version()}`")
        st.markdown(f"**OS:** `{platform.system()} {platform.release()}`")
        st.markdown(f"**Streamlit:** `{st.__version__}`")
    with c2:
        st.markdown(f"**KALI_API_URL:** `{os.environ.get('KALI_API_URL','(not set in env)')} `")
        try:
            import streamlit as _st
            kali_url = _st.secrets.get("KALI_API_URL", "(not set in Secrets)")
        except Exception:
            kali_url = "(Secrets not available)"
        st.markdown(f"**Secret KALI_API_URL:** `{kali_url}`")

    st.markdown("---")
    st.markdown("#### Run a quick tool test")
    test_tool = st.selectbox("Tool", list(TOOL_ENDPOINTS.keys()), key="diag_test_tool")
    test_params = st.text_input("Params (JSON)", '{"target": "8.8.8.8"}', key="diag_params")
    if st.button("▶️ Run Tool Test", key="btn_diag_run"):
        import json as _json
        try:
            params = _json.loads(test_params)
        except Exception:
            params = {}
        with st.spinner(f"Running {test_tool}..."):
            result = run_tool(test_tool, params)
        render_tool_result(result, test_tool)
