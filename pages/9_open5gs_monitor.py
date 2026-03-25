"""
pages/9_open5gs_monitor.py — Open5GS 5G Core Monitor
Wired to: nmap, tshark, nuclei, mobiwatch
"""
import streamlit as st
from kali_connector import run_tool, render_tool_result
try:
    from kali_connector import render_kali_status_mini
except ImportError:
    import streamlit as _st
    def render_kali_status_mini():
        with _st.expander("💡 Running in Demo Mode — expand to connect Kali", expanded=False):
            _st.info("Set KALI_API_URL in Streamlit Secrets and restart the backend to enable live tools.")
        return False
try:
    from kali_connector import render_kali_status_mini
except ImportError:
    import streamlit as _st
    def render_kali_status_mini():
        with _st.expander("💡 Running in Demo Mode — expand to connect Kali", expanded=False):
            _st.info("Set KALI_API_URL in Streamlit Secrets and restart the backend to enable live tools.")
        return False

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap');
body, .stApp { font-family: 'Inter', sans-serif !important; background:#0a0f1e; }
.page-hero {
    display:flex; align-items:center; gap:16px;
    background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(139,92,246,.04));
    border:1px solid rgba(255,255,255,.06); border-radius:14px; padding:20px 24px; margin-bottom:24px;
}
.page-hero-icon { font-size:2.2rem; }
.page-hero-title { font-size:1.4rem; font-weight:700; color:#f8fafc; }
.page-hero-sub { font-size:0.85rem; color:#94a3b8; margin-top:2px; }
.nf-card {
    background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07);
    border-radius:10px; padding:16px; text-align:center; margin-bottom:8px;
}
.nf-name  { font-weight:700; font-size:1rem; color:#f8fafc; }
.nf-desc  { font-size:.78rem; color:#64748b; margin-top:4px; }
.nf-green { border-color:rgba(16,185,129,.3); }
.nf-red   { border-color:rgba(239,68,68,.3); }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🧬</div>
  <div>
    <div class="page-hero-title">Open5GS Core Monitor</div>
    <div class="page-hero-sub">5G SA/NSA core network function health, SBI interface audit, and vulnerability scanning</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs(["🏥 NF Status Dashboard", "🔍 SBI Port Audit", "💉 Core Vulnerability Scan"])

# ─────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("#### 5G Core Network Function Health Dashboard")
    st.caption("Monitor Open5GS NF status — configure the Open5GS host below.")
    og_host = st.text_input("Open5GS Host IP", "127.0.0.1", key="og_host")

    nfs = [
        ("AMF", "Access and Mobility Management", 38412),
        ("SMF", "Session Management Function", 8805),
        ("UPF", "User Plane Function", 8805),
        ("NRF", "Network Repository Function", 7777),
        ("AUSF", "Authentication Server", 7778),
        ("UDM", "Unified Data Management", 7779),
        ("NSSF", "Network Slice Selection", 7780),
        ("PCF", "Policy Control Function", 7781),
    ]

    cols = st.columns(4)
    for i, (nf_name, nf_desc, port) in enumerate(nfs):
        with cols[i % 4]:
            st.markdown(f"""
            <div class="nf-card">
              <div class="nf-name">{nf_name}</div>
              <div class="nf-desc">{nf_desc}</div>
              <div style="font-size:.7rem;color:#475569;margin-top:6px">Port: {port}</div>
            </div>
            """, unsafe_allow_html=True)

    if st.button("🔄 Probe All NFs", type="primary", key="btn_probe_nfs"):
        with st.spinner(f"Probing Open5GS NFs on {og_host}..."):
            ports = ",".join(str(p) for _, _, p in nfs)
            result = run_tool("nmap", {"target": og_host, "flags": f"-p {ports} -sV --open"})
        render_tool_result(result, "Open5GS NF Probe")

# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("#### 5G SBI HTTP/2 Interface Audit")
    c1, c2 = st.columns(2)
    with c1:
        sbi_host = st.text_input("NRF / NF SBI Base URL", "http://127.0.0.1:7777", key="sbi_url")
    with c2:
        sbi_svc  = st.selectbox("Target Service", [
            "nnrf-disc (NF Discovery)",
            "nnrf-nfm (NF Management)",
            "nudm-sdm (Subscription Data)",
            "nausf-auth (Authentication)",
        ])

    if st.button("🔍 Audit SBI Interface", type="primary", key="btn_sbi_audit"):
        with st.spinner("Probing SBI endpoint..."):
            result = run_tool("nuclei", {"target": sbi_host, "templates": "5g-sbi"})
        render_tool_result(result, "5G SBI Audit")

# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### Open5GS Vulnerability Scanner")
    st.caption("Runs Nuclei 5G templates and Mobiwatch NAS analysis against the core.")
    vuln_target = st.text_input("Core IP / Domain", "127.0.0.1", key="vuln_target")
    scan_type   = st.multiselect("Scan Modules", [
        "CVE templates (Nuclei)", "5G NAS anomaly detection (Mobiwatch)",
        "HTTP/2 endpoint brute", "Default credentials"
    ], default=["CVE templates (Nuclei)"])

    if st.button("🚨 Run Vulnerability Scan", type="primary", key="btn_core_vuln"):
        results = {}
        with st.spinner("Running scans..."):
            if "CVE templates (Nuclei)" in scan_type:
                results["nuclei"] = run_tool("nuclei", {"target": vuln_target})
            if "5G NAS anomaly detection (Mobiwatch)" in scan_type:
                results["mobiwatch"] = run_tool("mobiwatch", {"target": vuln_target})

        for tool_name, result in results.items():
            render_tool_result(result, tool_name.capitalize())
