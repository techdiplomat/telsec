"""
pages/16_ss7_scanner.py — SS7 GT Network Scanner
Wired to: gtscan, sctpscan, nmap, scapy-ss7
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
    background:linear-gradient(135deg,rgba(14,165,233,.08),rgba(59,130,246,.04));
    border:1px solid rgba(255,255,255,.06); border-radius:14px; padding:20px 24px; margin-bottom:24px;
}
.page-hero-icon { font-size:2.2rem; }
.page-hero-title { font-size:1.4rem; font-weight:700; color:#f8fafc; }
.page-hero-sub { font-size:0.85rem; color:#94a3b8; margin-top:2px; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🗺️</div>
  <div>
    <div class="page-hero-title">SS7 GT Network Scanner</div>
    <div class="page-hero-sub">Global Title prefix enumeration · SCTP peer discovery · MAP test probes</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs(["🔭 GT Prefix Scan", "🌐 SCTP Peer Sweep", "📊 MAP Baseline Probe"])

# ─────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("#### Global Title Prefix Enumeration")
    st.info("Probe a GT prefix range to discover active HLRs, VLRs, and MSCs.", icon="ℹ️")

    c1, c2, c3 = st.columns(3)
    with c1:
        gt_country = st.selectbox("Country Code (CC)", ["91 – India", "44 – UK", "1 – USA", "49 – Germany", "Custom"])
        if "Custom" in gt_country:
            gt_country_code = st.text_input("Custom CC", "91")
        else:
            gt_country_code = gt_country.split(" ")[0]
    with c2:
        gt_ndc    = st.text_input("Network/Area Code", "90", help="National Destination Code / Area Code")
        gt_digits = st.number_input("Last N digits to sweep", 1, 9999, 50)
    with c3:
        gt_ssn    = st.selectbox("Target SSN", ["6 – HLR", "7 – VLR", "8 – MSC", "149 – SMSC", "All"])
        gt_timeout = st.number_input("Timeout per probe (ms)", 100, 5000, 500)

    prefix = f"{gt_country_code}{gt_ndc}"
    st.markdown(f"**Scanning prefix:** `{prefix}` → `{prefix}{'X'*4}` (sweep {gt_digits} GTs)")

    if st.button("🚀 Start GT Scan", type="primary", key="btn_gt_scan_page"):
        with st.spinner(f"Enumerating {gt_digits} GTs under prefix {prefix}..."):
            result = run_tool("gtscan", {
                "prefix": prefix,
                "count": gt_digits,
                "ssn": gt_ssn.split(" ")[0],
                "timeout": gt_timeout,
            })
        render_tool_result(result, "GTScan")

# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("#### SCTP Peer Discovery Sweep")
    c1, c2 = st.columns(2)
    with c1:
        sweep_net   = st.text_input("Target Network CIDR", "10.0.0.0/24", key="sweep_net")
        sweep_ports = st.text_input("SCTP Ports", "2905,2906,9900", key="sweep_ports")
    with c2:
        sweep_rate  = st.slider("Scan Rate (pkts/sec)", 10, 1000, 100)

    if st.button("🌐 Run SCTP Sweep", type="primary", key="btn_sctp_sweep"):
        with st.spinner(f"SCTP sweep on {sweep_net}..."):
            result = run_tool("sctpscan", {
                "target": sweep_net,
                "ports": sweep_ports,
                "rate": sweep_rate,
            })
        render_tool_result(result, "SCTPScan Sweep")

# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### MAP Baseline Probe (Authorized Pentest)")
    st.warning("Only execute against authorized target networks. MAP probes generate real signaling traffic.", icon="⚠️")

    c1, c2 = st.columns(2)
    with c1:
        probe_gt     = st.text_input("Target HLR / MSC GT", "9190000001", key="probe_gt")
        probe_msisdn = st.text_input("Test MSISDN", "+919999999999", key="probe_msisdn")
    with c2:
        probe_ops = st.multiselect("MAP Operations to probe", [
            "SRI — Send Routing Info",
            "ATI — Any Time Interrogation",
            "PRN — Provide Roaming Number",
        ], default=["SRI — Send Routing Info"])
        probe_src_gt = st.text_input("Source GT (Attacker)", "9190000099", key="probe_src_gt")

    if probe_ops and st.button("📡 Run MAP Baseline Probe", type="primary", key="btn_map_probe"):
        for op in probe_ops:
            op_code = op.split(" ")[0]
            st.markdown(f"**Sending MAP {op_code}:**")
            with st.spinner(f"Sending {op_code}..."):
                result = run_tool("scapy-ss7", {
                    "gt": probe_gt,
                    "msisdn": probe_msisdn,
                    "operation": op_code,
                    "src_gt": probe_src_gt,
                })
            render_tool_result(result, f"MAP {op_code}")
