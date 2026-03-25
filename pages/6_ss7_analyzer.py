"""
pages/6_ss7_analyzer.py — SS7 / SIGTRAN Protocol Analyzer
Wired to: scapy-ss7, sigploit, sctpscan, sigshark, gtscan
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
body, .stApp { font-family: 'Inter', sans-serif !important; background: #0a0f1e; }
.page-hero {
    display: flex; align-items: center; gap: 16px;
    background: linear-gradient(135deg,rgba(59,130,246,.08),rgba(139,92,246,.04));
    border: 1px solid rgba(255,255,255,.06); border-radius: 14px;
    padding: 20px 24px; margin-bottom: 24px;
}
.page-hero-icon { font-size: 2.2rem; }
.page-hero-title { font-size: 1.4rem; font-weight: 700; color: #f8fafc; }
.page-hero-sub   { font-size: 0.9rem; color: #94a3b8; margin-top: 4px; line-height: 1.5; }
.sev-badge {
    display:inline-block; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:600;
}
.sev-CRITICAL { background:rgba(220,38,38,.15); color:#ef4444; border:1px solid rgba(220,38,38,.3); }
.sev-HIGH     { background:rgba(234,88,12,.15);  color:#f97316; border:1px solid rgba(234,88,12,.3); }
.sev-MEDIUM   { background:rgba(217,119,6,.15);  color:#fbbf24; border:1px solid rgba(217,119,6,.3); }
/* Scrollable tab bar for crowded tabs */
.stTabs [data-baseweb="tab-list"] {
    overflow-x: auto !important;
    flex-wrap: nowrap !important;
    scrollbar-width: thin;
    scrollbar-color: rgba(255,255,255,0.1) transparent;
}
.stTabs [data-baseweb="tab-list"]::-webkit-scrollbar { height: 4px; }
.stTabs [data-baseweb="tab-list"]::-webkit-scrollbar-thumb {
    background: rgba(255,255,255,0.1); border-radius: 2px;
}
.stTabs [data-baseweb="tab"] { white-space: nowrap !important; flex-shrink: 0 !important; }
/* Amber action button */
.amber-btn > button {
    background: linear-gradient(135deg, #d97706 0%, #b45309 100%) !important;
    color: #fff !important;
    box-shadow: 0 2px 8px rgba(217,119,6,0.35) !important;
}
.amber-btn > button:hover {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
    box-shadow: 0 4px 16px rgba(245,158,11,0.45) !important;
    transform: translateY(-1px) !important;
}
/* GSMA info card */
.gsma-card {
    background: rgba(59,130,246,0.06); border: 1px solid rgba(59,130,246,0.2);
    border-left: 3px solid #3b82f6; border-radius: 10px;
    padding: 14px 18px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
}
.gsma-badge { font-size: 0.75rem; font-family: 'JetBrains Mono', monospace; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">📡</div>
  <div>
    <div class="page-hero-title">SS7 / SIGTRAN Protocol Analyzer</div>
    <div class="page-hero-sub">MAP, TCAP, SCCP, M3UA analysis · SS7 vulnerability scanning · GT enumeration</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🗺️ GT Scanner", "📡 Scapy SS7 Probe", "🔍 SCTP Discovery",
    "📊 Signal Capture", "🔎 SigShark Analysis"
])

# ─────────────────────────────────────────────────────────────────────────
# TAB 1: GT Scanner (gtscan)
# ─────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("#### Global Title (GT) Scanner")

    # GSMA reference card — inline, above the form
    st.markdown("""
    <div class="gsma-card">
      <div>
        <div style='font-size:.7rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px'>📋 GSMA Reference</div>
        <div style='font-size:.88rem;color:#e2e8f0;font-weight:600'>FS.11 Category 1 — Network Reconnaissance</div>
        <div style='font-size:.78rem;color:#94a3b8;margin-top:2px'>Identifies reachable signaling points through GT enumeration</div>
      </div>
      <div style='margin-left:auto;text-align:right;flex-shrink:0'>
        <div style='font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em'>CVSS Score</div>
        <div style='font-size:1.2rem;font-weight:800;color:#f59e0b;font-family:"JetBrains Mono",monospace'>5.3</div>
        <div style='font-size:.68rem;color:#64748b'>Medium</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    gt_prefix = st.text_input(
        "GT Prefix to scan", "9190", key="gt_prefix",
        placeholder="e.g. 9190 (India CC+AC)",
        help="Country Code + Area Code prefix to enumerate. Example: '9190' for India (+91) with area code 0."
    )
    gt_range = st.slider(
        "Range size (last digits to brute)", 1, 9999, 100,
        help="Number of GT suffixes to probe. Larger ranges take longer but discover more nodes."
    )
    gt_ssn = st.selectbox(
        "Default SSN", ["6 (HLR)", "7 (VLR)", "8 (MSC)", "149 (SMSC/SMS-GMSC)"],
        help="Subsystem Number: HLR (Home Location Register) = 6, VLR = 7, MSC = 8, SMSC = 149."
    )

    st.markdown('<div class="amber-btn">', unsafe_allow_html=True)
    _launch = st.button("🔎 Launch GT Scan", use_container_width=True, key="btn_gtscan")
    st.markdown('</div>', unsafe_allow_html=True)
    if _launch:
        with st.spinner(f"Scanning GT prefix {gt_prefix}..."):
            result = run_tool("gtscan", {"prefix": gt_prefix, "count": gt_range, "ssn": gt_ssn})
        render_tool_result(result, "GTScan")

# ─────────────────────────────────────────────────────────────────────────
# TAB 2: Scapy SS7 MAP Probe
# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("#### Scapy-SS7 MAP Operation Sender")
    st.warning("Live MAP operation — only use on authorized lab environments.", icon="⚠️")
    c1, c2 = st.columns(2)
    with c1:
        src_gt = st.text_input("Source GT (attacker)", "9190000001", key="src_gt")
        dst_gt = st.text_input("Destination GT (HLR/MSC)", "9190000002", key="dst_gt")
    with c2:
        target_msisdn = st.text_input("Target MSISDN", "+919999999999", key="ss7_msisdn")
        operation     = st.selectbox("MAP Operation", [
            "ATI — Any Time Interrogation",
            "SRI — Send Routing Info",
            "ISD — Insert Subscriber Data",
            "PRN — Provide Roaming Number",
            "SRF — Send Routing Info for SM",
        ])
    op_code = operation.split(" ")[0]

    if st.button("📡 Send MAP Operation", type="primary", key="btn_scapy_ss7", use_container_width=True):
        with st.spinner(f"Sending MAP {op_code} to {dst_gt}..."):
            result = run_tool("scapy-ss7", {"gt": dst_gt, "msisdn": target_msisdn, "operation": op_code, "src_gt": src_gt})
        render_tool_result(result, f"Scapy-SS7 MAP {op_code}")

# ─────────────────────────────────────────────────────────────────────────
# TAB 3: SCTP Discovery
# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### SCTP / M3UA Port Scanner")
    st.caption("Discover SS7-over-IP (SIGTRAN) peers. Default SS7 port is 2905.")
    c1, c2 = st.columns(2)
    with c1:
        sctp_target = st.text_input("Target IP / range", "10.0.0.0/24", key="sctp_target")
    with c2:
        sctp_ports  = st.text_input("Ports", "2905,9900,29180", key="sctp_ports")
    if st.button("🔍 Run SCTP Scan", type="primary", key="btn_sctpscan", use_container_width=True):
        with st.spinner(f"SCTP scanning {sctp_target}..."):
            result = run_tool("sctpscan", {"target": sctp_target, "ports": sctp_ports})
        render_tool_result(result, "SCTPScan")

# ─────────────────────────────────────────────────────────────────────────
# TAB 4: Signal Capture (osmocom / grgsm)
# ─────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("#### GSM / SS7 Signal Capture")
    st.caption("Capture over-the-air GSM frames or sniff SIGTRAN traffic with OsmocomBB or gr-gsm.")
    c1, c2 = st.columns(2)
    with c1:
        cap_mode   = st.selectbox("Capture Mode", ["gr-gsm (SDR receiver)", "osmocom (BB hardware)", "tshark (IP/SIGTRAN)"])
        cap_iface  = st.text_input("Interface / Device", "eth0" if "tshark" in cap_mode else "hackrf", key="cap_iface")
    with c2:
        cap_dur    = st.number_input("Capture Duration (sec)", 5, 120, 15, key="cap_dur")
        cap_filter = st.text_input("Display filter (tshark)", "m3ua or sccp or gsm_map", key="cap_filter")

    if st.button("⏺️ Start Capture", type="primary", key="btn_osmocom", use_container_width=True):
        if "gr-gsm" in cap_mode:
            tool_key = "gr-gsm"
            params = {"duration": cap_dur}
        elif "osmocom" in cap_mode:
            tool_key = "osmocom"
            params = {"duration": cap_dur}
        else:
            tool_key = "tshark"
            params = {"interface": cap_iface, "duration": cap_dur, "filter": cap_filter}

        with st.spinner(f"Capturing via {cap_mode}..."):
            result = run_tool(tool_key, params)
        render_tool_result(result, cap_mode)

# ─────────────────────────────────────────────────────────────────────────
# TAB 5: SigShark Frame Analysis
# ─────────────────────────────────────────────────────────────────────────
with tab5:
    st.markdown("#### SigShark — SS7/Diameter PCAP Analyzer")
    st.caption("Deep analysis of SS7 MAP/TCAP/SCCP/SCTP protocol captures.")
    uploaded_pcap = st.file_uploader("Upload .pcap / .pcapng file", type=["pcap", "pcapng", "cap"], key="sigshark_pcap")
    sig_filter    = st.text_input("Protocol filter", "gsm_map", key="sigshark_filter")

    if uploaded_pcap and st.button("🔬 Analyze with SigShark", type="primary", key="btn_sigshark"):
        import base64
        pcap_b64 = base64.b64encode(uploaded_pcap.read()).decode()
        with st.spinner("Analyzing PCAP with SigShark..."):
            result = run_tool("sigshark", {"pcap_b64": pcap_b64, "filter": sig_filter})
        render_tool_result(result, "SigShark")
