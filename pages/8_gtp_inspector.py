"""
pages/8_gtp_inspector.py — GTP-C / GTP-U Protocol Security Inspector
Wired to: nmap, tshark, sigploit, scapy-ss7, 5greplay
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
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🌐</div>
  <div>
    <div class="page-hero-title">GTP-C / GTP-U Protocol Inspector</div>
    <div class="page-hero-sub">S11/S5-S8 interface analysis · TEID hijacking · GTP tunneling anomalies · User-plane attacks</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 GTP Endpoint Discovery", "💉 GTP-C Attack Vectors",
    "🚇 Tunnel Injection (GTP-U)", "📦 PCAP Replay"
])

# ─────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("#### GTP-C / GTP-U Endpoint Discovery")
    st.caption("Scan for SGW, PGW, and MME GTP interfaces on standard ports.")
    c1, c2 = st.columns(2)
    with c1:
        gtp_net   = st.text_input("Target Network", "10.0.0.0/24", key="gtp_net")
        gtp_ports = st.text_input("GTP Ports", "2123,2152", key="gtp_ports")
    with c2:
        gtp_flags = st.text_input("Additional Nmap Flags", "-sU -sV --open", key="gtp_nmap_flags")

    if st.button("🔍 Discover GTP Endpoints", type="primary", key="btn_gtp_disc"):
        with st.spinner(f"Scanning {gtp_net} for GTP endpoints..."):
            result = run_tool("nmap", {"target": gtp_net, "flags": f"-p {gtp_ports} {gtp_flags}"})
        render_tool_result(result, "GTP Discovery (nmap)")

# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("#### GTP-C Control Plane Attack Vectors")
    st.warning("These attacks target the S11 (MME↔SGW) and S5/S8 (SGW↔PGW) GTP-C interfaces.", icon="⚠️")
    c1, c2 = st.columns(2)
    with c1:
        sgw_ip  = st.text_input("Target SGW/PGW IP", "10.0.0.10", key="sgw_ip")
        attack  = st.selectbox("Attack Type", [
            "Create Session Request Flood (DoS)",
            "TEID Enumeration (Brute-force)",
            "Malformed IE Injection",
            "Echo Request Flood",
            "Delete Bearer Spoofing",
        ])
    with c2:
        teid    = st.text_input("Target TEID (hex, for TEID attacks)", "0x00000001", key="teid_val")
        apn     = st.text_input("APN", "internet", key="gtp_apn")

    if st.button("🚀 Launch GTP-C Attack", type="primary", key="btn_gtpc_attack"):
        with st.spinner(f"Executing {attack} on {sgw_ip}..."):
            result = run_tool("sigploit", {
                "mode": "gtp",
                "target": sgw_ip,
                "attack_type": attack,
                "teid": teid,
                "apn": apn,
            })
        render_tool_result(result, f"GTP-C {attack}")

# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### GTP-U Data Plane Tunnel Injection")
    st.caption("Inject crafted IP packets into GTP-U tunnels to test user-plane isolation.")
    c1, c2 = st.columns(2)
    with c1:
        ugw_ip = st.text_input("Target eNB/UPF IP", "10.0.0.20", key="ugw_ip")
        u_teid = st.text_input("TEID", "0x00000042", key="u_teid")
    with c2:
        payload_type = st.selectbox("Injection Payload", ["ICMP Echo", "UDP Flood", "Malformed IPv6"])
        pkt_count    = st.slider("Packet Count", 1, 1000, 10)

    if st.button("💉 Inject GTP-U Payload", type="primary", key="btn_gtpu"):
        with st.spinner(f"Injecting into tunnel TEID={u_teid}..."):
            result = run_tool("sigploit", {
                "mode": "gtp-u",
                "target": ugw_ip,
                "teid": u_teid,
                "payload_type": payload_type,
                "count": pkt_count,
            })
        render_tool_result(result, "GTP-U Injection")

# ─────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("#### GTP PCAP Replay (5GReplay)")
    st.caption("Replay captured GTP sessions to reproduce attacks or test detection systems.")
    uploaded = st.file_uploader("Upload GTP .pcap file", type=["pcap","pcapng"], key="gtp_pcap_upload")
    replay_speed = st.slider("Replay Speed Multiplier", 0.1, 10.0, 1.0, 0.1)
    replay_iface = st.text_input("Output Interface", "eth0", key="gtp_replay_iface")

    if uploaded and st.button("▶️ Replay GTP Capture", type="primary", key="btn_5greplay"):
        import base64
        b64 = base64.b64encode(uploaded.read()).decode()
        with st.spinner("Replaying GTP session..."):
            result = run_tool("5greplay", {"pcap_b64": b64, "speed": replay_speed, "interface": replay_iface})
        render_tool_result(result, "5GReplay")
