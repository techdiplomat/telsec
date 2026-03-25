"""
pages/11_ueransim.py — UERANSIM 5G Lab Interface
Wired to: nmap, nuclei, mobiwatch, 5gbasechecker
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
    background:linear-gradient(135deg,rgba(139,92,246,.08),rgba(59,130,246,.04));
    border:1px solid rgba(255,255,255,.06); border-radius:14px; padding:20px 24px; margin-bottom:24px;
}
.page-hero-icon { font-size:2.2rem; }
.page-hero-title { font-size:1.4rem; font-weight:700; color:#f8fafc; }
.page-hero-sub { font-size:0.85rem; color:#94a3b8; margin-top:2px; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">📶</div>
  <div>
    <div class="page-hero-title">UERANSIM 5G NR Lab</div>
    <div class="page-hero-sub">Simulate UE/gNB, probe 5G NAS/RRC security, and test AMF registration flows</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs(["🧪 UE Registration Flow", "📡 gNB Probe", "🔬 5G Baseline Checker"])

with tab1:
    st.markdown("#### Simulated UE → AMF Registration Flow")
    c1, c2 = st.columns(2)
    with c1:
        amf_ip     = st.text_input("AMF IP", "10.0.0.1", key="amf_ip")
        amf_port   = st.number_input("AMF NGAP Port", 1, 65535, 38412, key="amf_port")
        sim_imsi   = st.text_input("Simulated IMSI", "001010000000001", key="sim_imsi")
    with c2:
        sim_key    = st.text_input("Sim K (Hex)", "465B5CE8B199B49FAA5F0A2EE238A6BC", key="sim_k")
        sim_opc    = st.text_input("OPc (Hex)", "E8ED289DEBA952E4283B54E88E6183CA", key="sim_opc")
        attack_mode = st.checkbox("🔴 Anomalous NAS messages (attack mode)", key="ue_attack")

    if st.button("📲 Start UE Registration", type="primary", key="btn_ue_reg"):
        with st.spinner("Sending Registration Request via UERANSIM..."):
            result = run_tool("mobiwatch", {
                "mode": "ue_registration",
                "amf": f"{amf_ip}:{amf_port}",
                "imsi": sim_imsi,
                "k": sim_key,
                "opc": sim_opc,
                "attack": attack_mode,
            })
        render_tool_result(result, "UE Registration Flow")

with tab2:
    st.markdown("#### gNB Interface Probe")
    c1, c2 = st.columns(2)
    with c1:
        gnb_ip   = st.text_input("gNB IP", "10.0.0.2", key="gnb_ip")
        gnb_port = st.number_input("NGAP Port", 1, 65535, 38412, key="gnb_port")
    with c2:
        gnb_scan_type = st.selectbox("Probe Type", [
            "NG-AP Setup (passive)", "NG-AP malformed PDU", "Xn-AP Discovery"
        ])

    if st.button("📡 Probe gNB", type="primary", key="btn_gnb_probe"):
        with st.spinner(f"Probing gNB {gnb_ip}..."):
            result = run_tool("nmap", {"target": gnb_ip, "flags": f"-p {gnb_port} -sV --script ngap-*"})
        render_tool_result(result, "gNB Probe")

with tab3:
    st.markdown("#### 5G Baseline Security Checker (5GBaseChecker)")
    st.info("Audits the 5G NAS security baseline — checks for downgrade attacks, null encryption, NAS authentication bypass.", icon="🔬")
    bc_ip = st.text_input("AMF / Core IP", "10.0.0.1", key="bc_ip")

    if st.button("🔍 Run 5G Baseline Check", type="primary", key="btn_5gbc"):
        with st.spinner("Running 5GBaseChecker..."):
            result = run_tool("5gbasechecker", {"target": bc_ip})
        render_tool_result(result, "5GBaseChecker")
