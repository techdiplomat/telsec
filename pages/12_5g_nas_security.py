"""
pages/12_5g_nas_security.py — 5G NAS Security Tester
Wired to: mobiwatch, 5gbasechecker, nmap, nuclei
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
    display:flex;align-items:center;gap:16px;
    background:linear-gradient(135deg,rgba(139,92,246,.08),rgba(59,130,246,.04));
    border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:20px 24px;margin-bottom:24px;
}
.page-hero-icon{font-size:2.2rem;}
.page-hero-title{font-size:1.4rem;font-weight:700;color:#f8fafc;}
.page-hero-sub{font-size:.85rem;color:#94a3b8;margin-top:2px;}
.check-row{display:flex;justify-content:space-between;align-items:center;
  padding:10px 16px;border-bottom:1px solid rgba(255,255,255,.05);font-size:.85rem;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🔐</div>
  <div>
    <div class="page-hero-title">5G NAS Security Tester</div>
    <div class="page-hero-sub">NAS message analysis · Authentication bypass · Downgrade attack · NULL encryption probing</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs([
    "🔏 NAS Auth Probe", "⬇️ Downgrade Attacks", "🔬 5G Baseline Audit"
])

with tab1:
    st.markdown("#### NAS Authentication Flow Probe")
    st.info("Trigger NAS registration flows to test Authentication and Key Agreement (AKA) behavior.", icon="ℹ️")
    c1, c2 = st.columns(2)
    with c1:
        amf_ip   = st.text_input("AMF IP", "10.0.0.1", key="nas_amf_ip")
        imsi     = st.text_input("Test IMSI", "001010000000001", key="nas_imsi")
        test_k   = st.text_input("K (hex)", "465B5CE8B199B49FAA5F0A2EE238A6BC", key="nas_k")
    with c2:
        test_opc = st.text_input("OPc (hex)", "E8ED289DEBA952E4283B54E88E6183CA", key="nas_opc")
        nas_mode = st.selectbox("Test Scenario", [
            "Normal Registration (Baseline)",
            "NULL integrity protection IEI",
            "NULL ciphering (EA0) probe",
            "Re-registration with stale TMSI",
        ])
    if st.button("🚀 Run NAS Probe", type="primary", key="btn_nas_probe"):
        with st.spinner("Sending NAS messages to AMF..."):
            result = run_tool("mobiwatch", {
                "mode": "nas_auth",
                "amf": amf_ip,
                "imsi": imsi,
                "k": test_k,
                "opc": test_opc,
                "scenario": nas_mode,
            })
        render_tool_result(result, "5G NAS Auth Probe")

with tab2:
    st.markdown("#### 5G → 4G Downgrade Attack")
    st.warning("Simulates attacker-controlled RAN trying to force UE to fall back to LTE/2G.", icon="⚠️")
    c1, c2 = st.columns(2)
    with c1:
        dg_amf = st.text_input("AMF IP", "10.0.0.1", key="dg_amf")
        dg_imsi = st.text_input("Target IMSI", "001010000000001", key="dg_imsi")
    with c2:
        dg_target = st.selectbox("Downgrade Target", ["4G LTE", "3G UMTS", "2G GSM"])
        dg_method = st.selectbox("Method", [
            "Reject cause #7 (EPS not allowed)",
            "RRC Release to legacy cell",
            "Null Algorithm Negotiation",
        ])
    if st.button("⬇️ Execute Downgrade Attack", type="primary", key="btn_dg"):
        with st.spinner("Executing downgrade..."):
            result = run_tool("5gbasechecker", {
                "target": dg_amf, "imsi": dg_imsi,
                "attack": "downgrade", "target_gen": dg_target, "method": dg_method
            })
        render_tool_result(result, "5G Downgrade Attack")

with tab3:
    st.markdown("#### 5G Security Baseline Checklist (GSMA FS.36)")
    st.caption("Automated check of 5G NAS security parameters against GSMA FS.36 / 3GPP TS 33.501.")
    bc_target = st.text_input("AMF / Core IP", "10.0.0.1", key="bc_nas_target")

    checks = [
        ("SUCI / SUPI concealment (ECIES)", "Critical", "NI"),
        ("5G-AKA or EAP-AKA' required", "Critical", "NI"),
        ("NULL integrity protection disabled", "High", "NI"),
        ("NULL ciphering (EA0) disabled in 5GC", "High", "NI"),
        ("NAS sequence number anti-replay", "Medium", "NI"),
        ("Bidding-down prevention in RegistrationReject", "Medium", "NI"),
    ]
    for check_name, sev, status in checks:
        col1, col2, col3 = st.columns([5, 1, 1])
        col1.write(check_name)
        col2.markdown(f'<span style="font-size:.75rem;color:#f59e0b">{sev}</span>', unsafe_allow_html=True)
        col3.markdown("⏳ Not run", unsafe_allow_html=True)

    if st.button("🔬 Run 5G Baseline Check", type="primary", key="btn_5g_baseline_nas"):
        with st.spinner("Running 5GBaseChecker..."):
            result = run_tool("5gbasechecker", {"target": bc_target})
        render_tool_result(result, "5GBaseChecker")
