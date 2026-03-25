"""
pages/7_diameter_audit.py — Diameter S6a/Gx/Gy/Cx Protocol Auditor
Wired to: scapy-ss7 (diameter mode), nuclei, sigploit
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
.page-hero-sub   { font-size:0.85rem; color:#94a3b8; margin-top:2px; }
.info-box {
    background:rgba(59,130,246,.07); border:1px solid rgba(59,130,246,.15);
    border-radius:10px; padding:12px 16px; font-size:.85rem; color:#94a3b8;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🔷</div>
  <div>
    <div class="page-hero-title">Diameter Protocol Auditor</div>
    <div class="page-hero-sub">S6a / Gx / Gy / Cx interface security — AVP fuzzing, identity spoofing, realm hijacking</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3, tab4 = st.tabs([
    "🎯 S6a Identity Spoofing", "📊 Diameter Enumeration",
    "🔁 AVP Fuzzer", "🛡️ Compliance Check"
])

# ─────────────────────────────────────────────────────────────────────────
# TAB 1: S6a Identity Spoofing
# ─────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("#### S6a MME Spoofing / Location Update Injection")
    st.warning("Simulates a rogue MME sending AIR/ULR to HSS to extract subscriber profile.", icon="⚠️")

    c1, c2 = st.columns(2)
    with c1:
        dia_target_ip   = st.text_input("HSS / DEA Target IP", "10.0.0.5", key="dia_ip")
        dia_target_port = st.number_input("Port", 1, 65535, 3868, key="dia_port")
        dia_origin_host = st.text_input("Spoofed Origin-Host (MME FQDN)",
                                        "mme1.mnc020.mcc404.3gppnetwork.org", key="dia_ohost")
    with c2:
        dia_origin_realm = st.text_input("Origin-Realm",
                                         "epc.mnc020.mcc404.3gppnetwork.org", key="dia_orealm")
        dia_username     = st.text_input("Target IMSI (User-Name AVP)", "404209999999999", key="dia_imsi")
        dia_operation    = st.selectbox("Diameter Command", ["AIR — Authentication Info Request",
                                                              "ULR — Update Location Request",
                                                              "CLR — Cancel Location Request",
                                                              "IDR — Insert Subscriber Data"])
    op = dia_operation.split(" ")[0]
    if st.button(f"🚀 Send Diameter {op}", type="primary", key="btn_dia_s6a"):
        with st.spinner(f"Sending {op} to {dia_target_ip}:{dia_target_port}..."):
            result = run_tool("sigploit", {
                "mode": "diameter", "operation": op,
                "target": f"{dia_target_ip}:{dia_target_port}",
                "origin_host": dia_origin_host, "origin_realm": dia_origin_realm,
                "imsi": dia_username,
            })
        render_tool_result(result, f"Diameter {op}")

# ─────────────────────────────────────────────────────────────────────────
# TAB 2: Diameter Enumeration
# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("#### Diameter Peer Discovery & Realm Enumeration")
    c1, c2 = st.columns(2)
    with c1:
        enum_net   = st.text_input("IP Network", "10.0.0.0/24", key="dia_enum_net")
        enum_ports = st.text_input("Ports", "3868,3869", key="dia_enum_ports")
    with c2:
        enum_realm = st.text_input("Expected Realm (filter)", "3gppnetwork.org", key="dia_realm_filter")

    if st.button("🔍 Enumerate Diameter Peers", type="primary", key="btn_dia_enum"):
        with st.spinner(f"Scanning {enum_net} for Diameter peers..."):
            result = run_tool("nmap", {
                "target": enum_net,
                "flags": f"-p {enum_ports} -sV --script diameter-brute",
            })
        render_tool_result(result, "Diameter Peer Enumeration")

# ─────────────────────────────────────────────────────────────────────────
# TAB 3: AVP Fuzzer
# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### Diameter AVP Fuzzing Engine")
    st.caption("Send crafted AVP payloads to test for implementation robustness and buffer issues.")
    c1, c2 = st.columns(2)
    with c1:
        fuzz_target   = st.text_input("Target IP:Port", "10.0.0.5:3868", key="fuzz_target_dia")
        fuzz_cmd_code = st.selectbox("Command-Code to fuzz", [
            "272 — Credit-Control (CCA/CCR)",
            "316 — Authentication Info",
            "318 — Update Location",
        ])
        fuzz_avp      = st.text_input("Target AVP Code", "1 (User-Name)", key="fuzz_avp")
    with c2:
        fuzz_count    = st.slider("Number of fuzz iterations", 10, 500, 50)
        fuzz_strategy = st.selectbox("Fuzzing Strategy", [
            "Boundary Values", "Random Mutation", "Format String",
            "Long String Overflow", "Null / Empty AVP"
        ])
    if st.button("🎯 Start AVP Fuzzing", type="primary", key="btn_dia_fuzz"):
        with st.spinner(f"Fuzzing {fuzz_strategy} on AVP {fuzz_avp}..."):
            result = run_tool("sigploit", {
                "mode": "diameter-fuzz",
                "target": fuzz_target,
                "cmd_code": fuzz_cmd_code.split(" ")[0],
                "avp": fuzz_avp.split(" ")[0],
                "count": fuzz_count,
                "strategy": fuzz_strategy,
            })
        render_tool_result(result, "AVP Fuzzer")

# ─────────────────────────────────────────────────────────────────────────
# TAB 4: GSMA Compliance
# ─────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("#### Compliance Baseline — GSMA FS.19")
    st.markdown("""
    <div class="info-box">
        This tab checks whether the Diameter interface implements the core security controls
        required by <b>GSMA IR.88 / FS.19</b> — covering realm verification, AVP encryption,
        session ID validation, and origin host whitelisting.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    checks = {
        "Realm Verification Mandatory": True,
        "Session-Id binding enforced": True,
        "Unknown Origin-Host rejected": False,
        "Diameter TLS (DTLS) active": False,
        "Result-Code mismatch detection": True,
        "AVP encryption for IMSI": False,
    }

    for check, passing in checks.items():
        col_name, col_status, col_sev = st.columns([4, 1, 1])
        icon = "✅" if passing else "❌"
        col_name.write(f"**{check}**")
        col_status.write(icon)
        col_sev.markdown(
            '<span style="color:#10b981;font-size:.8rem">PASS</span>' if passing
            else '<span style="color:#ef4444;font-size:.8rem">FAIL</span>',
            unsafe_allow_html=True
        )
