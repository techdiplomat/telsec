"""
pages/19_protocol_lab.py — Protocol Lab / Scapy Craft Workbench
Wired to: scapy-ss7, sigploit, sctpscan, tshark
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
    background:linear-gradient(135deg,rgba(6,182,212,.06),rgba(59,130,246,.04));
    border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:20px 24px;margin-bottom:24px;
}
.page-hero-icon{font-size:2.2rem;} .page-hero-title{font-size:1.4rem;font-weight:700;color:#f8fafc;}
.page-hero-sub{font-size:.85rem;color:#94a3b8;margin-top:2px;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🧪</div>
  <div>
    <div class="page-hero-title">Protocol Lab / Packet Workbench</div>
    <div class="page-hero-sub">Craft custom SS7 / Diameter / GTP / SIP packets · send raw SCTP · interactive protocol sandbox</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs([
    "✏️ Packet Crafter (Scapy)", "🔌 SCTP Raw Sender", "📐 Wireshark Filter Builder"
])

with tab1:
    st.markdown("#### Custom Packet Crafter — Scapy-SS7")
    st.caption("Build custom MAP / SCCP / M3UA signaling packets and send them to a target.")

    c1, c2 = st.columns(2)
    with c1:
        craft_proto  = st.selectbox("Protocol Layer", ["MAP/TCAP", "BSSAP", "SCCP", "Diameter AVP", "GTP", "SIP"])
        craft_dst_gt = st.text_input("Destination GT", "9190000001", key="craft_dst")
        craft_src_gt = st.text_input("Source GT", "9190000099", key="craft_src")
    with c2:
        craft_op     = st.selectbox("Operation / Message", [
            "anyTimeInterrogation", "sendRoutingInfo", "insertSubscriberData",
            "deleteSubscriberData", "updateLocation", "cancelLocation",
        ])
        craft_msisdn = st.text_input("MSISDN / IMSI", "+919999999999", key="craft_msisdn")

    st.markdown("**Custom AVP / IEs (JSON key-value)**")
    craft_attrs = st.text_area("Attributes", '{"imsi": "404209999999999", "hlr_number": "9190000001"}',
                               height=100, key="craft_attrs")

    if st.button("🚀 Send Packet", type="primary", key="btn_craft_send"):
        import json as _json
        try:
            attrs = _json.loads(craft_attrs)
        except Exception:
            attrs = {}

        with st.spinner(f"Sending custom {craft_proto} packet..."):
            result = run_tool("scapy-ss7", {
                "gt": craft_dst_gt,
                "src_gt": craft_src_gt,
                "operation": craft_op,
                "msisdn": craft_msisdn,
                "extra": attrs,
            })
        render_tool_result(result, f"Scapy-SS7 {craft_op}")

with tab2:
    st.markdown("#### SCTP Raw Payload Sender")
    st.caption("Send raw binary or hex payload over SCTP to any M3UA/SIGTRAN endpoint.")
    c1, c2 = st.columns(2)
    with c1:
        sctp_dst_ip  = st.text_input("Destination IP", "10.0.0.5", key="raw_sctp_ip")
        sctp_dst_port = st.number_input("Destination Port", 1, 65535, 2905, key="raw_sctp_port")
    with c2:
        sctp_ppid    = st.selectbox("PPID (Protocol ID)", ["3 — M3UA", "49 — GTP", "0 — Raw", "46 — Diameter"])
        sctp_payload = st.text_input("Hex Payload", "0300000d010000001200000000000000", key="raw_sctp_payload")

    if st.button("📤 Send Raw SCTP", type="primary", key="btn_raw_sctp"):
        with st.spinner(f"Sending SCTP to {sctp_dst_ip}:{sctp_dst_port}..."):
            result = run_tool("sctpscan", {
                "target": sctp_dst_ip,
                "ports": str(sctp_dst_port),
                "ppid": sctp_ppid.split(" ")[0],
                "payload": sctp_payload,
                "mode": "send",
            })
        render_tool_result(result, "Raw SCTP Sender")

with tab3:
    st.markdown("#### Wireshark / TShark Display Filter Builder")
    st.caption("Helper to build and test complex display filters without the Wireshark GUI.")

    filter_presets = {
        "All SS7/SCCP traffic":        "m3ua or sccp or gsm_map",
        "GTP-C (control plane)":       "gtp and gtp.type != 255",
        "Diameter S6a only":           "diameter and diameter.applicationId == 16777251",
        "5G NAS Registration":         "nas-5gs and nas_5gs.sm.message_type == 0x41",
        "SIP REGISTER storms":         "sip.Method == \"REGISTER\" and frame.len > 500",
        "SCTP heartbeat missing":      "sctp.chunk_type == 5",
    }

    selected_preset = st.selectbox("Load Preset", ["(custom)"] + list(filter_presets.keys()))
    if selected_preset != "(custom)":
        filter_val = filter_presets[selected_preset]
    else:
        filter_val = ""

    custom_filter = st.text_area("Display Filter", filter_val, height=80, key="tshark_filter_builder")
    test_iface = st.text_input("Test on Interface (for live validation)", "eth0", key="filter_test_iface")
    test_dur   = st.number_input("Capture Duration (sec)", 5, 60, 10, key="filter_test_dur")

    if st.button("🧪 Test Filter Live", type="primary", key="btn_filter_test"):
        with st.spinner(f"Applying filter on {test_iface}..."):
            result = run_tool("tshark", {
                "interface": test_iface,
                "duration": test_dur,
                "filter": custom_filter,
            })
        render_tool_result(result, "TShark Filter Test")
