"""
pages/18_threat_detection.py — Telecom Threat Detection Engine
Wired to: tshark, lucid, mobiwatch, sigfw, nuclei
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
    background:linear-gradient(135deg,rgba(239,68,68,.05),rgba(139,92,246,.04));
    border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:20px 24px;margin-bottom:24px;
}
.page-hero-icon{font-size:2.2rem;} .page-hero-title{font-size:1.4rem;font-weight:700;color:#f8fafc;}
.page-hero-sub{font-size:.85rem;color:#94a3b8;margin-top:2px;}
.alert-row {
    background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.15);border-radius:8px;
    padding:12px 16px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🔍</div>
  <div>
    <div class="page-hero-title">Threat Detection Engine</div>
    <div class="page-hero-sub">Live traffic anomaly detection · LUCID AI classification · SigFW rule matching · attack pattern correlation</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs([
    "📡 Live Traffic Monitor", "🤖 AI Anomaly Detection (LUCID)", "🚨 Attack Pattern Alerts"
])

with tab1:
    st.markdown("#### Live Interface Traffic Monitor")
    c1, c2 = st.columns(2)
    with c1:
        mon_iface  = st.text_input("Capture Interface", "eth0", key="mon_iface")
        mon_dur    = st.number_input("Capture Duration (sec)", 5, 300, 30, key="mon_dur")
    with c2:
        mon_filter = st.text_input("BPF Filter", "m3ua or sctp or gtp or udp port 2123", key="mon_filter")
        mon_proto  = st.multiselect("Protocol Highlighters", ["SS7/SCTP", "GTP-C", "GTP-U", "Diameter", "SIP", "5G-NGAP"], default=["SS7/SCTP", "GTP-C"])

    if st.button("⏺️ Start Monitor Capture", type="primary", key="btn_live_mon"):
        with st.spinner(f"Monitoring {mon_iface} for {mon_dur}s..."):
            result = run_tool("tshark", {
                "interface": mon_iface,
                "duration": mon_dur,
                "filter": mon_filter,
            })
        render_tool_result(result, "Live Traffic Monitor")

with tab2:
    st.markdown("#### LUCID AI — ML-based DDoS & Anomaly Classifier")
    st.info(
        "LUCID uses a CNN-based classifier trained on 5G/4G/SS7 attack traffic to detect "
        "DDoS, signaling storms, and protocol anomalies in real-time PCAP captures.", icon="🤖"
    )
    ai_pcap = st.file_uploader("Upload PCAP to classify", type=["pcap", "pcapng"], key="lucid_pcap")
    c1, c2 = st.columns(2)
    with c1:
        ai_mode     = st.selectbox("Detection Mode", [
            "DDoS Detection", "SS7 Signaling Anomaly", "GTP Flood Detection", "SIP Storm"
        ])
    with c2:
        ai_threshold = st.slider("Alert Threshold (confidence %)", 50, 99, 80)

    if ai_pcap and st.button("🤖 Run LUCID Classifier", type="primary", key="btn_lucid"):
        import base64
        b64 = base64.b64encode(ai_pcap.read()).decode()
        with st.spinner("Running LUCID AI classification..."):
            result = run_tool("lucid", {
                "pcap_b64": b64,
                "mode": ai_mode,
                "threshold": ai_threshold / 100,
            })
        render_tool_result(result, f"LUCID — {ai_mode}")

with tab3:
    st.markdown("#### Real-time Attack Pattern Alerts")
    st.caption("Simulated alert feed from SigFW / Mobiwatch integration — connect Kali backend to enable live feed.")

    alerts = [
        ("MAP ATI Storm", "192.168.1.42", "19.5K req/min from unknown GT — possible HLR scan", "CRITICAL"),
        ("GTP Flood", "10.0.0.8", "Create Session Request rate exceeded 1000/sec on S11", "HIGH"),
        ("Diameter Realm Spoof", "external-realm.com", "Origin-Realm not in whitelist — possible fraudulent MME", "HIGH"),
        ("SIP REGISTER Flood", "185.110.22.33", "40K REGISTER/min on P-CSCF — SIP DDoS candidate", "MEDIUM"),
        ("5G NAS NULL enc", "gNB-03", "UE negotiated EA0 (NULL encryption) on N1 interface", "HIGH"),
    ]

    for title, source, detail, sev in alerts:
        color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#fbbf24"}.get(sev, "#94a3b8")
        st.markdown(f"""
        <div class="alert-row" style="border-left:3px solid {color}">
          <div>
            <div style="font-weight:600;font-size:.88rem;color:#f8fafc">{title}</div>
            <div style="font-size:.78rem;color:#64748b;margin-top:2px">
              Source: <code>{source}</code> — {detail}
            </div>
          </div>
          <div style="font-size:.75rem;font-weight:700;color:{color}">{sev}</div>
        </div>
        """, unsafe_allow_html=True)
