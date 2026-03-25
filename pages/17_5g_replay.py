"""
pages/17_5g_replay.py — 5G Traffic Replay Engine
Wired to: 5greplay, tshark-pcap, tshark
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
    background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(6,182,212,.04));
    border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:20px 24px;margin-bottom:24px;
}
.page-hero-icon{font-size:2.2rem;}
.page-hero-title{font-size:1.4rem;font-weight:700;color:#f8fafc;}
.page-hero-sub{font-size:.85rem;color:#94a3b8;margin-top:2px;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">▶️</div>
  <div>
    <div class="page-hero-title">5G Traffic Replay Engine</div>
    <div class="page-hero-sub">Replay GTP/NGAP/SBI captures to test detection systems and reproduce protocol-level attacks</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3 = st.tabs(["📁 PCAP Upload & Replay", "🎥 Live Capture → Replay", "🔍 Offline PCAP Analysis"])

with tab1:
    st.markdown("#### Upload PCAP & Replay to Target Interface")
    uploaded = st.file_uploader("Upload 5G/GTP .pcap file", type=["pcap", "pcapng", "cap"], key="replay_pcap")
    c1, c2 = st.columns(2)
    with c1:
        replay_iface = st.text_input("Output Interface", "eth0", key="replay_iface")
        replay_speed = st.slider("Replay Speed Multiplier", 0.1, 10.0, 1.0, 0.1, key="replay_speed")
    with c2:
        replay_loops  = st.number_input("Repeat Loops", 1, 100, 1, key="replay_loops")
        replay_filter = st.text_input("Filter (BPF)", "udp port 2152", key="replay_bpf")

    if uploaded and st.button("▶️ Replay PCAP", type="primary", key="btn_replay_pcap"):
        import base64
        b64 = base64.b64encode(uploaded.read()).decode()
        with st.spinner(f"Replaying at {replay_speed}x speed on {replay_iface}..."):
            result = run_tool("5greplay", {
                "pcap_b64": b64,
                "speed": replay_speed,
                "interface": replay_iface,
                "loops": replay_loops,
                "filter": replay_filter,
            })
        render_tool_result(result, "5GReplay")

with tab2:
    st.markdown("#### Live Capture → Buffer → Replay pipeline")
    st.caption("Capture traffic live, buffer it in-memory, then replay immediately on a target interface.")
    c1, c2 = st.columns(2)
    with c1:
        cap_iface  = st.text_input("Capture Interface", "eth0", key="cap_live_iface")
        cap_dur    = st.number_input("Capture Duration (sec)", 5, 300, 30, key="cap_live_dur")
    with c2:
        replay_tgt = st.text_input("Replay Target Interface", "eth1", key="cap_live_replay_iface")
        cap_filter_live = st.text_input("Capture Filter", "udp port 2152 or udp port 2123", key="cap_live_flt")

    if st.button("🔴 Capture & Replay", type="primary", key="btn_live_replay"):
        with st.spinner(f"Capturing {cap_dur}s on {cap_iface}..."):
            cap_result = run_tool("tshark", {
                "interface": cap_iface,
                "duration": cap_dur,
                "filter": cap_filter_live,
            })
        render_tool_result(cap_result, "Live Capture")

        if cap_result.get("success"):
            st.info("Capture complete. Replaying now on target interface...")

with tab3:
    st.markdown("#### Offline PCAP Analysis (TShark)")
    st.caption("Analyze a PCAP file offline to review 5G/GTP flows, message timing, and anomalies.")
    pcap_analyze = st.file_uploader("Upload PCAP for analysis", type=["pcap", "pcapng"], key="tshark_analyze")
    tshark_filter = st.text_input("Display Filter", "ngap or gtp or nas-5gs or http2", key="tshark_dsp_flt")

    if pcap_analyze and st.button("🔍 Analyze with TShark", type="primary", key="btn_tshark_analyze"):
        import base64
        b64 = base64.b64encode(pcap_analyze.read()).decode()
        with st.spinner("Analyzing PCAP..."):
            result = run_tool("tshark-pcap", {"pcap_b64": b64, "filter": tshark_filter})
        render_tool_result(result, "TShark Analysis")
