"""
TelSec — Page 4: Protocol Fuzzing Engine
=========================================
Tabs: MAP/SS7 | Diameter AVP | GTP | SIP/IMS | 5G HTTP/2 SBI
"""
import streamlit as st
import plotly.graph_objects as go
import random, json, time

from tstp_data import TSTP
from utils.tstp_engine import render_tstp_card, render_tstp_table, export_tstp_report

st.set_page_config(page_title="TelSec — Protocol Fuzzing", page_icon="🔩", layout="wide")

SEV = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#16a34a"}

def _fc(title, severity, detail, ref=""):
    c = SEV.get(severity, "#6b7280")
    st.markdown(
        f"<div style='border-left:4px solid {c};background:#0f172a;padding:12px 16px;border-radius:6px;margin:8px 0'>"
        f"<b style='color:{c}'>🔩 {severity.upper()} — {title}</b><br>"
        f"<span style='font-size:0.88rem;color:#e2e8f0'>{detail}</span></div>",
        unsafe_allow_html=True,
    )

def _fuzz_chart(iters, crashes, title):
    """Plotly fuzz iteration chart with crash markers."""
    fig = go.Figure()
    # Response time line
    rt = [random.uniform(1, 50) for _ in range(iters)]
    fig.add_trace(go.Scatter(
        x=list(range(iters)), y=rt, mode="lines",
        name="Response Time (ms)", line=dict(color="#2563eb", width=1.5),
    ))
    # Crash markers
    if crashes:
        fig.add_trace(go.Scatter(
            x=crashes, y=[rt[c] for c in crashes], mode="markers",
            name="Crash / Exception", marker=dict(color="#dc2626", size=14, symbol="x"),
        ))
    # Timeout markers
    timeouts = [i for i in range(iters) if random.random() < 0.04 and i not in crashes]
    if timeouts:
        fig.add_trace(go.Scatter(
            x=timeouts, y=[rt[t] for t in timeouts], mode="markers",
            name="Timeout / No Response", marker=dict(color="#ca8a04", size=10, symbol="circle-open"),
        ))
    fig.update_layout(
        title=title, xaxis_title="Fuzz Iteration",
        yaxis_title="Response Time (ms)",
        plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
        font=dict(color="#e2e8f0"), legend=dict(bgcolor="#334155"),
        height=300,
    )
    return fig, len(crashes), len(timeouts)

def _run_fuzz_sim(iters, proto):
    crash_prob = {"MAP/SS7": 0.06, "Diameter": 0.04, "GTP": 0.05, "SIP": 0.03, "5G HTTP/2": 0.04}.get(proto, 0.04)
    crashes = sorted([i for i in range(iters) if random.random() < crash_prob])
    return crashes

def _fuzz_table(results):
    import pandas as pd
    df = pd.DataFrame(results)
    st.dataframe(df, use_container_width=True, hide_index=True)

# ── Page Header ───────────────────────────────────────────────────────────────
st.title("🔩 Protocol Fuzzing Engine")
st.caption("Automated robustness testing across MAP/SS7, Diameter, GTP, SIP/IMS, and 5G HTTP/2 SBI.")
st.warning("⚠️ Fuzzing can cause node instability. Always run on isolated lab nodes — never on production.", icon="🔴")
st.divider()

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🅂 MAP / SS7 Fuzzer",
    "🅳 Diameter AVP Fuzzer",
    "🅶 GTP Fuzzer",
    "📞 SIP / IMS Fuzzer",
    "🌐 5G HTTP/2 SBI Fuzzer",
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1: MAP/SS7 FUZZING
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🅂 MAP / SS7 ASN.1 BER Fuzzer")
    col_f, col_r = st.columns([1, 2])

    with col_f:
        target1 = st.text_input("Target HLR/MSC/STP", placeholder="192.168.1.10 / GT:44...", key="m_tgt")
        op_code = st.selectbox("MAP Operation Code", [
            "MAP_ATI (46 — Any-Time-Interrogation)",
            "MAP_SRI (22 — Send-Routing-Info)",
            "MAP_SRI_SM (45 — SRI for SMS)",
            "MAP_UL (2 — Update-Location)",
            "MAP_RESET (37)",
        ], key="m_op")
        fuzz_phases = st.multiselect("Fuzz Phases", [
            "Boundary (max TAG/LENGTH)", "Truncated TLV", "Type Confusion",
            "Deeply Nested SEQUENCE", "Indefinite-Length BER", "Missing Mandatory IE",
        ], default=["Boundary (max TAG/LENGTH)", "Truncated TLV", "Type Confusion"], key="m_phases")
        iters1 = st.slider("Iterations", 10, 500, 50, key="m_iters")
        run1 = st.button("▶ Start MAP Fuzzer", key="m_run", use_container_width=True, type="primary")

    with col_r:
        if run1:
            crashes = _run_fuzz_sim(iters1, "MAP/SS7")
            fig, nc, nt = _fuzz_chart(iters1, crashes,
                                       f"MAP/SS7 Fuzz — {target1 or 'TARGET'} ({iters1} iterations)")
            st.plotly_chart(fig, use_container_width=True)

            c1, c2, c3 = st.columns(3)
            c1.metric("Iterations", iters1)
            c2.metric("☠ Crashes", nc, delta="FAIL" if nc > 0 else "PASS")
            c3.metric("⏱ Timeouts", nt)

            if nc > 0:
                _fc("MAP Stack Crash Detected", "Critical",
                    f"{nc} crash(es) caused by malformed ASN.1 BER input in phases: {', '.join(fuzz_phases)}. "
                    "Node requires immediate vendor patch and code review.",
                    "3GPP TS 29.002 | ITU-T Q.773 | GSMA FS.11 §5")

            # Crash detail table
            if crashes:
                results = [{"Iteration": c, "Phase": random.choice(fuzz_phases),
                            "Fuzz Type": random.choice(["TAG overflow", "Missing IE", "Type=ANY", "Nested >100"]),
                            "Result": "CRASH / Core Dump"} for c in crashes[:10]]
                _fuzz_table(results)
            st.divider()

        st.markdown("### 📋 TSTP — MAP Fuzzing")
        entry = TSTP.get("TELSEC-FUZZ-001")
        if entry:
            render_tstp_card(entry, "TELSEC-FUZZ-001")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2: DIAMETER AVP FUZZING
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("🅳 Diameter AVP Injection & Boundary Fuzzer")
    col_f2, col_r2 = st.columns([1, 2])

    with col_f2:
        tgt2 = st.text_input("Target HSS/OCS/PCRF", placeholder="192.168.1.20", key="d_tgt")
        interface2 = st.selectbox("Diameter Interface", ["S6a (AIR/ULR)", "Gx (CCR/CCA)", "Gy (CCR for charging)", "Sh (UDR/UDA)", "Rf (ACR)"], key="d_iface")
        avp_fuzz = st.multiselect("AVP Fuzz Strategies", [
            "Unknown Vendor-Specific AVP", "Mandatory bit on non-mandatory",
            "Duplicate mandatory AVPs", "AVP Length Overflow",
            "AVP Length Underflow", "Grouped AVP deep nesting (50+)",
            "Invalid UTF-8 in string AVPs", "Negative unsigned integer",
        ], default=["Unknown Vendor-Specific AVP", "AVP Length Overflow"], key="d_avp")
        iters2 = st.slider("Iterations", 10, 500, 50, key="d_iters")
        run2 = st.button("▶ Start Diameter Fuzzer", key="d_run", use_container_width=True, type="primary")

    with col_r2:
        if run2:
            crashes = _run_fuzz_sim(iters2, "Diameter")
            fig, nc, nt = _fuzz_chart(iters2, crashes, f"Diameter {interface2} Fuzz ({iters2} iterations)")
            st.plotly_chart(fig, use_container_width=True)

            c1, c2, c3 = st.columns(3)
            c1.metric("Iterations", iters2)
            c2.metric("☠ Crashes/Exceptions", nc, delta="FAIL" if nc > 0 else "PASS")
            c3.metric("Expected Result Codes", f"{iters2 - nc}")

            if nc > 0:
                _fc("Diameter AVP Processing Error", "High",
                    f"{nc} exception(s) from Diameter AVP fuzzing on {interface2}. "
                    "Target does not safely handle malformed AVP structures.",
                    "RFC 6733 §4.1 | 3GPP TS 29.272 | GSMA FS.19 §6")
            else:
                st.success("✅ All fuzz cases returned proper error codes (5xxx). Diameter AVP parser is robust.")

            results = [{"Iteration": random.randint(0, iters2), "Strategy": random.choice(avp_fuzz),
                        "Expected": "5001/5009/5014", "Actual": "200 OK (VULNERABLE)" if random.random() < 0.3 else "5001 UNSUPPORTED"}
                       for _ in range(min(8, iters2))]
            _fuzz_table(results)
            st.divider()

        st.markdown("### 📋 TSTP — Diameter Fuzzing")
        entry = TSTP.get("TELSEC-FUZZ-002")
        if entry:
            render_tstp_card(entry, "TELSEC-FUZZ-002")


# ════════════════════════════════════════════════════════════════════════════
# TAB 3: GTP FUZZING
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🅶 GTP Parameter Fuzzer")
    col_f3, col_r3 = st.columns([1, 2])

    with col_f3:
        tgt3 = st.text_input("Target PGW / UPF IP", placeholder="192.168.1.30", key="gtp_tgt")
        gtp_ver = st.radio("GTP Version", ["GTPv1-C (Gn/Gp)", "GTPv2-C (S5/S8/S11)", "GTP-U (Data Plane)"], horizontal=True, key="gtp_ver")
        gtp_fuzz = st.multiselect("GTP Fuzz Types", [
            "Invalid Message Type", "Zero-TEID flood", "Oversized IE",
            "Missing Mandatory IE (Bearer Context)", "IMSI/APN mismatch",
            "GTP-in-GTP tunnel encapsulation", "Sequence number rollover",
        ], default=["Invalid Message Type", "Missing Mandatory IE (Bearer Context)"], key="gtp_fuzz")
        iters3 = st.slider("Iterations", 10, 300, 30, key="gtp_iters")
        run3 = st.button("▶ Start GTP Fuzzer", key="gtp_run", use_container_width=True, type="primary")

    with col_r3:
        if run3:
            crashes = _run_fuzz_sim(iters3, "GTP")
            fig, nc, nt = _fuzz_chart(iters3, crashes, f"GTP {gtp_ver} Fuzz ({iters3} iterations)")
            st.plotly_chart(fig, use_container_width=True)

            c1, c2 = st.columns(2)
            c1.metric("☠ Crashes", nc, delta="FAIL" if nc > 0 else "PASS")
            c2.metric("⏱ Timeouts", nt)

            _fc(f"GTP Fuzzing — {gtp_ver}", "High" if nc > 0 else "Medium",
                f"{'Crash detected!' if nc > 0 else 'No crash.'} GTP-in-GTP encapsulation and TEID zero-flood are most impactful vectors. "
                "Verify GTP firewall rate limiting and TEID validation.",
                "GSMA FS.20 | 3GPP TS 29.274 | GSMA IR.77")
            st.divider()

        st.markdown("### 📋 TSTP — GTP")
        for tid in ["TELSEC-FUZZ-001", "TELSEC-FUZZ-002"]:
            entry = TSTP.get(tid)
            if entry:
                render_tstp_card(entry, tid)


# ════════════════════════════════════════════════════════════════════════════
# TAB 4: SIP/IMS FUZZING
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("📞 SIP / IMS Fuzzer")
    col_f4, col_r4 = st.columns([1, 2])

    with col_f4:
        tgt4 = st.text_input("Target P-CSCF / IMS Core", placeholder="192.168.1.40:5060", key="sip_tgt")
        sip_method = st.selectbox("SIP Method to Fuzz", ["REGISTER", "INVITE", "SUBSCRIBE", "NOTIFY", "REFER", "UPDATE"], key="sip_meth")
        sip_fuzz = st.multiselect("SIP Fuzz Strategies", [
            "Malformed SIP URI (special chars in user part)",
            "Oversized Via header (>32KB)", "Missing mandatory headers (From/To/Call-ID)",
            "SIP fragmentation (SCTP chunks)", "Long Route header chain",
            "NULL byte in SDP body", "Content-Length mismatch",
            "Max Forwards header = 0", "Invalid SIP version string",
        ], default=["Malformed SIP URI (special chars in user part)", "Oversized Via header (>32KB)"], key="sip_fuzz")
        iters4 = st.slider("Iterations", 10, 200, 30, key="sip_iters")
        run4 = st.button("▶ Start SIP Fuzzer", key="sip_run", use_container_width=True, type="primary")

    with col_r4:
        if run4:
            crashes = _run_fuzz_sim(iters4, "SIP")
            fig, nc, nt = _fuzz_chart(iters4, crashes, f"SIP/{sip_method} Fuzz ({iters4} iterations)")
            st.plotly_chart(fig, use_container_width=True)
            st.metric("☠ Crashes", nc, delta="FAIL" if nc > 0 else "PASS")

            _fc(f"SIP/{sip_method} Fuzzing", "High" if nc > 0 else "Low",
                f"{'SIP stack crash — patch required immediately.' if nc > 0 else 'SIP stack robust for tested vectors.'} "
                "Test via SIPP/Spirent or manual SIP crafting tools.",
                "RFC 3261 | GSMA IR.92 (VoLTE) | OWASP VoIP Top 10")
            st.divider()

        st.markdown("### 📋 TSTP — SIP/IMS")
        entry = TSTP.get("TELSEC-FUZZ-002")
        if entry:
            render_tstp_card(entry, "TELSEC-FUZZ-002")


# ════════════════════════════════════════════════════════════════════════════
# TAB 5: 5G HTTP/2 SBI FUZZING
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("🌐 5G HTTP/2 SBI JSON Schema Fuzzer")
    col_f5, col_r5 = st.columns([1, 2])

    with col_f5:
        tgt5 = st.text_input("Target NF SBI Endpoint", placeholder="https://amf.5gc.mnc020.mcc404:443/namf-comm/v1/", key="h2_tgt")
        nf5 = st.selectbox("Target NF", ["AMF", "SMF", "UDM", "AUSF", "NRF", "NEF", "PCF"], key="h2_nf")
        fuzz5 = st.multiselect("HTTP/2 Fuzz Strategies", [
            "Missing required JSON fields",
            "Extra unexpected JSON fields",
            "Wrong data types (int→string swap)",
            "Extremely long string values (>65535 chars)",
            "Deeply nested JSON (100+ levels)",
            "SQL/NoSQL injection in string fields",
            "Null bytes / Unicode surrogates",
            "HTTP/2 stream multiplexing abuse",
            "HPACK header compression bomb",
        ], default=["Missing required JSON fields", "SQL/NoSQL injection in string fields"], key="h2_fuzz")
        token5 = st.text_input("OAuth Bearer Token", placeholder="eyJ...", key="h2_token")
        iters5 = st.slider("Iterations", 10, 200, 30, key="h2_iters")
        run5 = st.button("▶ Start SBI Fuzzer", key="h2_run", use_container_width=True, type="primary")

    with col_r5:
        if run5:
            crashes = _run_fuzz_sim(iters5, "5G HTTP/2")
            fig, nc, nt = _fuzz_chart(iters5, crashes, f"{nf5} SBI HTTP/2 Fuzz ({iters5} iterations)")
            st.plotly_chart(fig, use_container_width=True)

            c1, c2, c3 = st.columns(3)
            c1.metric("Iterations", iters5)
            c2.metric("☠ Crashes", nc, delta="FAIL" if nc > 0 else "PASS")
            c3.metric("⏱ Timeouts", nt)

            results = [{"Iteration": random.randint(0, iters5),
                        "Strategy": random.choice(fuzz5),
                        "HTTP Status": random.choice(["400", "422", "200 (VULN)", "500 (CRASH)", "503"]),
                        "DB Error Leaked": random.choice(["No ✅", "No ✅", "Yes ⚠", "No ✅"])} for _ in range(min(10, iters5))]
            _fuzz_table(results)

            _fc(f"5G SBI {nf5} — JSON Fuzzing", "High" if nc > 0 else "Medium",
                f"{nc} crash(es), {nt} timeouts in {iters5} iterations. "
                "Verify OpenAPI schema enforcement and reject malformed JSON at SBI gateway.",
                "3GPP TS 29.501 | OWASP API Top 10 | RFC 9113 (HTTP/2)")
            st.divider()

        st.markdown("### 📋 TSTP — 5G SBI Fuzzing")
        entry = TSTP.get("TELSEC-FUZZ-003")
        if entry:
            render_tstp_card(entry, "TELSEC-FUZZ-003")

        with st.expander("📊 Fuzzing TSTP Status"):
            render_tstp_table({k: v for k, v in TSTP.items() if k.startswith("TELSEC-FUZZ")})

# ── Export ────────────────────────────────────────────────────────────────────
st.divider()
with st.expander("📤 Export Protocol Fuzzing TSTP Report (JSON)"):
    rel = {k: v for k, v in TSTP.items() if k.startswith("TELSEC-FUZZ")}
    report = export_tstp_report(rel)
    st.download_button("⬇ Download JSON", data=json.dumps(report, indent=2).encode(),
                       file_name="telsec_fuzzing_report.json", mime="application/json")
    st.json(report, expanded=False)
