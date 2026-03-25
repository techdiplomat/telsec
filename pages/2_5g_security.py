"""
TelSec — Page 2: 5G Security Testing
======================================
Tabs: SBA Interface Testing | NF Auth Abuse | Network Slice Security |
      gNB Interface Testing | PFCP/UPF Testing
"""
import streamlit as st
import plotly.graph_objects as go
import random, json

from tstp_data import TSTP
from utils.tstp_engine import render_tstp_card, render_tstp_table, export_tstp_report

st.set_page_config(page_title="TelSec — 5G Security", page_icon="📡", layout="wide")

SEV = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#16a34a"}

def _fc(title, severity, detail, ref=""):
    c = SEV.get(severity, "#6b7280")
    st.markdown(
        f"<div style='border-left:4px solid {c};background:#0f172a;padding:12px 16px;border-radius:6px;margin:8px 0'>"
        f"<b style='color:{c}'>⚠ {severity.upper()} — {title}</b><br>"
        f"<span style='font-size:0.88rem;color:#e2e8f0'>{detail}</span><br>"
        f"<span style='font-size:0.76rem;color:#64748b'>{ref}</span></div>",
        unsafe_allow_html=True,
    )

def _flow(steps):
    st.code("\n".join(f"{i:>2}. {s}" for i, s in enumerate(steps, 1)), language="text")

# ── NF Topology Legend ────────────────────────────────────────────────────────
st.title("📡 5G Security Testing")
st.caption("Service-Based Architecture (SBA) testing aligned to 3GPP TS 33.501, TS 33.511, GSMA FS.40.")

with st.expander("🗺 5G Core NF Topology Reference", expanded=False):
    nfs = {
        "AMF": "Access and Mobility Management — N1/N2/N8/N11/N12/N15",
        "SMF": "Session Management — N4/N7/N10/N11",
        "UPF": "User Plane — N3/N4/N6/N9",
        "UDM": "Unified Data Management — N8/N10/N13",
        "AUSF": "Auth Server Function — N12/N13",
        "PCF": "Policy Control — N7/N15",
        "NRF": "NF Repository — Nnrf (registration/discovery)",
        "NEF": "Network Exposure — N33/Nnef",
        "NSSF": "Network Slice Selection — Nnssf",
    }
    cols = st.columns(3)
    for i, (nf, desc) in enumerate(nfs.items()):
        with cols[i % 3]:
            st.markdown(f"**`{nf}`** — {desc}")

st.divider()

# ── Interface auto-population ─────────────────────────────────────────────────
NF_IFACES = {
    "AMF": ["N1", "N2", "N8", "N11", "N12", "N15"],
    "SMF": ["N4", "N7", "N10", "N11"],
    "UPF": ["N3", "N4", "N6", "N9"],
    "UDM": ["N8", "N10", "N13"],
    "AUSF": ["N12", "N13"],
    "PCF": ["N7", "N15"],
    "NRF": ["Nnrf"],
    "NEF": ["N33", "Nnef"],
    "NSSF": ["Nnssf"],
}

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔗 SBA Interface Testing",
    "🗝 NF Auth Abuse",
    "🍰 Network Slice Security",
    "📡 gNB Interface Testing",
    "🔀 PFCP / UPF Testing",
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1: SBA INTERFACE TESTING
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🔗 SBA Interface Testing")
    col_f, col_r = st.columns([1, 2])

    with col_f:
        target_nf = st.selectbox("Target NF", list(NF_IFACES.keys()), key="sba_nf")
        ifaces = NF_IFACES.get(target_nf, [])
        iface = st.selectbox("Interface", ifaces, key="sba_iface")
        atk_vec = st.selectbox("Attack Vector", [
            "NF Discovery Abuse via NRF API",
            "Unauthorized NF Registration",
            "HTTP/2 API Parameter Injection",
            "3GPP JSON Schema Violation",
            "NF Service Token Replay",
            "PLMN ID Spoofing in SBI Header",
            "UE Context Leak via Namf_Communication",
        ], key="sba_vec")
        api_ep = st.text_input("API Endpoint", value=f"/n{target_nf.lower()}-nfm/v1/nf-instances", key="sba_ep")
        token  = st.text_input("OAuth Bearer Token (test/expired)", placeholder="eyJhbGciOiJSUzI1NiJ9...", key="sba_token")
        method = st.selectbox("HTTP Method", ["GET", "POST", "PUT", "PATCH", "DELETE"], key="sba_meth")
        sim    = st.checkbox("🛡 Simulation Mode", value=True, key="sba_sim")
        run1   = st.button("▶ Run", key="sba_run", use_container_width=True, type="primary")

    with col_r:
        if run1:
            st.markdown(f"**Simulated HTTP/2 SBI Request to `{target_nf}` via `{iface}`:**")
            fake_body = json.dumps({"nfInstanceId": "e1234567-dead-beef-cafe-1234567890ab",
                                    "nfType": target_nf, "nfStatus": "REGISTERED",
                                    "plmnList": [{"mcc": "404", "mnc": "20"}]}, indent=2)
            st.code(
                f"{method} {api_ep} HTTP/2\n"
                f"Host: {target_nf.lower()}.sbi.5gc.mnc020.mcc404.3gppnetwork.org\n"
                f"Authorization: Bearer {token[:20] + '...' if token else '[MISSING]'}\n"
                f"Content-Type: application/json\n\n{fake_body}",
                language="http",
            )

            if "NF Registration" in atk_vec:
                st.markdown("**Simulated Response:**")
                st.code("HTTP/2 401 Unauthorized\n{\"title\":\"Unauthorized\",\"status\":401,\"cause\":\"INVALID_TOKEN\"}", language="http")
                _fc("Unauthorized NF Registration attempt via NRF", "Critical",
                    f"NRF should reject PUT to {api_ep} without valid OAuth token. If accepted, rogue {target_nf} can steal UE traffic.",
                    "3GPP TS 33.501 §13.1 | TS 29.510 | GSMA FS.40 §5.4")
            elif "Token Replay" in atk_vec:
                st.code("HTTP/2 401 Unauthorized\n{\"title\":\"Token Expired\",\"status\":401,\"cause\":\"ACCESS_TOKEN_EXPIRED\"}", language="http")
                _fc("OAuth Token Replay / Scope Escalation", "Critical",
                    "Replayed or scope-escalated JWT accepted by NF resource server. Cross-NF token used.",
                    "3GPP TS 33.501 §13.3 | RFC 7519 | CVE-2015-9235")
            elif "JSON Schema" in atk_vec:
                st.code("HTTP/2 422 Unprocessable Entity\n{\"title\":\"Schema Violation\",\"status\":422}", language="http")
                _fc("JSON Schema Violation — Fuzzing Response", "Medium",
                    "Missing required 3GPP JSON fields should return 422. If 200 returned, input validation bypassed.",
                    "3GPP TS 29.501 | OWASP API Security Top 10")
            else:
                st.code(f"HTTP/2 403 Forbidden\n{{\"title\":\"Forbidden\",\"status\":403}}", language="http")
                _fc(f"{atk_vec}", "High",
                    f"5G SBA attack on {target_nf} via {iface}. Verify NRF access policy and mTLS enforcement.",
                    "3GPP TS 33.501 §13 | GSMA FS.40")
            st.divider()

        st.markdown("### 📋 Associated TSTP Procedures")
        for tid in ["TELSEC-5G-SBA-001", "TELSEC-5G-SBA-002"]:
            entry = TSTP.get(tid)
            if entry:
                render_tstp_card(entry, tid)

        with st.expander("📊 SBA TSTP Status"):
            render_tstp_table({k: v for k, v in TSTP.items() if "SBA" in k})


# ════════════════════════════════════════════════════════════════════════════
# TAB 2: NF AUTH ABUSE
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("🗝 NF Authentication Abuse")
    col_f2, col_r2 = st.columns([1, 2])

    with col_f2:
        nf2 = st.selectbox("Target NF", list(NF_IFACES.keys()), key="nfauth_nf")
        atk2 = st.selectbox("Auth Attack Type", [
            "mTLS Certificate Bypass (self-signed cert)",
            "OAuth Token Scope Escalation",
            "OAuth Token Algorithm Confusion (RS256→HS256)",
            "JWT 'none' Algorithm Attack",
            "Token Expiry Non-Enforcement",
            "Cross-NF Token Replay",
        ], key="nfauth_atk")
        origin_host = st.text_input("Rogue Origin-Host FQDN", placeholder=f"rogue.{nf2.lower()}.mnc020.mcc404", key="nfauth_oh")
        run2 = st.button("▶ Simulate Auth Attack", key="nfauth_run", use_container_width=True, type="primary")

    with col_r2:
        if run2:
            _flow([
                f"Attacker NF: {origin_host or 'rogue.amf.mnc020.mcc404'}",
                f"Target NF: {nf2} — OAuth Token Server: NRF/AUSF",
                f"Attack: {atk2}",
                "Step 1: Connect to SBI interface (HTTP/2 over TLS)",
                "Step 2: Attempt mTLS with self-signed certificate" if "mTLS" in atk2 else
                "Step 2: Tamper JWT header algorithm field" if "Algorithm" in atk2 else
                "Step 2: Present expired/replayed token",
                "Expected: HTTP 401 / TLS handshake failure",
                "Actual (if vulnerable): HTTP 200 / Auth vectors returned",
            ])
            _fc(f"NF Auth Abuse — {atk2}", "Critical",
                f"{nf2} must enforce mTLS with valid CA-signed certificate AND short-lived OAuth tokens per TS 33.501 §13.",
                "3GPP TS 33.501 §13 | 3GPP TS 33.310 | GSMA FS.40")

        st.markdown("### 📋 Relevant TSTP")
        for tid in ["TELSEC-5G-SBA-001", "TELSEC-5G-SBA-002"]:
            entry = TSTP.get(tid)
            if entry:
                render_tstp_card(entry, tid)


# ════════════════════════════════════════════════════════════════════════════
# TAB 3: NETWORK SLICE SECURITY
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🍰 Network Slice Security Testing")
    col_f3, col_r3 = st.columns([1, 2])

    with col_f3:
        atk3 = st.selectbox("Attack Type", [
            "Inter-Slice Lateral Movement",
            "S-NSSAI Identifier Brute Force",
            "Slice Resource Exhaustion (DoS)",
            "NSSF Policy Manipulation",
            "UE Slice Assignment Bypass",
            "Cross-Slice User Data Leakage",
        ], key="sl_atk")
        atk_sst = st.text_input("Attacker Slice S-NSSAI (SST-SD)", placeholder="1-000001 (eMBB)", key="sl_atk_sst")
        tgt_sst = st.text_input("Target Slice S-NSSAI (SST-SD)", placeholder="2-000001 (URLLC)", key="sl_tgt_sst")
        sl_type = st.selectbox("Slice Type", ["eMBB", "URLLC", "mMTC", "Network Slice as a Service"], key="sl_type")
        cap3 = st.selectbox("Attacker Capability", ["Standard UE", "Rooted UE", "Compromised gNB"], key="sl_cap")
        run3 = st.button("▶ Simulate Slice Attack", key="sl_run", use_container_width=True, type="primary")

    with col_r3:
        if run3:
            isolation_score = random.randint(40, 95)
            _flow([
                f"Attacker in Slice [{atk_sst or '1-000001 eMBB'}] targeting Slice [{tgt_sst or '2-000001 URLLC'}]",
                f"Attack: {atk3}",
                "Send PDU Session Establishment on target S-NSSAI (unauthorized)",
                "NSSF/AMF checks subscriber's Allowed-NSSAI — attempt rejected" if isolation_score > 70 else
                "⚠ NSSF returns Configured-NSSAI including unauthorized slice",
                "Attempt PFCP message injection targeting cross-slice SEID",
                "UPF isolation check: " + ("PASS — separate PFCP sessions" if isolation_score > 70 else "FAIL — shared UPF context"),
            ])
            _fc(f"Slice Isolation — {atk3}", "High" if isolation_score > 70 else "Critical",
                f"Isolation score: {isolation_score}%. {'Slice isolation intact.' if isolation_score > 70 else 'Cross-slice access detected!'}",
                "3GPP TS 33.501 §A.9 | TS 23.501 §5.15 | GSMA FS.40 §6.2")

            # Isolation heat map
            categories = ["Control Plane", "User Plane", "PFCP Sessions", "QoS Flows", "Charging", "Logging"]
            scores = [random.randint(50, 100) for _ in categories]
            fig = go.Figure(go.Bar(
                x=scores, y=categories, orientation="h",
                marker=dict(color=["#16a34a" if s >= 80 else "#ca8a04" if s >= 60 else "#dc2626" for s in scores]),
            ))
            fig.update_layout(
                title="Slice Isolation Score per Dimension",
                xaxis=dict(range=[0, 100], title="Score (%)"),
                plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                font=dict(color="#e2e8f0"), height=300,
            )
            st.plotly_chart(fig, use_container_width=True)
            st.metric("Overall Isolation Score", f"{isolation_score}%",
                      delta="PASS" if isolation_score > 70 else "FAIL")
            st.divider()

        st.markdown("### 📋 TSTP — Slice Isolation")
        entry = TSTP.get("TELSEC-5G-SL-001")
        if entry:
            render_tstp_card(entry, "TELSEC-5G-SL-001")


# ════════════════════════════════════════════════════════════════════════════
# TAB 4: gNB INTERFACE TESTING
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("📡 gNB Interface Testing")
    col_f4, col_r4 = st.columns([1, 2])

    with col_f4:
        iface4 = st.selectbox("Interface", ["F1-C", "F1-U", "E1", "Xn-C", "Xn-U", "NG-C (N2)", "NG-U (N3)"], key="gnb_iface")
        atk4 = st.selectbox("Attack Type", [
            "F1-C Control Plane Eavesdropping",
            "Xn Handover Hijacking",
            "NG-AP Message Injection (N2)",
            "RRC Connection Establishment Abuse",
            "PDCP SN Prediction (E1 interface)",
            "gNB Impersonation via Xn",
            "UE Context Release via NG-C",
        ], key="gnb_atk")
        gnb_id = st.text_input("gNB Identity (Global gNB-ID + PLMN)", placeholder="gNB-ID=1234567, MCC=404, MNC=20", key="gnb_id")
        tls_st = st.radio("TLS/IPSec Status", ["Enabled", "Disabled", "Certificate Expired"], horizontal=True, key="gnb_tls")
        oran = st.checkbox("Open RAN (O-RAN) Deployment", value=False, key="gnb_oran")
        run4 = st.button("▶ Simulate gNB Attack", key="gnb_run", use_container_width=True, type="primary")

    with col_r4:
        if run4:
            risk_mult = 1.5 if tls_st == "Disabled" else 1.2 if tls_st == "Certificate Expired" else 1.0
            base_sev = "Critical" if "NG-AP" in atk4 or "Impersonation" in atk4 else "High"
            oran_note = " ⚠ O-RAN E2 interface also exposed." if oran else ""

            if "NG-AP" in atk4 or "Context Release" in atk4:
                st.code(
                    "-- Simulated NGAP PDU --\nNGSetupRequest {\n"
                    f"  globalRANNodeID: gNB-ID={gnb_id or '0x1234567'}\n"
                    "  rANNodeName: rogue-gnb.lab\n"
                    "  supportedTAList: [ TAC=0x001, PLMNIdentity=MCC404-MNC20 ]\n"
                    "  defaultPagingDRX: v128\n}",
                    language="text",
                )
            elif "Xn" in atk4:
                st.code(
                    "-- XnAP HandoverRequest (spoofed) --\nXnSetupRequest: {\n"
                    f"  globalNG-RAN-NodeID: gNB-ID={gnb_id or 'ROGUE_GNB'}\n"
                    "  TAC: 0x0002\n  handoverCandidate: UE-Context-ID=42\n}",
                    language="text",
                )
            else:
                st.code(f"-- {iface4} Attack: {atk4} --\nInterface: {iface4}\nTLS: {tls_st}{oran_note}", language="text")

            _fc(f"gNB {atk4} via {iface4}", base_sev,
                f"Risk multiplier: {risk_mult}x (TLS: {tls_st}).{oran_note} "
                "AMF should reject NGSetup from unregistered gNB-ID. IPSec mandatory on N2 per TS 33.501 §9.2.",
                "3GPP TS 38.413 (NGAP) | TS 33.501 §9.2 | TS 33.511 §4.2 | O-RAN WG11")

            if tls_st == "Disabled":
                st.error("🚨 **TLS/IPSec DISABLED** — all gNB interface traffic is cleartext. Immediate remediation required.")
            elif tls_st == "Certificate Expired":
                st.warning("⚠️ **Certificate Expired** — TLS handshake will fail for new sessions. Renew certificate immediately.")
            st.divider()

        st.markdown("### 📋 TSTP — gNB Interface")
        for tid in ["TELSEC-5G-GNB-001", "TELSEC-5G-GNB-002"]:
            entry = TSTP.get(tid)
            if entry:
                render_tstp_card(entry, tid)

        with st.expander("📊 gNB TSTP Status"):
            render_tstp_table({k: v for k, v in TSTP.items() if "GNB" in k})


# ════════════════════════════════════════════════════════════════════════════
# TAB 5: PFCP / UPF TESTING
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("🔀 PFCP / UPF Testing")
    col_f5, col_r5 = st.columns([1, 2])

    with col_f5:
        pfcp_atk = st.selectbox("PFCP Attack Type", [
            "Session Establishment with invalid SEID",
            "PFCP Session Modification — QoS Bypass",
            "PFCP Heartbeat Suppression (DoS)",
            "GTP-U Packet Injection (N3 interface)",
            "UPF PFCP Association Takeover",
            "Cross-PFCP Session SEID Collision",
        ], key="pfcp_atk")
        upf_ip = st.text_input("UPF IP Address", placeholder="192.168.10.10", key="pfcp_upf")
        smf_ip = st.text_input("Legitimate SMF IP", placeholder="192.168.10.1", key="pfcp_smf")
        seid   = st.text_input("Target SEID (Session Endpoint Identifier)", placeholder="0x0000000000000001", key="pfcp_seid")
        run5   = st.button("▶ Simulate PFCP Attack", key="pfcp_run", use_container_width=True, type="primary")

    with col_r5:
        if run5:
            _flow([
                f"Attacker → UPF [{upf_ip or 'TARGET_UPF'}]: PFCP Session Establishment Request",
                f"Spoofed SMF IP: [{smf_ip or 'SPOOFED_SMF'}], SEID: {seid or '0xDEAD'}",
                f"Attack: {pfcp_atk}",
                "UPF validates F-SEID source IP against SMF whitelist",
                "Expected: PFCP Session Establishment Rejection (Cause: Request Rejected)",
                "If accepted: attacker controls data plane for target UE sessions",
            ])
            _fc(f"PFCP — {pfcp_atk}", "Critical",
                f"UPF N4 interface must only accept PFCP from whitelisted SMF IPs. "
                f"Node separation and GTP-U packet filtering required per TS 33.501 §9.3.",
                "3GPP TS 29.244 (PFCP) | TS 33.501 §9.3 | GSMA FS.40")

        st.markdown("### 📋 Relevant TSTP")
        for tid in ["TELSEC-5G-SBA-001", "TELSEC-5G-SL-001"]:
            entry = TSTP.get(tid)
            if entry:
                render_tstp_card(entry, tid)

# ── Export ────────────────────────────────────────────────────────────────────
st.divider()
with st.expander("📤 Export 5G Security TSTP Report (JSON)"):
    rel = {k: v for k, v in TSTP.items() if "5G" in k or "SBA" in k or "SL" in k or "GNB" in k}
    report = export_tstp_report(rel)
    st.download_button("⬇ Download JSON", data=json.dumps(report, indent=2).encode(),
                       file_name="telsec_5g_security_report.json", mime="application/json")
    st.json(report, expanded=False)
