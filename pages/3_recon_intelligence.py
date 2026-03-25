"""
TelSec — Page 3: Telecom OSINT & Reconnaissance
=================================================
Tabs: Subscriber Enumeration | Network Topology Mapping |
      ENUM/DNS/SIP Recon | Fingerprinting
"""
import streamlit as st
import plotly.graph_objects as go
import random, json

from tstp_data import TSTP
from utils.tstp_engine import render_tstp_card, render_tstp_table, export_tstp_report

st.set_page_config(page_title="TelSec — Recon & Intelligence", page_icon="🔎", layout="wide")

SEV = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#16a34a"}

def _fc(title, severity, detail, ref=""):
    c = SEV.get(severity, "#6b7280")
    st.markdown(
        f"<div style='border-left:4px solid {c};background:#0f172a;padding:12px 16px;border-radius:6px;margin:8px 0'>"
        f"<b style='color:{c}'>ℹ {severity.upper()} — {title}</b><br>"
        f"<span style='font-size:0.88rem;color:#e2e8f0'>{detail}</span><br>"
        f"<span style='font-size:0.76rem;color:#64748b'>{ref}</span></div>",
        unsafe_allow_html=True,
    )

def _flow(steps):
    st.code("\n".join(f"{i:>2}. {s}" for i, s in enumerate(steps, 1)), language="text")

def _fake_msisdn():
    return f"+91{random.randint(700000000,999999999)}"

st.title("🔎 Telecom OSINT & Reconnaissance")
st.caption("Passive and active intelligence gathering techniques across SS7, Diameter, SIP, and 5G interfaces.")
st.info("🔒 OSINT simulations gather no real subscriber data. All output is synthetic.", icon="🛡")
st.divider()

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Subscriber Enumeration",
    "🗺 Network Topology Mapping",
    "🌐 ENUM / DNS / SIP Recon",
    "🔬 Fingerprinting",
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1: SUBSCRIBER ENUMERATION
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("📋 Subscriber Enumeration")
    col_f, col_r = st.columns([1, 2])

    with col_f:
        enum_method = st.selectbox("Enumeration Method", [
            "MAP SRI (Send-Routing-Info) — MSISDN→IMSI",
            "MAP SRI-SM (SMS Home Routing probe)",
            "MAP SendIMSI (direct IMSI query)",
            "Diameter S6a — ULR (Update-Location-Req probe)",
            "5G SUPI via AMF Registration probe",
        ], key="enum_method")
        start_msisdn = st.text_input("Start MSISDN (batch range)", value="+917000000000", key="enum_start")
        batch_size   = st.slider("Batch Size", 1, 500, 10, key="enum_batch")
        mcc_mnc_e    = st.text_input("Target MCC-MNC", value="404-20", key="enum_mcc")
        run_e = st.button("▶ Run Enumeration Probe", key="enum_run", use_container_width=True, type="primary")

    with col_r:
        if run_e:
            _flow([
                f"Method: {enum_method}",
                f"Target Network: MCC-MNC {mcc_mnc_e}",
                f"Starting MSISDN: {start_msisdn}",
                f"Batch size: {batch_size} sequential numbers",
                "Sending probes via SS7 test STP or Diameter test node",
                "Rate: measuring responses per second",
                "Logging: IMSI returned? MSC address? Anonymized SMSHRN?",
            ])

            # Synthetic results table
            results = []
            for i in range(min(batch_size, 15)):
                msisdn = f"+91{int(start_msisdn.replace('+91','').replace('+','').strip()[:10]) + i:010d}"
                exposed = random.random() < 0.3  # 30% chance exposed (vulnerability present)
                results.append({
                    "MSISDN": msisdn,
                    "Response": "IMSI Returned ⚠" if exposed else "SMSHRN (anonymized) ✅",
                    "MSC Exposed": "YES ⚠" if exposed else "NO ✅",
                    "Status": "FAIL" if exposed else "PASS",
                })

            import pandas as pd
            df = pd.DataFrame(results)
            fail_count = (df["Status"] == "FAIL").sum()
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.metric("Exposed Subscribers (simulated)", f"{fail_count}/{len(results)}",
                      delta="FAIL — SHR or rate-limit missing" if fail_count > 0 else "PASS")

            if fail_count > 0:
                _fc("Subscriber IMSI/MSC Exposure via Enumeration", "High",
                    f"{fail_count}/{len(results)} MSISDNs returned real IMSI and MSC address. SMS Home Routing or FS.11 Cat-2 filter absent.",
                    "GSMA FS.11 Cat-2 | GSMA FS.26 §4.2 | IR.70 (SHR)")
            else:
                st.success("✅ All responses anonymized — SMS Home Routing active, FS.11 Cat-2 filtering effective.")
            st.divider()

        st.markdown("### 📋 TSTP — Subscriber Enumeration")
        entry = TSTP.get("TELSEC-RECON-001")
        if entry:
            render_tstp_card(entry, "TELSEC-RECON-001")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2: NETWORK TOPOLOGY MAPPING
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("🗺 Network Topology Mapping")
    col_f2, col_r2 = st.columns([1, 2])

    with col_f2:
        topo_method = st.selectbox("Discovery Method", [
            "SCCP SST → STP Subsystem Discovery",
            "SCCP Capability / Cluster Messages",
            "Diameter CER/CEA Peer Enumeration",
            "Diameter DWR Hop-Count Probing",
            "SNMP MIB Walk (if exposed)",
            "SIP OPTIONS Sweep",
        ], key="topo_method")
        gateway_gt = st.text_input("Known STP/DRA Gateway GT", placeholder="441234567890 or 10.0.0.1", key="topo_gt")
        run2 = st.button("▶ Run Topology Probe", key="topo_run", use_container_width=True, type="primary")

    with col_r2:
        if run2:
            _flow([
                f"Target: {gateway_gt or 'GATEWAY_GT'}",
                f"Method: {topo_method}",
                "Probe 1: Send SCCP SST (Subsystem-Status-Test) to gateway" if "SCCP" in topo_method else
                "Probe 1: Send Diameter CER with minimal capabilities to DRA",
                "Observe SSA/SSP response → extract subsystems, adjacent nodes",
                "Build topology map from responses",
                "Check: are internal node addresses/point codes exposed in error messages?",
            ])

            # Synthetic topology
            nodes = ["Gateway STP", "Internal STP-A", "HLR", "MSC-1", "MSC-2", "VLR"] if "SCCP" in topo_method else \
                    ["DRA-Primary", "DRA-Secondary", "HSS", "OCS", "PCRF", "MME-Pool"]
            exposed = random.sample(nodes, k=random.randint(1, 3))

            fig = go.Figure()
            for i, node in enumerate(nodes):
                color = "#dc2626" if node in exposed else "#2563eb"
                fig.add_trace(go.Scatter(
                    x=[i], y=[0], mode="markers+text",
                    marker=dict(size=40, color=color),
                    text=[node], textposition="bottom center",
                    name=node,
                ))
            fig.update_layout(
                title="Discovered Topology (Red = Internal addresses exposed)",
                plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
                font=dict(color="#e2e8f0"), showlegend=False,
                height=250, xaxis=dict(visible=False), yaxis=dict(visible=False),
            )
            st.plotly_chart(fig, use_container_width=True)

            _fc("Internal Node Address Exposure", "Medium",
                f"Exposed nodes: {', '.join(exposed)}. Internal STP/DRA point codes visible in SCCP/Diameter error messages or capability exchanges.",
                "GSMA FS.07 §4 | GSMA FS.11 §4.3 | ITU-T Q.714")
            st.divider()

        st.markdown("### 📋 TSTP — Topology Mapping")
        entry = TSTP.get("TELSEC-RECON-002")
        if entry:
            render_tstp_card(entry, "TELSEC-RECON-002")

        with st.expander("📊 Recon TSTP Status"):
            render_tstp_table({k: v for k, v in TSTP.items() if k.startswith("TELSEC-RECON")})


# ════════════════════════════════════════════════════════════════════════════
# TAB 3: ENUM / DNS / SIP RECON
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🌐 ENUM / DNS / SIP Reconnaissance")
    col_f3, col_r3 = st.columns([1, 2])

    with col_f3:
        recon_type = st.selectbox("Recon Type", [
            "ENUM (NAPTR) — Phone Number to SIP URI",
            "DNS Zone Transfer (telecom domain)",
            "SIP OPTIONS Scan (IMS ProSe / VoLTE)",
            "SIP REGISTER enumeration",
            "Diameter FQDN brute-force",
            "NRF DNS-SD / mDNS discovery (5G)",
        ], key="sip_type")
        target_domain = st.text_input("Target Domain", placeholder="imsoperator.com or epc.mnc020.mcc404.3gppnetwork.org", key="sip_domain")
        run3 = st.button("▶ Run Recon", key="sip_run", use_container_width=True, type="primary")

    with col_r3:
        if run3:
            if "ENUM" in recon_type:
                _flow([
                    f"Query ENUM DNS for e164.arpa: {target_domain or 'e164.arpa'}",
                    "Resolve NAPTR records for target phone number",
                    "Extract SIP URI or TEL URI from NAPTR response",
                    "Cross-reference with IMSI via MAP SRI (if SS7 access available)",
                ])
                st.code(
                    f";; NAPTR record for +91XXXXXXXXXX.e164.arpa\n"
                    f"100 10 u E2U+sip !^.*$!sip:user@{target_domain or 'ims.operator.com'}! .\n"
                    f"100 10 u E2U+tel !^.*$!tel:+91XXXXXXXXXX! .",
                    language="text",
                )
                _fc("ENUM NAPTR Record Exposes SIP URI", "Medium",
                    "Subscriber's SIP identity discoverable via ENUM DNS. If not secured, enables SIP scanning and identity enumeration.",
                    "RFC 3761 (ENUM) | GSMA IR.67 (IMS) | ITU-T E.164")
            elif "DNS Zone" in recon_type:
                _flow([
                    f"Attempt DNS zone transfer: dig AXFR {target_domain or 'epc.mnc020.mcc404.3gppnetwork.org'}",
                    "Check response: REFUSED (secure) or full zone transfer (vulnerable)",
                    "Extract: MME FQDNs, HSS addresses, PGW hostnames, PCRF IPs",
                ])
                st.code(
                    f"; (Simulated zone transfer excerpt)\n"
                    f"mme-pool.{target_domain or 'epc.operator.net'}.  IN A  10.1.2.3\n"
                    f"hss.{target_domain or 'epc.operator.net'}.        IN A  10.1.2.4\n"
                    f"pgw.{target_domain or 'epc.operator.net'}.        IN A  10.1.2.5\n"
                    f"; TSIG authentication: NOT PRESENT (vulnerable)",
                    language="text",
                )
                _fc("DNS Zone Transfer — Core Network Topology Exposed", "High",
                    "DNS AXFR not restricted. Internal MME/HSS/PGW IP addresses and FQDNs disclosed to external queriers.",
                    "RFC 5936 (DNS AXFR) | GSMA FS.40 §5.3 | 3GPP TS 23.003")
            else:
                _flow([
                    f"SIP OPTIONS sweep on {target_domain or 'ims.operator.com'}:5060",
                    "Enumerate registered SIP URIs via 200 OK vs 404 Not Found response timing",
                    f"Target: sip:user@{target_domain or 'ims.operator.com'}",
                ])
                _fc(f"{recon_type}","Medium",
                    "SIP server responses allow subscriber enumeration. Rate limiting or captcha-equivalent not enforced on OPTIONS.",
                    "RFC 3261 (SIP) | GSMA IR.92 (VoLTE) | OWASP VoIP Top 10")


# ════════════════════════════════════════════════════════════════════════════
# TAB 4: FINGERPRINTING
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🔬 Telecom Node Fingerprinting")
    col_f4, col_r4 = st.columns([1, 2])

    with col_f4:
        fp_target = st.selectbox("Target Node Type", ["SS7 HLR/MSC/STP", "Diameter HSS/DRA", "5G AMF/NRF", "SIP Proxy/CSCF", "GTP PGW/UPF"], key="fp_target")
        fp_method = st.selectbox("Fingerprint Method", [
            "Error message vendor string analysis",
            "Timing side-channel (response latency)",
            "Protocol capability enumeration",
            "TCP/SCTP stack fingerprint (TTL, window size)",
            "TLS/DTLS cipher suite probing",
        ], key="fp_method")
        target_ip_fp = st.text_input("Target IP/FQDN", placeholder="192.168.1.10 or node.operator.net", key="fp_ip")
        run4 = st.button("▶ Fingerprint Node", key="fp_run", use_container_width=True, type="primary")

    with col_r4:
        if run4:
            vendors = ["Ericsson MSC-S/HLR", "Nokia NetAct HSS", "Huawei USN/HLR", "ZTE MSCS", "Generic OpenSS7", "Ulticom SCTP Stack"]
            detected = random.choice(vendors)
            confidence = random.randint(55, 92)

            _flow([
                f"Target: {fp_target} @ {target_ip_fp or 'TARGET'}",
                f"Method: {fp_method}",
                "Probe sent → analyzing response characteristics",
                f"Error message pattern match: '{detected}'",
                f"Protocol capability vector: {random.randint(5,15)} features matched",
                f"Confidence: {confidence}%",
            ])

            st.metric("Detected Vendor/Version", detected, delta=f"{confidence}% confidence")
            _fc("Node Fingerprinting Successful", "Medium",
                f"Node {fp_target} fingerprinted as **{detected}** with {confidence}% confidence via {fp_method}. "
                "Vendor/version information aids targeted CVE exploitation.",
                "CVE NIST NVD | GSMA FS.11 §4.5 | OWASP Information Disclosure")

            # Known CVE suggestions
            st.markdown("**🔍 Associated CVE References (simulated lookup):**")
            cves = [f"CVE-2024-{random.randint(10000,59999)}", f"CVE-2023-{random.randint(10000,59999)}"]
            for cve in cves:
                st.markdown(f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve}) — Check vendor advisory")

# ── Export ─────────────────────────────────────────────────────────────────────
st.divider()
with st.expander("📤 Export Recon TSTP Report (JSON)"):
    rel = {k: v for k, v in TSTP.items() if k.startswith("TELSEC-RECON")}
    report = export_tstp_report(rel)
    st.download_button("⬇ Download JSON", data=json.dumps(report, indent=2).encode(),
                       file_name="telsec_recon_report.json", mime="application/json")
    st.json(report, expanded=False)
