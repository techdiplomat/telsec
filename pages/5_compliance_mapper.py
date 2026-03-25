"""
TelSec — Page 5: Compliance & Regulatory Mapping
==================================================
Tabs: Standard Selector | Finding Mapper | Gap Analysis |
      India Regulatory (TEC/TRAI/DoT/CERT-In)
"""
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import json, random

from tstp_data import TSTP
from utils.tstp_engine import render_tstp_card, render_tstp_table, export_tstp_report

st.set_page_config(page_title="TelSec — Compliance Mapper", page_icon="📜", layout="wide")

# ── Standard definitions ──────────────────────────────────────────────────────
STANDARDS = {
    "GSMA FS.11 v6.0": {
        "desc": "SS7 Network Interconnect (MAP) Security Requirements",
        "controls": {
            "FS.11-CAT1": ("Block unauthorized MAP operations — mandatory", "Critical"),
            "FS.11-CAT2": ("Alert/block location & routing info disclosure", "Critical"),
            "FS.11-CAT3": ("Detect coordinated multi-message attacks", "High"),
            "FS.11-LOG":  ("Comprehensive logging of all blocked traffic", "High"),
            "FS.11-SOC":  ("SOC integration and alerting within 30s", "Medium"),
        },
    },
    "GSMA FS.19 v4.0": {
        "desc": "Diameter Interconnect Security",
        "controls": {
            "FS.19-DRA":  ("Deployed DRA with peer whitelisting", "Critical"),
            "FS.19-TLS":  ("mTLS enforced on all Diameter interfaces", "Critical"),
            "FS.19-DOIC": ("Overload protection (RFC 7683 DOIC)", "High"),
            "FS.19-RATE": ("Rate limiting on all diameter interfaces", "High"),
        },
    },
    "GSMA FS.40 v3.0": {
        "desc": "5G Network Security Requirements",
        "controls": {
            "FS.40-MTLS": ("mTLS on all SBI interfaces (TS 33.501 §13)", "Critical"),
            "FS.40-OAUTH":("OAuth 2.0 NF access tokens enforced", "Critical"),
            "FS.40-SLICE":("Network slice isolation enforced", "High"),
            "FS.40-GNB":  ("N2 interface IPSec enforced", "Critical"),
        },
    },
    "3GPP TS 33.117 SCAS": {
        "desc": "Security Assurance Specification for NEs",
        "controls": {
            "SCAS-AUTH":  ("NE requires strong mutual authentication", "Critical"),
            "SCAS-AUDIT": ("Audit logging per TS 33.117 §4.2", "High"),
            "SCAS-PATCH": ("Software vulnerability management process", "High"),
            "SCAS-CRYPT": ("Only approved ciphers — no NULL/export", "Critical"),
        },
    },
    "3GPP TS 33.501 (5G)": {
        "desc": "Security architecture for 5G system",
        "controls": {
            "33501-SUCI":  ("SUCI concealment mandatory for UE identity", "Critical"),
            "33501-NDS":   ("Network Domain Security (NDS/IP) enforced", "Critical"),
            "33501-OAUTH": ("OAuth 2.0 for NF service authorization §13", "Critical"),
            "33501-SLICE": ("Slice security isolation §A.9", "High"),
        },
    },
    "NIST SP 800-187": {
        "desc": "Guide to LTE Security",
        "controls": {
            "NIST-ECP":  ("Subscriber authentication using EPS-AKA", "High"),
            "NIST-SEC":  ("S1-AP/X2-AP integrity protection enforced", "High"),
            "NIST-CIPH": ("NULL cipher not allowed in production", "Critical"),
        },
    },
}

INDIA_REGS = {
    "TEC ITSAR (Telecom Equipment Security)": {
        "desc": "India TEC mandatory security requirements for telecom equipment licensing (2021)",
        "controls": {
            "ITSAR-4.1": ("SS7 firewall with GSMA FS.11 Cat-1/2/3 rules", "Critical"),
            "ITSAR-4.2": ("Diameter firewall per GSMA FS.19", "Critical"),
            "ITSAR-4.3": ("GTP-C/U firewall deployed on international interfaces", "High"),
            "ITSAR-4.4": ("Vulnerability disclosure timeline: severity-based", "Medium"),
            "ITSAR-4.5": ("Annual third-party security audit mandatory", "High"),
            "ITSAR-5.1": ("5G NF software integrity verification required", "High"),
            "ITSAR-5.2": ("SUCI concealment enforced for 5G UEs", "Critical"),
        },
    },
    "DoT License Conditions (UL/UAS)": {
        "desc": "Dept. of Telecommunications Unified Licence security clauses",
        "controls": {
            "DOT-SEC1":  ("TSPs must adopt GSMA security standards", "Critical"),
            "DOT-SEC2":  ("Lawful intercept compatibility (CALEA-equivalent)", "Critical"),
            "DOT-SEC3":  ("Subscriber data protection — no unauthorized disclosure", "Critical"),
            "DOT-SEC4":  ("Significant security incident reporting within 6h to DoT", "High"),
            "DOT-SEC5":  ("International roaming security controls mandatory", "High"),
        },
    },
    "TRAI Telecom Security Regulations": {
        "desc": "TRAI recommendations on network security and subscriber data protection",
        "controls": {
            "TRAI-SIM":  ("SIM swap fraud prevention controls", "Critical"),
            "TRAI-KYC":  ("eKYC verification with biometric for new SIM", "High"),
            "TRAI-OTP":  ("OTP authentication for critical transactions", "High"),
            "TRAI-DATA": ("Subscriber data localization compliance", "Medium"),
            "TRAI-SPAM": ("TCCCPR 2018 — commercial communication filtering", "Medium"),
        },
    },
    "CERT-In Directions (MeitY 2022)": {
        "desc": "Mandatory cybersecurity reporting and controls for TSPs",
        "controls": {
            "CERT-6H":   ("Report cybersecurity incidents within 6 hours to CERT-In", "Critical"),
            "CERT-LOG":  ("Maintain ICT system logs for 180 days", "High"),
            "CERT-NTP":  ("Synchronize systems to NTP from govt. servers", "Medium"),
            "CERT-VPN":  ("VPN service providers maintain subscriber logs", "High"),
            "CERT-KYCC": ("Conduct KYC verification of subscribers", "Medium"),
        },
    },
}

# ── TSTP mapped to standard controls ─────────────────────────────────────────
TSTP_CONTROL_MAP = {
    "TELSEC-LOC-001": ["FS.11-CAT2", "FS.11-CAT3", "ITSAR-4.1"],
    "TELSEC-LOC-002": ["FS.19-DRA", "FS.19-TLS", "ITSAR-4.2"],
    "TELSEC-ID-001":  ["33501-SUCI", "ITSAR-5.2", "NIST-ECP"],
    "TELSEC-ID-002":  ["FS.11-CAT1", "ITSAR-4.1"],
    "TELSEC-INT-001": ["FS.11-CAT2", "FS.26-SHR", "ITSAR-4.1"],
    "TELSEC-INT-002": ["ITSAR-4.3", "FS.20-GTP"],
    "TELSEC-INT-003": ["FS.19-DRA", "ITSAR-4.2"],
    "TELSEC-DOS-001": ["FS.11-CAT2", "FS.11-SOC", "DOT-SEC4"],
    "TELSEC-DOS-002": ["FS.19-DOIC", "FS.19-RATE"],
    "TELSEC-AUTH-001":["33501-SUCI", "NIST-CIPH", "ITSAR-5.2"],
    "TELSEC-AUTH-002":["FS.19-TLS", "ITSAR-4.2", "33501-OAUTH"],
    "TELSEC-5G-SBA-001":["FS.40-OAUTH", "FS.40-MTLS", "33501-OAUTH"],
    "TELSEC-5G-SBA-002":["FS.40-OAUTH", "33501-OAUTH", "SCAS-AUTH"],
    "TELSEC-5G-SL-001": ["FS.40-SLICE", "33501-SLICE"],
    "TELSEC-5G-GNB-001":["FS.40-GNB", "33501-NDS", "NIST-SEC"],
    "TELSEC-5G-GNB-002":["FS.40-GNB", "33501-NDS"],
    "TELSEC-RECON-001": ["FS.11-CAT2", "ITSAR-4.1"],
    "TELSEC-RECON-002": ["FS.19-DRA", "SCAS-AUDIT"],
    "TELSEC-FUZZ-001":  ["SCAS-AUTH", "SCAS-PATCH", "ITSAR-4.5"],
    "TELSEC-FUZZ-002":  ["SCAS-AUTH", "SCAS-PATCH", "FS.19-DRA"],
    "TELSEC-FUZZ-003":  ["FS.40-MTLS", "SCAS-PATCH", "ITSAR-5.1"],
    "TELSEC-COMP-001":  ["FS.11-CAT1", "FS.11-CAT2", "FS.11-LOG", "FS.11-SOC", "ITSAR-4.1", "ITSAR-4.5"],
}

st.title("📜 Compliance & Regulatory Mapping")
st.caption("Map TelSec test findings to GSMA, 3GPP, ITU-T, NIST, and India regulatory requirements.")
st.divider()

tab1, tab2, tab3, tab4 = st.tabs([
    "🗂 Standard Selector",
    "🔗 Finding Mapper",
    "📊 Gap Analysis",
    "🇮🇳 India Regulatory",
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1: STANDARD SELECTOR
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🗂 Select Standards for Compliance Assessment")

    selected_standards = st.multiselect(
        "Select Standards to Assess Against",
        list(STANDARDS.keys()),
        default=["GSMA FS.11 v6.0", "GSMA FS.40 v3.0", "3GPP TS 33.501 (5G)"],
        key="stds_select",
    )

    if not selected_standards:
        st.info("Select at least one standard above.")
    else:
        for std_name in selected_standards:
            std = STANDARDS[std_name]
            with st.expander(f"📘 {std_name} — {std['desc']}", expanded=False):
                rows = []
                for ctrl_id, (ctrl_desc, ctrl_sev) in std["controls"].items():
                    verdict = st.session_state.get(f"ctrl_{ctrl_id}", "NOT ASSESSED")
                    rows.append({
                        "Control ID": ctrl_id,
                        "Description": ctrl_desc,
                        "Severity": ctrl_sev,
                        "Status": verdict,
                    })
                import pandas as pd
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

                c1, c2, c3 = st.columns(3)
                total = len(std["controls"])
                assessed = sum(1 for r in rows if r["Status"] != "NOT ASSESSED")
                c1.metric("Total Controls", total)
                c2.metric("Assessed", assessed)
                c3.metric("Coverage", f"{100*assessed//total if total else 0}%")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2: FINDING MAPPER
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("🔗 Map Test Findings to Compliance Controls")

    col_f2, col_r2 = st.columns([1, 2])

    with col_f2:
        tstp_id = st.selectbox("Select TSTP Test Case", list(TSTP_CONTROL_MAP.keys()), key="map_tstp")
        verdict = st.radio("Test Verdict", ["PASS", "FAIL", "PARTIAL"], horizontal=True, key="map_verdict")
        findings_txt = st.text_area("Finding Description (optional)", height=100, key="map_finding",
                                    placeholder="e.g. SS7 firewall accepts MAP_ATI from external GT. Cell-ID returned.")
        map_btn = st.button("🔗 Map to Controls", key="map_btn", use_container_width=True, type="primary")

    with col_r2:
        if map_btn or tstp_id:
            mapped_controls = TSTP_CONTROL_MAP.get(tstp_id, [])
            tstp_entry = TSTP.get(tstp_id, {})

            st.markdown(f"**Test:** `{tstp_id}` — {tstp_entry.get('title', '')}")
            st.markdown(f"**Verdict:** {'🔴 FAIL' if verdict=='FAIL' else '🟢 PASS' if verdict=='PASS' else '🟡 PARTIAL'}")

            if mapped_controls:
                st.markdown("**Mapped Controls:**")
                control_rows = []
                for ctrl in mapped_controls:
                    # Find which standard this control belongs to
                    for std_name, std in STANDARDS.items():
                        if ctrl in std["controls"]:
                            desc, sev = std["controls"][ctrl]
                            control_rows.append({
                                "Control ID": ctrl, "Standard": std_name,
                                "Description": desc, "Severity": sev,
                                "Finding Impact": verdict,
                            })
                import pandas as pd
                if control_rows:
                    st.dataframe(pd.DataFrame(control_rows), use_container_width=True, hide_index=True)
                    if verdict == "FAIL":
                        st.error(f"❌ {len(control_rows)} control(s) impacted by this FAIL finding. Remediation required.")
                    elif verdict == "PASS":
                        st.success(f"✅ {len(control_rows)} controls satisfied by this PASS finding.")
            else:
                st.info("No direct control mapping defined. Reference the TSTP references manually.")

    # TSTP card
    entry = TSTP.get(tstp_id)
    if entry:
        with st.expander("📋 Full TSTP Procedure"):
            render_tstp_card(entry, tstp_id)


# ════════════════════════════════════════════════════════════════════════════
# TAB 3: GAP ANALYSIS
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("📊 Compliance Gap Analysis")

    selected_stds_gap = st.multiselect(
        "Standards for Gap Analysis",
        list(STANDARDS.keys()),
        default=list(STANDARDS.keys()),
        key="gap_stds",
    )

    if not selected_stds_gap:
        st.info("Select standards above.")
    else:
        # Synthetic compliance score per standard
        std_names, scores, total_ctrl, gaps = [], [], [], []
        for std_name in selected_stds_gap:
            std = STANDARDS[std_name]
            n = len(std["controls"])
            compliant = random.randint(int(n * 0.4), n)
            score = round(100 * compliant / n)
            std_names.append(std_name.split()[0] + " " + std_name.split()[1] if len(std_name.split()) > 1 else std_name)
            scores.append(score)
            total_ctrl.append(n)
            gaps.append(n - compliant)

        # Radar chart
        fig_radar = go.Figure(go.Scatterpolar(
            r=scores + [scores[0]],
            theta=std_names + [std_names[0]],
            fill="toself",
            fillcolor="rgba(37,99,235,0.2)",
            line=dict(color="#2563eb", width=2),
            name="Compliance %",
        ))
        fig_radar.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(color="#94a3b8"))),
            plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
            font=dict(color="#e2e8f0"), title="Compliance Radar", height=420,
        )
        st.plotly_chart(fig_radar, use_container_width=True)

        # Bar chart
        colors = ["#16a34a" if s >= 80 else "#ca8a04" if s >= 60 else "#dc2626" for s in scores]
        fig_bar = go.Figure(go.Bar(
            x=std_names, y=scores, marker=dict(color=colors),
            text=[f"{s}%" for s in scores], textposition="outside",
        ))
        fig_bar.update_layout(
            title="Compliance Score by Standard",
            yaxis=dict(range=[0, 110], title="Score %"),
            plot_bgcolor="#0f172a", paper_bgcolor="#1e293b",
            font=dict(color="#e2e8f0"), height=350,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

        # Gap table
        import pandas as pd
        gap_df = pd.DataFrame({
            "Standard": selected_stds_gap,
            "Total Controls": total_ctrl,
            "Gap Controls": gaps,
            "Compliance %": [f"{s}%" for s in scores],
            "Status": ["✅ PASS" if s >= 80 else "⚠ PARTIAL" if s >= 60 else "❌ FAIL" for s in scores],
        })
        st.dataframe(gap_df, use_container_width=True, hide_index=True)
        st.metric("Overall Weighted Compliance", f"{sum(scores) // len(scores)}%")

        # Critical gaps highlight
        worst = min(zip(scores, selected_stds_gap), key=lambda x: x[0])
        st.error(f"🚨 Largest gap: **{worst[1]}** at {worst[0]}% compliance. Prioritize remediation here.")


# ════════════════════════════════════════════════════════════════════════════
# TAB 4: INDIA REGULATORY
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🇮🇳 India Regulatory Compliance")
    st.info("Covers TEC ITSAR, DoT UL License, TRAI, and CERT-In 2022 directions — mandatory for Indian TSPs.", icon="🇮🇳")

    selected_india = st.multiselect(
        "Indian Regulations",
        list(INDIA_REGS.keys()),
        default=list(INDIA_REGS.keys()),
        key="india_regs",
    )

    for reg_name in selected_india:
        reg = INDIA_REGS[reg_name]
        st.markdown(f"---\n#### 📋 {reg_name}")
        st.caption(reg["desc"])
        rows = []
        for ctrl_id, (ctrl_desc, ctrl_sev) in reg["controls"].items():
            mock_status = random.choice(["COMPLIANT ✅", "COMPLIANT ✅", "GAP FOUND ⚠", "NOT ASSESSED"])
            rows.append({
                "Control ID": ctrl_id,
                "Requirement": ctrl_desc,
                "Severity": ctrl_sev,
                "Status": mock_status,
            })
        import pandas as pd
        df_india = pd.DataFrame(rows)
        gaps = df_india[df_india["Status"].str.contains("GAP")].shape[0]
        compliant = df_india[df_india["Status"].str.contains("COMPLIANT")].shape[0]

        c1, c2, c3 = st.columns(3)
        c1.metric("Controls", len(rows))
        c2.metric("Compliant", compliant, delta="PASS" if gaps == 0 else None)
        c3.metric("Gaps Found", gaps, delta="FAIL" if gaps > 0 else "PASS")

        st.dataframe(df_india, use_container_width=True, hide_index=True)

    # TSTP card for COMP-001
    st.divider()
    st.markdown("### 📋 TSTP — Compliance Completeness Check")
    entry = TSTP.get("TELSEC-COMP-001")
    if entry:
        render_tstp_card(entry, "TELSEC-COMP-001")

# ── Export ────────────────────────────────────────────────────────────────────
st.divider()
with st.expander("📤 Export Compliance TSTP Report (JSON)"):
    rel = {k: v for k, v in TSTP.items() if k.startswith("TELSEC-COMP")}
    report = export_tstp_report(rel)
    # Add standard mapping
    report["standard_mapping"] = {tid: ctrls for tid, ctrls in TSTP_CONTROL_MAP.items()}
    st.download_button("⬇ Download JSON", data=json.dumps(report, indent=2).encode(),
                       file_name="telsec_compliance_report.json", mime="application/json")
    st.json(report, expanded=False)
