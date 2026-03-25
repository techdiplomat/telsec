"""
pages/10_threat_intel.py — Telecom Threat Intelligence Dashboard
Wired to: nuclei (CVE), zmap, whois, dnsrecon, lucid, sigfw
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
    background:linear-gradient(135deg,rgba(239,68,68,.06),rgba(139,92,246,.04));
    border:1px solid rgba(255,255,255,.06); border-radius:14px; padding:20px 24px; margin-bottom:24px;
}
.page-hero-icon { font-size:2.2rem; }
.page-hero-title { font-size:1.4rem; font-weight:700; color:#f8fafc; }
.page-hero-sub { font-size:0.85rem; color:#94a3b8; margin-top:2px; }
.ioc-card {
    background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07);
    border-radius:8px; padding:12px 16px; margin-bottom:8px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">🛡️</div>
  <div>
    <div class="page-hero-title">Telecom Threat Intelligence</div>
    <div class="page-hero-sub">IoC scanning · CVE database · Signaling firewall · Network OSINT research</div>
  </div>
</div>
""", unsafe_allow_html=True)

render_kali_status_mini()

tab1, tab2, tab3, tab4 = st.tabs([
    "🔎 CVE & Template Scan", "🌐 Network OSINT", "🧱 SigFW Rule Audit", "📋 IoC Feed"
])

# ─────────────────────────────────────────────────────────────────────────
with tab1:
    st.markdown("#### CVE & Nuclei Template Scan")
    c1, c2 = st.columns(2)
    with c1:
        nuclei_target    = st.text_input("Target Host / URL", "https://example.com", key="nuclei_target")
        nuclei_templates = st.multiselect("Template Tags", [
            "cve", "telecom", "exposed-panels", "misconfigurations",
            "default-logins", "network", "ssl"
        ], default=["cve"])
    with c2:
        nuclei_severity  = st.multiselect("Severity Filter", ["critical", "high", "medium", "low", "info"], default=["critical", "high"])
        nuclei_rate      = st.slider("Rate Limit (req/sec)", 10, 1000, 150)

    if st.button("🚀 Run Nuclei Scan", type="primary", key="btn_nuclei"):
        tags = ",".join(nuclei_templates)
        sev  = ",".join(nuclei_severity)
        with st.spinner(f"Scanning {nuclei_target}..."):
            result = run_tool("nuclei", {
                "target": nuclei_target,
                "templates": tags,
                "severity": sev,
                "rate_limit": nuclei_rate,
            })
        render_tool_result(result, "Nuclei")

# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("#### Network OSINT & Recon")
    c1, c2 = st.columns(2)
    with c1:
        osint_domain = st.text_input("Target Domain / IP", "mnc020.mcc404.3gppnetwork.org", key="osint_domain")
    with c2:
        osint_tools  = st.multiselect("Tools to run", ["whois", "dnsrecon", "zmap"], default=["whois", "dnsrecon"])

    if st.button("🔍 Run OSINT Recon", type="primary", key="btn_osint"):
        for tool in osint_tools:
            st.markdown(f"**{tool.upper()} results:**")
            with st.spinner(f"Running {tool}..."):
                if tool == "dnsrecon":
                    result = run_tool("dnsrecon", {"domain": osint_domain, "types": "std,rvl,brt"})
                elif tool == "whois":
                    result = run_tool("whois", {"target": osint_domain})
                else:
                    result = run_tool("zmap", {"target": osint_domain})
            render_tool_result(result, tool.upper())

# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("#### Signaling Firewall (SigFW) Rule Audit")
    st.caption("Audit SigFW blocking rules against known SS7/Diameter attack signatures.")
    sigfw_host = st.text_input("SigFW API Endpoint", "http://localhost:8080", key="sigfw_host")

    col_rules = {
        "MAP ATI Blocking Rule": "Block unsolicited ATI from untrusted GT",
        "Diameter Origin-Realm Whitelist": "Reject unknown realms at Diameter border",
        "GTP-C Rate Limiting": "Max 100 session requests/sec per IP",
        "5G SBI mTLS Enforcement": "NF communication requires mutual TLS",
        "MAP SRI-SM screening": "Block SRI-SM from non-home GT",
    }

    for rule, desc in col_rules.items():
        c1, c2, c3 = st.columns([3, 2, 1])
        c1.write(f"**{rule}**")
        c2.caption(desc)
        c3.markdown('<span style="color:#10b981">✅</span>', unsafe_allow_html=True)

    if st.button("🧱 Live Audit SigFW Config", type="primary", key="btn_sigfw"):
        with st.spinner("Connecting to SigFW REST API..."):
            result = run_tool("sigfw", {"host": sigfw_host, "action": "audit"})
        render_tool_result(result, "SigFW Audit")

# ─────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("#### Indicators of Compromise (IoC) Feed")
    st.markdown("""
    <div class="ioc-card">
      <div style="font-size:.75rem;color:#64748b;text-transform:uppercase;margin-bottom:8px">Recent Telecom IoC Activity (Simulated Feed)</div>
    """, unsafe_allow_html=True)

    iocs = [
        ("GT", "919012345678", "Known SS7 attacker GT — 3 ATI events in 24h", "HIGH"),
        ("Realm", "epc.attacker-net.com", "Unauthorized Diameter realm – seen in CL spoofing", "CRITICAL"),
        ("IP", "185.220.101.42", "Tor exit node probing SBI ports", "MEDIUM"),
        ("GT", "447700000001", "SMSC associated with SMiShing campaign", "HIGH"),
        ("IMSI prefix", "404 56", "Leaked IMSI range from HLR dump", "CRITICAL"),
    ]

    for ioc_type, ioc_val, desc, sev in iocs:
        color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#fbbf24"}.get(sev, "#94a3b8")
        st.markdown(f"""
        <div class="ioc-card" style="border-left:3px solid {color}">
          <div style="display:flex;justify-content:space-between;">
            <div>
              <span style="font-size:.7rem;font-weight:600;color:#94a3b8;text-transform:uppercase">{ioc_type}</span>
              <span style="font-family:'JetBrains Mono';font-size:.85rem;color:#f8fafc;margin-left:8px">{ioc_val}</span>
            </div>
            <span style="font-size:.75rem;font-weight:600;color:{color}">{sev}</span>
          </div>
          <div style="font-size:.8rem;color:#64748b;margin-top:4px">{desc}</div>
        </div>
        """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
