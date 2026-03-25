"""
TelSec — SIP / VoLTE Security Testing (Page 14)
================================================
Covers: SIP Device Discovery (svmap), Extension Bruteforce (svwar),
        SIP OPTIONS probe, Kamailio/IMS security test
"""
import streamlit as st

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">📞</div>
  <div>
    <div class="page-hero-title">SIP / VoLTE Security</div>
    <div class="page-hero-sub">SIPVicious enumeration · Extension bruteforce · Kamailio probe · IMS/VoLTE signaling audit</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Kali connector ────────────────────────────────────────────────────────────
from kali_connector import run_tool, render_tool_result
try:
    from kali_connector import render_kali_status_mini
except ImportError:
    def render_kali_status_mini():
        import streamlit as _st
        with _st.expander("💡 Running in Demo Mode", expanded=False):
            _st.info("Set KALI_API_URL in Streamlit Secrets to enable live tools.")
        return False

render_kali_status_mini()
kali_online = True  # run_tool() handles offline gracefully



try:
    from kali_connector import render_kali_status_banner, run_tool, render_tool_result
    render_kali_status_mini()
except Exception:
    kali_online = False
    st.info("ℹ️ Kali backend not connected — Demo Mode active")

# ── Target config ─────────────────────────────────────────────────────────────
with st.expander("⚙️ SIP / IMS Target Parameters", expanded=False):
    col1, col2, col3 = st.columns(3)
    with col1:
        sip_target = st.text_input("SIP Server / Network", value="192.168.1.0/24")
        sip_port   = st.number_input("SIP Port", value=5060, min_value=1, max_value=65535)
    with col2:
        ext_start  = st.number_input("Extension Range Start", value=100)
        ext_end    = st.number_input("Extension Range End", value=200)
    with col3:
        sip_proto  = st.selectbox("Transport", ["UDP", "TCP", "TLS"])
        user_agent = st.text_input("Spoofed User-Agent", value="TelSec-Audit/1.0")

tabs = st.tabs([
    "🗺️ SIP Discovery (svmap)",
    "🔢 Extension Enum (svwar)",
    "📩 OPTIONS Probe",
    "🏢 Kamailio / IMS Test",
])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: svmap
# ─────────────────────────────────────────────────────────────────────────────
with tabs[0]:
    with st.expander("📘 Auditor Manual — SIP Device Discovery (svmap)", expanded=False):
        st.markdown("""
**Objective:** Enumerate SIP-capable devices and PBX/IMS systems on the target network segment.

**Tool:** SIPVicious `svmap` — sends SIP OPTIONS to discover responding devices.

**What it finds:**
- SIP phones, PBX systems, SBC/IMS nodes
- Server version banners (information disclosure)
- Open SIP ports and unsecured services

**Expected Outcome:**
- ✅ PASS: No unauthenticated SIP devices on production subnets; TLS enforced
- ❌ FAIL: Plaintext SIP devices discoverable from external scope; version disclosed

**CVSS 5.3** | CWE-200 | GSMA PRD IR.92

```mermaid
sequenceDiagram
    participant Scanner as TelSec (svmap)
    participant Net as Network Segment
    participant PBX as SIP PBX/IMS
    Scanner->>Net: SIP OPTIONS (broadcast)
    PBX-->>Scanner: 200 OK [Server: Asterisk/Kamailio]
    Note over Scanner,PBX: Server header = information disclosure
```
""")

    st.markdown("### 🗺️ SIP Network Discovery")
    col1, col2 = st.columns([3, 1])
    with col1:
        svmap_target = st.text_input("Target subnet / IP", value=sip_target, key="svmap_t")
    with col2:
        if st.button("▶ Run svmap", use_container_width=True, key="svmap_run"):
            with st.spinner("Scanning for SIP devices..."):
                result = run_tool("svmap", {"target": svmap_target})
                render_tool_result(result, "svmap")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: svwar
# ─────────────────────────────────────────────────────────────────────────────
with tabs[1]:
    with st.expander("📘 Auditor Manual — Extension Enumeration (svwar)", expanded=False):
        st.markdown("""
**Objective:** Discover valid SIP extensions and identify those without authentication requirements.

**Tool:** SIPVicious `svwar` — sends REGISTER/OPTIONS per extension to probe existence.

**What it finds:**
- Valid extension numbers
- Extensions that respond without credentials (auth bypass)
- Extensions using deprecated digest auth

**Expected Outcome:**
- ✅ PASS: All extensions require strong authentication; no open extensions
- ❌ FAIL: Open/unauthenticated extensions found — toll fraud risk

**CVSS 6.5** | CWE-306 | 3GPP TS 24.229

```mermaid
sequenceDiagram
    participant Atk as TelSec (svwar)
    participant PBX
    Atk->>PBX: REGISTER sip:100@pbx
    PBX-->>Atk: 401 Unauthorized (extension exists)
    Atk->>PBX: REGISTER sip:102@pbx
    PBX-->>Atk: 200 OK (no auth required!)
    Note over Atk,PBX: Extension 102 = FAIL: toll fraud risk
```
""")

    st.markdown("### 🔢 SIP Extension Enumeration")
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        svwar_target = st.text_input("SIP Server IP", value=sip_target.split("/")[0], key="svwar_t")
    with col2:
        ext_r = f"{int(ext_start)}-{int(ext_end)}"
        st.text_input("Extension Range", value=ext_r, key="svwar_range", disabled=True)
    with col3:
        if st.button("▶ Run svwar", use_container_width=True, key="svwar_run"):
            with st.spinner("Enumerating extensions..."):
                result = run_tool("svwar", {"target": svwar_target, "ext_range": ext_r})
                render_tool_result(result, "svwar")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: OPTIONS Probe
# ─────────────────────────────────────────────────────────────────────────────
with tabs[2]:
    with st.expander("📘 Auditor Manual — SIP OPTIONS Probe", expanded=False):
        st.markdown("""
**Objective:** Send a single SIP OPTIONS request to verify server response and check for:
- Unauthenticated response (should require auth in production)
- Version banner disclosure in `Server:` header
- Allowed methods in `Allow:` header (surface area assessment)

**Expected Outcome:**
- ✅ PASS: OPTIONS requires authorization or returns 403/407
- ❌ FAIL: 200 OK returned without credentials — enumeration + info leak

**CVSS 5.3** | RFC 3261 §11 | 3GPP IR.92
""")

    st.markdown("### 📩 SIP OPTIONS Probe")
    col1, col2 = st.columns([3, 1])
    with col1:
        opts_target = st.text_input("SIP Server", value=sip_target.split("/")[0], key="opts_t")
    with col2:
        if st.button("▶ Send OPTIONS", use_container_width=True, key="opts_run"):
            with st.spinner("Sending SIP OPTIONS..."):
                result = run_tool("kamailio_test", {"target": opts_target})
                render_tool_result(result, "SIP OPTIONS")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4: Kamailio / IMS
# ─────────────────────────────────────────────────────────────────────────────
with tabs[3]:
    with st.expander("📘 Auditor Manual — Kamailio / IMS Security Assessment", expanded=False):
        st.markdown("""
**Objective:** Perform targeted functional security tests against a Kamailio SIP proxy or IMS core.

**Test Areas:**
| Test | Description | Standard |
|---|---|---|
| REGISTER flood | Rate limiting on REGISTER storms | TS 24.229 |
| INVITE without auth | Test if calls can be placed unauthenticated | RFC 3261 |
| P-Asserted-Identity spoofing | Inject fake PAI header for caller-ID spoofing | RFC 3325 |
| Via header manipulation | RTP path injection via malformed Via | RFC 3261 §18 |
| Record-Route bypass | Test SBC/IMS policy enforcement | 3GPP IR.92 |

**Expected Outcome:**
- ✅ PASS: All unauthenticated requests rejected (407/403); PAI validated by SBC
- ❌ FAIL: Open INVITE, spoofed PAI accepted, or flood not rate-limited

**CVSS Range: 5.3–8.6** | GSMA PRD IR.92 / IR.94
""")

    st.markdown("### 🏢 Kamailio / IMS Probe")
    col1, col2 = st.columns([2, 1])
    with col1:
        ims_target = st.text_input("IMS / Kamailio IP", value=sip_target.split("/")[0], key="ims_t")
        ims_test = st.selectbox("Test Type", [
            "SIP OPTIONS probe",
            "REGISTER flood (50 requests)",
            "INVITE without credentials",
            "P-Asserted-Identity spoof",
        ], key="ims_test")
    with col2:
        if st.button("▶ Run IMS Test", use_container_width=True, key="ims_run"):
            with st.spinner("Running IMS security test..."):
                result = run_tool("kamailio_test", {"target": ims_target, "test_type": ims_test})
                render_tool_result(result, f"IMS: {ims_test}")
