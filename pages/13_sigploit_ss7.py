"""
TelSec — SigPloit & SS7 Attack Suite (Page 13)
================================================
Covers: Location Tracking, SMS Interception, Call Interception, DoS Flood, Subscriber Enumeration
"""
import streamlit as st

# ── Page hero ──────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;600;700&display=swap');
</style>
<div class="page-hero">
  <div class="page-hero-icon">📡</div>
  <div>
    <div class="page-hero-title">SigPloit — SS7 Attack Suite</div>
    <div class="page-hero-sub">MAP/CAP location tracking · SMS interception · Call rerouting · DoS · Subscriber enumeration · GSMA FS.11 aligned</div>
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

# ── Parameters ────────────────────────────────────────────────────────────────
with st.expander("⚙️ SS7 Connection Parameters", expanded=False):
    col1, col2, col3 = st.columns(3)
    with col1:
        gt   = st.text_input("Source GT (Global Title)", value="491770000000", help="Your authorized test GT")
        opc  = st.text_input("OPC (Origin Point Code)", value="0001")
    with col2:
        msisdn = st.text_input("Target MSISDN", value="491771234567", help="Subscriber under test")
        dpc    = st.text_input("DPC (Destination Point Code)", value="0002")
    with col3:
        stp_ip = st.text_input("SS7/STP IP", value="192.168.1.100")
        sctp_port = st.number_input("SCTP Port", value=2905, min_value=1, max_value=65535)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tabs = st.tabs([
    "📍 Location Tracking",
    "✉️ SMS Interception",
    "📞 Call Interception",
    "💥 DoS Flood",
    "🔍 Subscriber Enum",
])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: LOCATION TRACKING
# ─────────────────────────────────────────────────────────────────────────────
with tabs[0]:
    with st.expander("📘 Auditor Manual — MAP ATI Location Tracking", expanded=False):
        st.markdown("""
**Objective:** Verify that the HLR/VLR rejects MAP Any-Time-Interrogation (ATI) requests from
unauthorized external Global Titles.

**Standard Tests:**
- GSMA FS.11 Category 2 — Subscriber Data Disclosure
- 3GPP TS 29.002 §7.3.3 (MAP_ANY_TIME_INTERROGATION)

**Methodology:**
1. Craft MAP ATI PDU with spoofed Calling GT
2. Route via SCTP/M3UA to target STP/HLR
3. Check if ATI Response reveals: IMSI, VLR Address, Cell-ID, location area

**Expected Outcome:**
- ✅ PASS: HLR rejects with MAP error `unexpectedDataValue` or firewall blocks at SCCP
- ❌ FAIL: ATI Response received with subscriber location data

**CVSS 8.2** | CWE-306 | GSMA FS.11 Cat-2

```mermaid
sequenceDiagram
    participant Atk as Attacker (Test GT)
    participant STP as SS7 STP/Firewall
    participant HLR as HLR/VLR
    Atk->>STP: MAP ATI [MSISDN, RequestedInfo=LocationInfo]
    STP-->>Atk: (Ideally) SCCP Error / MAP Reject
    STP->>HLR: (If no firewall) MAP ATI forwarded
    HLR-->>Atk: ATI Response [IMSI, VLR, CellId, LAC]
    Note over Atk,HLR: FAIL if response received
```
""")

    st.markdown("### 📍 MAP ATI — Location Disclosure Test")
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("▶ Run ATI Test", use_container_width=True, key="ati_run"):
            with st.spinner("Sending MAP ATI via SigPloit..."):
                result = run_tool("sigploit", {"mode": "location", "gt": gt, "msisdn": msisdn, "extra": f"{opc},{dpc}"}) if kali_online else run_tool("sigploit", {"mode": "location", "gt": gt, "msisdn": msisdn})
                render_tool_result(result, "SigPloit ATI")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: SMS INTERCEPTION
# ─────────────────────────────────────────────────────────────────────────────
with tabs[1]:
    with st.expander("📘 Auditor Manual — MAP SRI-SM / mt-ForwardSM Interception", expanded=False):
        st.markdown("""
**Objective:** Verify that SMSC and HLR cannot be manipulated to deliver SMS to an attacker-controlled MSC.

**Standard Tests:**
- GSMA FS.11 Category 3 — Call/SMS Interception
- 3GPP TS 29.002 §7.3.2 (MAP_SEND_ROUTING_INFO_FOR_SM)

**Methodology:**
1. Send MAP SRI-SM to SMSC requesting routing info for target MSISDN
2. Receive IMSI + MSC address from SRI response
3. Send mt-ForwardSM specifying attacker-controlled MSC
4. If mt-ForwardSM succeeds → SMS intercepted

**Expected Outcome:**
- ✅ PASS: SMS-HE filtering prevents SRI-SM from external unauthorized GT
- ❌ FAIL: SMS delivered to attacker MSC — OTP/2FA intercept possible

**CVSS 8.8** | GSMA FS.11 Cat-3

```mermaid
sequenceDiagram
    participant Atk as Attacker
    participant SMSC
    participant HLR
    participant FakeMSC as Attacker MSC
    Atk->>SMSC: SRI_SM(MSISDN)
    SMSC->>HLR: SRI_SM(MSISDN)
    HLR-->>SMSC: IMSI + Real MSC addr
    SMSC-->>Atk: IMSI + MSC addr
    Atk->>FakeMSC: mt-ForwardSM → redirect SMS here
    Note over Atk,FakeMSC: FAIL: SMS (incl. OTPs) intercepted
```
""")

    st.markdown("### ✉️ MAP SRI-SM — SMS Interception Test")
    if st.button("▶ Run SMS Interception Test", key="sms_run"):
        with st.spinner("Executing SRI-SM + mt-ForwardSM sequence..."):
            result = run_tool("sigploit", {"mode": "sms", "gt": gt, "msisdn": msisdn})
            render_tool_result(result, "SigPloit SMS")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: CALL INTERCEPTION
# ─────────────────────────────────────────────────────────────────────────────
with tabs[2]:
    with st.expander("📘 Auditor Manual — MAP PSI / IAM Call Rerouting", expanded=False):
        st.markdown("""
**Objective:** Verify that voice call routing cannot be manipulated via MAP Provide Subscriber Info (PSI).

**Standard Tests:**
- GSMA FS.11 Category 3 — Call Interception
- 3GPP TS 29.002 §7.3.14 (MAP_PROVIDE_SUBSCRIBER_INFO)

**Methodology:**
1. Send MAP PSI to retrieve subscriber's serving MSC/VLR
2. Inject IAM (Initial Address Message) to the serving MSC with attacker as called party
3. Monitor if call setup proceeds to attacker-controlled node

**Expected Outcome:**
- ✅ PASS: MAP PSI rejected by SS7 firewall or MSC
- ❌ FAIL: PSI response + call diverted — full call interception possible

**CVSS 9.1** | GSMA FS.11 Cat-3
""")

    st.markdown("### 📞 MAP PSI — Call Rerouting Test")
    if st.button("▶ Run Call Intercept Test", key="call_run"):
        with st.spinner("Executing MAP PSI + IAM injection..."):
            result = run_tool("sigploit", {"mode": "call", "gt": gt, "msisdn": msisdn})
            render_tool_result(result, "SigPloit Call")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4: DoS FLOOD
# ─────────────────────────────────────────────────────────────────────────────
with tabs[3]:
    with st.expander("📘 Auditor Manual — MAP SRI-SM DoS Flood", expanded=False):
        st.markdown("""
**Objective:** Verify HLR/VLR implements rate limiting against MAP flood attacks.

**Standard Tests:**
- GSMA FS.11 Category 4 — Fraud and DoS
- 3GPP TS 29.002, FS.19

**Methodology:**
1. Send N × MAP SRI-SM requests in rapid succession to the HLR
2. Monitor HLR response times and error rates
3. Check if Cancel Location is triggered (locking subscriber out)

**Expected Outcome:**
- ✅ PASS: Rate-limiting blocks after N requests, no Cancel Location
- ❌ FAIL: HLR processes all queries, subscriber service impacted

**CVSS 7.5** | GSMA FS.11 Cat-4
""")

    col1, col2 = st.columns([2, 1])
    with col1:
        flood_count = st.slider("Number of MAP queries to send", 10, 200, 50)
    with col2:
        if st.button("▶ Run DoS Flood Test", key="dos_run"):
            with st.spinner(f"Sending {flood_count} MAP queries..."):
                result = run_tool("sigploit", {"mode": "dos", "gt": gt, "msisdn": msisdn, "extra": str(flood_count)})
                render_tool_result(result, "SigPloit DoS")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 5: SUBSCRIBER ENUM (Scapy SS7)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[4]:
    with st.expander("📘 Auditor Manual — Scapy MAP Packet Crafting", expanded=False):
        st.markdown("""
**Objective:** Craft raw SS7/MAP PDUs with Scapy to test specific protocol behaviours.

**Use Cases:**
- Test MAP ATI, SRI, PSI, CLR with arbitrary parameters
- Verify SCCP Calling-GT category filtering
- Build custom test harnesses from protocol primitives

**Operations available:**
| Operation | Description |
|---|---|
| ATI | Any-Time-Interrogation (location) |
| SRI | Send Routing Info (SMS routing) |
| PSI | Provide Subscriber Info (call routing) |
| CLR | Cancel Location (subscriber lockout) |
""")

    col1, col2 = st.columns(2)
    with col1:
        scapy_op = st.selectbox("MAP Operation", ["ATI", "SRI", "PSI", "CLR"], key="scapy_op")
    with col2:
        if st.button("▶ Craft & Send PDU", key="scapy_run"):
            with st.spinner(f"Crafting MAP {scapy_op} packet with Scapy..."):
                result = run_tool("scapy-ss7", {"gt": gt, "msisdn": msisdn, "operation": scapy_op})
                render_tool_result(result, f"Scapy MAP {scapy_op}")
