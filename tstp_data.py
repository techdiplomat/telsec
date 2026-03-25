"""
TelSec - Test Schedule & Test Procedure (TSTP)
================================================
Structured TSTP for all audit tests across 2G/3G/4G/5G.

Each entry defines:
  what        - Test objective
  how         - Step-by-step procedure
  when        - Pre-conditions / timing
  where       - Network element / interface under test
  tools       - Tools required
  pass_criteria - What constitutes a PASS
  fail_criteria - What constitutes a FAIL
  standard    - GSMA / 3GPP reference
  duration    - Estimated test duration
"""

from __future__ import annotations
from typing import Dict, Any

TSTP: Dict[str, Dict[str, Any]] = {

    # ================================================================
    # 2G / GSM
    # ================================================================

    "GSM-001": {
        "title": "GSM Cell Discovery & BTS Inventory",
        "what": (
            "Scan the GSM 900/1800 MHz spectrum to enumerate all active Base Transceiver "
            "Stations (BTSes) visible from the test location. Record ARFCN, MCC, MNC, LAC, "
            "and Cell-ID for each discovered cell and verify against the authorized cell inventory."
        ),
        "how": [
            "1. Connect RTL-SDR or HackRF to test laptop with gr-gsm installed.",
            "2. Run: kal -s GSM900  and  kal -s GSM1800  to enumerate ARFCNs.",
            "3. For each ARFCN found, run: grgsm_scanner --arfcn <N> to extract BCCH system information.",
            "4. Record PLMN (MCC+MNC), LAC, Cell-ID from SI Type 1/3 messages.",
            "5. Cross-reference discovered cells against authorized cell list in config/targets.yaml.",
            "6. Flag any cell with unknown MCC/MNC or Cell-ID not in the authorized list.",
        ],
        "when": (
            "First step in every 2G audit engagement. Run before any active tests. "
            "Perform during both business hours and off-hours to detect temporary/rogue cells."
        ),
        "where": "GSM BCCH (Broadcast Control Channel) — passive RF monitoring. No network connection required.",
        "tools": ["kalibrate-rtl (kal)", "gr-gsm (grgsm_scanner)", "RTL-SDR / HackRF"],
        "pass_criteria": (
            "All discovered cells match the authorized cell inventory. "
            "No unknown MCC/MNC or rogue Cell-IDs detected."
        ),
        "fail_criteria": (
            "Any discovered cell with MCC/MNC or Cell-ID not in the authorized list. "
            "Presence of cells with identical PLMN but different LAC/Cell-ID than expected (rogue BTS indicator)."
        ),
        "standard": "GSMA FS.11 | 3GPP TS 45.005 | 3GPP TS 44.018 (SI messages)",
        "severity_if_fail": "HIGH",
        "duration": "15–60 minutes depending on band and area",
        "environment": "Passive RF — no target network connection needed",
    },

    "GSM-002": {
        "title": "A5/0 Null Cipher Detection",
        "what": (
            "Verify that the network does NOT negotiate A5/0 (null cipher — no encryption) "
            "for voice and data channels. A5/0 means all SDCCH and TCH traffic is transmitted "
            "in cleartext, interceptable by any passive radio listener."
        ),
        "how": [
            "1. Use grgsm_livemon or OpenBTS to monitor SDCCH on target ARFCN.",
            "2. Initiate a test call or Location Update from an authorized test SIM.",
            "3. Capture the Ciphering Mode Command message on SDCCH.",
            "4. Inspect the 'algorithm identifier' field in the message.",
            "   - A5/1 = byte 0x01 (acceptable minimum)",
            "   - A5/3 = byte 0x03 (preferred)",
            "   - A5/0 = byte 0x00 (FAIL — no encryption)",
            "5. Record the ARFCN, timestamp, and cipher algorithm negotiated.",
        ],
        "when": (
            "After cell discovery (GSM-001). Run during active authorized test window. "
            "Test SIM must be provisioned on the target network."
        ),
        "where": "GSM SDCCH (Stand-alone Dedicated Control Channel) — Layer 3 MM/RR messages",
        "tools": ["gr-gsm (grgsm_livemon)", "Wireshark with GSM dissector", "Test SIM + phone"],
        "pass_criteria": (
            "Ciphering Mode Command contains A5/1 or A5/3. "
            "No A5/0 negotiation observed for any test call or registration."
        ),
        "fail_criteria": (
            "Ciphering Mode Command contains A5/0 algorithm identifier (0x00). "
            "Network accepts or initiates unencrypted SDCCH/TCH sessions."
        ),
        "standard": "GSMA FS.11 Cat.1 | 3GPP TS 33.102 §6.1 | ETSI TS 143 020",
        "severity_if_fail": "CRITICAL",
        "duration": "10–20 minutes",
        "environment": "Active — test SIM on target network required",
        "cvss": "9.8 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },

    "GSM-003": {
        "title": "IMSI Exposure in Identity Response",
        "what": (
            "Check whether the network allows the Mobile Station's IMSI to be transmitted "
            "in cleartext over the air in Identity Response messages. Properly configured "
            "networks should assign TMSI on first attach and use TMSI for all subsequent IDs."
        ),
        "how": [
            "1. Using grgsm_livemon, monitor SDCCH on target ARFCN.",
            "2. Power-cycle the test mobile (force a fresh Location Update / IMSI Attach).",
            "3. Capture all Layer 3 MM messages during initial attach procedure.",
            "4. Check if IDENTITY REQUEST is sent by network requesting IMSI (ID Type = 0x01).",
            "5. If IDENTITY REQUEST observed: check subsequent IDENTITY RESPONSE for cleartext IMSI.",
            "6. Also verify: after successful attach, does Location Update Accept include TMSI?",
            "7. If no TMSI assigned → IMSI will be retransmitted at next attach (FAIL).",
        ],
        "when": (
            "After A5/0 test. Use a test SIM never previously registered on this network "
            "to force a fresh IMSI attach. Test in areas with known poor TMSI management."
        ),
        "where": "GSM SDCCH — Layer 3 MM (Mobility Management) sublayer",
        "tools": ["gr-gsm (grgsm_livemon)", "Wireshark", "Test SIM (fresh/not registered)"],
        "pass_criteria": (
            "Network assigns TMSI in Location Update Accept. "
            "IDENTITY REQUEST (if sent) uses IMSI only on first attach, never on repeat. "
            "All subsequent Location Updates use TMSI, not IMSI."
        ),
        "fail_criteria": (
            "IMSI sent in cleartext on SDCCH in IDENTITY RESPONSE. "
            "No TMSI assigned by VLR after initial registration. "
            "IMSI retransmitted on repeat Location Updates."
        ),
        "standard": "GSMA FS.11 Cat.1 | 3GPP TS 33.102 §6.2 | 3GPP TS 24.008 §9.2.15",
        "severity_if_fail": "HIGH",
        "duration": "15–30 minutes",
        "environment": "Active — fresh test SIM required",
        "cvss": "7.5 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    },

    "GSM-004": {
        "title": "TMSI Re-Identification Attack",
        "what": (
            "Determine if a subscriber's IMSI can be correlated to their TMSI by forcing "
            "IMSI paging requests. An attacker with a fake BTS can send IMSI-specific paging "
            "and observe SDCCH responses to map IMSI↔TMSI↔physical location."
        ),
        "how": [
            "1. From prior GSM-001/003 captures, note the TMSI of the authorized test subscriber.",
            "2. Configure a test IMSI Paging message using OpenBTS or a modified BTS.",
            "3. Broadcast paging for the test IMSI on CCCH (Paging Channel).",
            "4. Observe whether the test UE responds on SDCCH (confirming IMSI→TMSI link).",
            "5. Record any Channel Request messages from the UE on RACH.",
            "6. Cross-correlate RACH timing with TMSI assigned in previous registration.",
        ],
        "when": "After GSM-003 (TMSI must be known). Requires authorized test SIM.",
        "where": "GSM CCCH (Common Control Channel) — Paging Channel (PCH) and RACH",
        "tools": ["OpenBTS or osmo-nitb", "gr-gsm", "Test SIM"],
        "pass_criteria": (
            "UE does not respond to IMSI paging requests after TMSI has been assigned. "
            "Network uses TMSI-only paging after initial registration."
        ),
        "fail_criteria": (
            "UE responds to IMSI paging, confirming IMSI↔TMSI↔physical location correlation. "
            "Network paginates using IMSI even when TMSI is available."
        ),
        "standard": "GSMA FS.11 Cat.1 | 3GPP TS 24.008 §9.2.19 | 3GPP TS 44.018",
        "severity_if_fail": "HIGH",
        "duration": "20–40 minutes",
        "environment": "Active — requires controlled BTS environment",
        "cvss": "7.5 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    },

    "GSM-005": {
        "title": "Rogue BTS Detection",
        "what": (
            "Detect the presence of any unauthorized BTS (IMSI catcher / fake base station) "
            "operating in or near the target coverage area by analyzing BCCH parameters, "
            "signal anomalies, and LAC inconsistencies."
        ),
        "how": [
            "1. Build a baseline BCCH database from step GSM-001 (authorized cells).",
            "2. Continuously scan all GSM900/1800 ARFCNs at 5-minute intervals for 2+ hours.",
            "3. Flag any new Cell-ID appearing that wasn't in baseline.",
            "4. For each flagged cell: compare C1/C2 (cell selection) parameters — rogues often have abnormally high power.",
            "5. Check LAC: rogues frequently use a LAC not matching surrounding legitimate cells, or LAC=0.",
            "6. Analyze BA-list (neighbour ARFCNs) — rogues often broadcast empty or minimal BA-lists.",
            "7. Monitor for unusual SILENT PERIOD or missing neighbor cell announcements.",
        ],
        "when": (
            "Passive monitoring throughout the audit. Run 24/7 if possible. "
            "Critical during high-security events or VIP protection assessments."
        ),
        "where": "GSM BCCH — passive RF spectrum analysis",
        "tools": ["gr-gsm (grgsm_scanner)", "kalibrate-rtl", "RTL-SDR + omni antenna"],
        "pass_criteria": (
            "No new Cell-IDs appear outside the authorized cell list. "
            "All observed LAC values match the operator's known network plan. "
            "BA-lists are consistent with expected neighbor cells."
        ),
        "fail_criteria": (
            "Unknown Cell-ID or LAC detected in coverage area. "
            "Cell with identical PLMN but anomalously high signal strength vs surroundings. "
            "Empty BA-list or abnormal C2 values (rogue BTS trying to capture MSes)."
        ),
        "standard": "GSMA FS.11 Cat.4 | 3GPP TS 45.008 (cell selection) | IMSI Catcher detection research",
        "severity_if_fail": "CRITICAL",
        "duration": "Continuous passive monitoring (min 2 hours)",
        "environment": "Passive — no network connection needed",
        "cvss": "9.3 (AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)",
    },

    "GSM-006": {
        "title": "Authentication Vector Replay Attack",
        "what": (
            "Verify that the network prevents authentication replay attacks by checking "
            "whether old RAND/SRES authentication vectors can be re-used to authenticate "
            "a cloned SIM against the network."
        ),
        "how": [
            "1. From a legitimate authentication exchange (GSM-003 capture), extract RAND challenge.",
            "2. Record the SRES response from the authorized test SIM.",
            "3. Attempt to replay the same RAND/SRES pair in a new Authentication Response.",
            "4. Observe whether the network accepts the replayed authentication tuple.",
            "5. Additionally check: does the HLR issue each RAND only once (quintuplet reuse detection)?",
            "6. Monitor VLR for signs of authentication vector exhaustion (SRI-SM response changes).",
        ],
        "when": (
            "After GSM-003 (authentication exchange captured). "
            "Requires ability to send crafted Layer 3 messages (OpenBTS or SIM toolkit)."
        ),
        "where": "GSM MM Authentication sublayer — SDCCH / VLR-HLR Gr interface",
        "tools": ["gr-gsm", "OpenBTS", "SIM card programmer (for SRES injection)", "Wireshark"],
        "pass_criteria": (
            "Network rejects replayed RAND/SRES pairs. "
            "Each RAND is issued only once; VLR invalidates used authentication tuples. "
            "Authentication failure (cause 0x06) returned on replay attempt."
        ),
        "fail_criteria": (
            "Network accepts replayed RAND/SRES authentication tuple. "
            "VLR reuses authentication vectors previously issued to legitimate MS. "
            "Clone SIM successfully attaches using captured authentication data."
        ),
        "standard": "GSMA FS.11 | 3GPP TS 33.102 §6.3 | 3GPP TS 24.008 §9.2.10",
        "severity_if_fail": "CRITICAL",
        "duration": "30–60 minutes",
        "environment": "Active — full control of test SIM and monitoring setup required",
        "cvss": "9.8 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },


    # ================================================================
    # 5G / NR
    # ================================================================

    "NR-001": {
        "title": "5G NR Cell Discovery & AMF Port Scan",
        "what": "Enumerate 5G NR cells (gNBs) in the target spectrum and verify AMF NGAP/SBA port exposure is restricted to authorized gNBs.",
        "how": [
            "1. Run: python3 -m nr_scan --band n78 --arfcn-start 520000 --arfcn-end 522000",
            "2. For each gNB found, record NR-ARFCN, PCI, SS-RSRP, MCC/MNC, TAC.",
            "3. Run nmap -sU -p 38412 <AMF_IP> to check NGAP exposure.",
            "4. Run nmap -p 29518,29502,29503 <SBA_IP> to check NF API ports.",
            "5. Verify that AMF port 38412 only responds to packets sourced from authorized gNB IPs.",
            "6. Cross-reference all discovered gNBs against the authorized cell database.",
        ],
        "when": "First step in every 5G audit. Run before any active SBA/NAS tests.",
        "where": "NR PBCH/SSB (Primary Synchronisation Signal Block) — passive RF + IP layer",
        "tools": ["srsRAN 5G", "nmap", "UERANSIM", "Wireshark/tshark"],
        "pass_criteria": "All gNBs match authorized list. AMF NGAP port not reachable from non-authorized IPs.",
        "fail_criteria": "Unknown gNB found. AMF port 38412 accessible from arbitrary internet hosts.",
        "standard": "GSMA FS.40 | 3GPP TS 38.413 (NGAP) | 3GPP TS 38.101",
        "severity_if_fail": "HIGH",
        "duration": "20–45 minutes",
        "environment": "Passive RF + IP — no UE auth required for port scan",
    },

    "NR-002": {
        "title": "SUCI/SUPI Privacy — Null Protection Scheme Detection",
        "what": "Verify UE transmits SUCI using ECIES (Profile A or B) and NOT Protection Scheme 0 (null), which exposes the IMSI/MSIN in cleartext in RRC Registration Requests.",
        "how": [
            "1. Using UERANSIM or a test UE, initiate a 5G NR registration to the target AMF.",
            "2. Capture NAS Registration Request using tshark: tshark -i lo -Y 'nas-5gs'",
            "3. Decode the SUCI IE: check Scheme-ID field.",
            "   - Scheme-ID 0 = NULL (FAIL — MSIN in cleartext)",
            "   - Scheme-ID 1 = ECIES Profile A (PASS)",
            "   - Scheme-ID 2 = ECIES Profile B (PASS)",
            "4. Also verify: AMF rejects SUCI with Scheme-ID 0 for non-emergency calls.",
            "5. Document the Protection Scheme Identifier and any MSIN exposure.",
        ],
        "when": "After NR-001. Requires test UE registered on target 5G network.",
        "where": "5G NR NAS layer — Registration Request → SUCI IE (TS 24.501 §9.11.3.4)",
        "tools": ["UERANSIM", "tshark", "Wireshark 5G-NAS dissector"],
        "pass_criteria": "SUCI uses Scheme-ID 1 or 2 (ECIES). MSIN not visible in cleartext. AMF rejects Scheme-ID 0.",
        "fail_criteria": "SUCI contains Scheme-ID 0 (null). MSIN transmitted in cleartext. AMF accepts null-scheme SUCI.",
        "standard": "GSMA FS.40-5G1 | 3GPP TS 33.501 §6.12.2 | 3GPP TS 24.501 §9.11.3.4",
        "severity_if_fail": "CRITICAL",
        "duration": "15–30 minutes",
        "environment": "Active — test UE registered on target 5GC",
        "cvss": "8.7 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    },

    "NR-003": {
        "title": "NAS Security Algorithm Downgrade (5G-EA0/5G-IA0)",
        "what": "Verify the AMF enforces minimum NAS ciphering (5G-EA1+) and integrity (5G-IA1+). A misconfigured AMF may accept 5G-EA0 (null cipher) and 5G-IA0 (null integrity), exposing all NAS traffic.",
        "how": [
            "1. Configure UERANSIM UE to advertise 5G-EA0/5G-IA0 as highest-priority algorithms.",
            "2. Initiate NAS Registration. Capture the Security Mode Command from AMF.",
            "3. Inspect the 'Selected NAS security algorithms' IE:",
            "   - Ciphering: 5G-EA0 (0x00) = FAIL",
            "   - Integrity: 5G-IA0 (0x00) = FAIL",
            "4. If AMF sends EA0/IA0: verify UE accepts it (double FAIL).",
            "5. If UE is vulnerable: subsequent NAS messages are interceptable/modifiable.",
            "6. Document: AMF config, algorithm selection log, captured NAS traffic.",
        ],
        "when": "After NR-002. Active test with UERANSIM connected to target AMF.",
        "where": "5G NAS layer — Security Mode Command (AMF→UE) on N1 interface",
        "tools": ["UERANSIM", "tshark", "Wireshark", "Open5GS (reference AMF)"],
        "pass_criteria": "AMF selects 5G-EA1 or higher AND 5G-IA1 or higher. AMF never sends EA0 or IA0.",
        "fail_criteria": "AMF Security Mode Command contains 5G-EA0 or 5G-IA0. UE accepts null algorithms.",
        "standard": "GSMA FS.40-5G1 | 3GPP TS 33.501 §6.7.3 | CVE-2019-25104",
        "severity_if_fail": "CRITICAL",
        "duration": "20–30 minutes",
        "environment": "Active — UERANSIM connected to target 5GC",
        "cvss": "9.3 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    },

    "NR-004": {
        "title": "AMF Registration Spam / DoS",
        "what": "Verify the AMF implements rate limiting on Registration Requests to prevent resource exhaustion from unauthenticated UE floods.",
        "how": [
            "1. Using UERANSIM multi-UE mode, configure 500 simultaneous UE instances with random SUPIs.",
            "2. Launch registration flood: ueransim-gnb --ue-count 500 --no-auth",
            "3. Monitor AMF CPU/RAM using: docker stats or top on the 5GC host.",
            "4. Measure: registration success rate, AMF response latency, memory growth.",
            "5. Check if AMF applies per-gNB rate limiting (NGAP overload indicator).",
            "6. Verify AMF sends NGAP Overload Start message before impact on legitimate UEs.",
        ],
        "when": "After baseline performance is established. Run in isolated test window — warn operator first.",
        "where": "5G AMF — NGAP N2 interface (gNB→AMF) and NAS N1 Registration procedure",
        "tools": ["UERANSIM (multi-UE mode)", "nmap", "htop / docker stats"],
        "pass_criteria": "AMF rate-limits registrations. NGAP Overload Start sent at threshold. No crash or service degradation.",
        "fail_criteria": "AMF crashes or response latency >5x baseline. No rate limiting. Legitimate UEs rejected due to resource exhaustion.",
        "standard": "3GPP TS 23.501 §5.19 (Overload Control) | 3GPP TS 38.413 §8.7",
        "severity_if_fail": "HIGH",
        "duration": "30–60 minutes",
        "environment": "Active — coordinate with operator before running",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    "NR-005": {
        "title": "AUSF/UDM SBA API Authentication Check",
        "what": "Verify that 5G SBA APIs (Nudm, Nausf, Nsmf, etc.) require a valid OAuth2 Bearer token from NRF before returning subscriber data. Unauthenticated API access is a critical 5GC vulnerability.",
        "how": [
            "1. Identify UDM/AUSF service URLs from NRF discovery (NR-006 or config).",
            "2. Send unauthenticated HTTP/2 GET to: /nudm-uecm/v1/imsi-<IMSI>/registrations",
            "   Using: httpx --http2 http://<UDM_IP>:29503/nudm-uecm/v1/imsi-404300000000001/registrations",
            "3. Send unauthenticated GET to: /nausf-auth/v1/ue-authentications",
            "4. If HTTP 200: FAIL — subscriber data returned without auth.",
            "5. If HTTP 401 Unauthorized: PASS — OAuth2 enforced.",
            "6. Also test with expired/forged Bearer token to verify token validation.",
        ],
        "when": "After NR-001 (target SBA IPs known). Can be run without a registered UE.",
        "where": "5G SBA — Nudm-UECM (port 29503), Nausf (29509), Nsmf (29502) REST APIs over HTTP/2",
        "tools": ["httpx (HTTP/2 client)", "curl --http2", "Postman", "TelSec SBA prober"],
        "pass_criteria": "All SBA endpoints return HTTP 401 without valid NRF-issued Bearer token.",
        "fail_criteria": "Any SBA endpoint returns HTTP 200 without authentication. Subscriber data exposed.",
        "standard": "GSMA FS.40-5G1 | 3GPP TS 33.501 §13.3 | 3GPP TS 29.510 (NRF OAuth2)",
        "severity_if_fail": "CRITICAL",
        "duration": "15–30 minutes",
        "environment": "Active — network access to SBA interfaces required",
        "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },

    "NR-006": {
        "title": "NRF Service Discovery Abuse",
        "what": "Verify NRF restricts the NF instance list to authenticated NFs. An open NRF allows any attacker to enumerate the entire 5GC topology (AMF IPs, SMF ports, UDM URLs).",
        "how": [
            "1. Send unauthenticated GET: /nnrf-nfm/v1/nf-instances?nf-type=AMF",
            "   Using: httpx --http2 http://<NRF_IP>:7777/nnrf-nfm/v1/nf-instances",
            "2. Inspect response: if JSON list of NF instances returned → FAIL.",
            "3. Also test: /nnrf-disc/v1/nf-instances?target-nf-type=UDM (discovery endpoint).",
            "4. Check if NRF applies mTLS on all NF registration and discovery calls.",
            "5. Verify NRF access tokens have correct scope and expiry.",
        ],
        "when": "Immediately after NR-001. NRF IP must be known (often co-located with AMF).",
        "where": "5G NRF — Nnrf-NFManagement (port 7777/443) REST API",
        "tools": ["httpx", "curl", "Wireshark for TLS inspection"],
        "pass_criteria": "NRF returns HTTP 401/403 without valid NF-issued mTLS certificate. No NF topology exposed.",
        "fail_criteria": "NRF returns NF instance list unauthenticated. Full 5GC topology (IPs, ports, NF IDs) exposed.",
        "standard": "GSMA FS.40-5G1 | 3GPP TS 29.510 §5.2 | 3GPP TS 33.501 §13.3",
        "severity_if_fail": "HIGH",
        "duration": "10–20 minutes",
        "environment": "Active — IP access to NRF required",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    },

    "NR-007": {
        "title": "Network Slice Isolation Test",
        "what": "Verify that a UE subscribed to one S-NSSAI cannot establish PDU sessions in a different, restricted S-NSSAI (network slice). Slice boundary leakage violates enterprise/URLLC isolation guarantees.",
        "how": [
            "1. Register test UE with subscription for S-NSSAI SST=1 (eMBB) only.",
            "2. Attempt PDU Session Establishment with S-NSSAI SST=2 (URLLC/restricted).",
            "3. Observe SMF/AMF response: PDU Session Reject with cause 'S-NSSAI not allowed' = PASS.",
            "4. If PDU session is established for SST=2 → FAIL.",
            "5. Also test: modify Allowed-NSSAI in Registration Accept and attempt SST=3 access.",
            "6. Verify NSSF enforces allowed-NSSAI at both registration AND PDU session setup.",
        ],
        "when": "After test UE is registered (NR-002/NR-003 completed). Requires NSSF configured with slice restrictions.",
        "where": "5G NSSF — N22 interface | AMF — N11 interface | SMF — Nsmf API",
        "tools": ["UERANSIM", "Open5GS NSSF", "tshark for N2/N11 capture"],
        "pass_criteria": "PDU session rejected with cause 'S-NSSAI not allowed' for unauthorized slices. NSSF enforces at PDU setup.",
        "fail_criteria": "UE successfully establishes PDU session in unauthorized S-NSSAI. Slice isolation bypassed.",
        "standard": "GSMA FS.37-R1 | 3GPP TS 33.501 §5.11 | 3GPP TS 23.501 §5.15",
        "severity_if_fail": "HIGH",
        "duration": "30–45 minutes",
        "environment": "Active — multi-slice 5GC lab required",
        "cvss": "8.1 (AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N)",
    },

    "NR-008": {
        "title": "SMF PDU Session Hijacking via Unauthenticated API",
        "what": "Verify the SMF requires authenticated AMF NF instance ID before creating PDU sessions. An unauthenticated POST to Nsmf-PDUSession creates data sessions for arbitrary SUPIs.",
        "how": [
            "1. Craft HTTP/2 POST to: /nsmf-pdusession/v1/sm-contexts",
            "   Body: {\"supi\":\"imsi-404300000000001\", \"pduSessionId\":1, ...}",
            "2. Send without Bearer token: httpx --http2 -X POST http://<SMF_IP>:29502/nsmf-pdusession/v1/sm-contexts -d @payload.json",
            "3. If HTTP 201 Created → FAIL — PDU session created without auth.",
            "4. If HTTP 401 → PASS — OAuth2 enforced.",
            "5. Also test with a Bearer token from a non-AMF NF type to check scope validation.",
        ],
        "when": "After NR-005/NR-006 (SBA IPs known). No registered UE required.",
        "where": "5G SMF — Nsmf-PDUSession API (port 29502)",
        "tools": ["httpx", "curl --http2", "jq (JSON payload builder)", "TelSec SBA prober"],
        "pass_criteria": "SMF returns HTTP 401/403 for unauthenticated POST. Token scope validated (AMF only).",
        "fail_criteria": "SMF creates PDU session (HTTP 201) without Bearer token or AMF identity validation.",
        "standard": "GSMA FS.40-5G1 | 3GPP TS 29.502 | 3GPP TS 33.501 §13.3",
        "severity_if_fail": "CRITICAL",
        "duration": "20–30 minutes",
        "environment": "Active — IP access to SMF required",
        "cvss": "9.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },

    "NR-009": {
        "title": "UPF GTP-U Packet Injection",
        "what": "Verify the 5G UPF validates GTP-U source addresses and TEIDs. An attacker with N3 network access can inject arbitrary user-plane packets into active UE sessions.",
        "how": [
            "1. Identify UPF N3 interface IP from NRF/config.",
            "2. Enumerate active GTP-U TEIDs by scanning UDP/2152 with sequential TEID probes (Scapy).",
            "3. Craft GTP-U packet: Scapy GTPHeader(teid=<discovered_teid>)/IP()/UDP()/payload",
            "4. Inject 100-byte UDP payload targeting UPF at port 2152.",
            "5. Monitor: does UPF forward injected packet to UE (via pcap on UE-side)?",
            "6. Check UPF logs for TEID validation failures or source IP validation.",
        ],
        "when": "After basic connectivity tests. N3 network segment access required.",
        "where": "5G UPF — N3 interface (gNB↔UPF), GTP-U protocol UDP/2152",
        "tools": ["Scapy (GTP-U module)", "tshark", "iproute2 (ip route)"],
        "pass_criteria": "UPF rejects GTP-U packets from unknown source IPs. TEID enumeration returns no valid tunnel IDs.",
        "fail_criteria": "UPF forwards injected payload to UE. TEID enumeration reveals active tunnels. No source IP validation.",
        "standard": "GSMA FS.19-D1 | 3GPP TS 29.281 (GTP-U) | 3GPP TS 33.501 §5.10",
        "severity_if_fail": "HIGH",
        "duration": "30–60 minutes",
        "environment": "Active — N3 network segment access required",
        "cvss": "8.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
    },

    "NR-010": {
        "title": "PCF Policy Bypass",
        "what": "Verify the PCF (Policy Control Function) enforces QoS and charging policies and that a UE cannot request higher bandwidth QoS classes than subscribed.",
        "how": [
            "1. Register test UE with a limited QoS subscription (e.g., 5 Mbps downlink).",
            "2. Via SMF, request PDU session with 5QI=1 (GBR, ultra-low latency — URLLC tier).",
            "3. Observe PCF Npcf-SMPolicyControl response: policy rejected? = PASS.",
            "4. If PCF grants 5QI=1 to a non-subscribed UE → FAIL.",
            "5. Also test: modify PCC rules via crafted Npcf API call (if accessible unauthenticated).",
        ],
        "when": "After UE registered and PDU session established. PCF must be configured with QoS profiles.",
        "where": "5G PCF — Npcf-SMPolicyControl API | SMF-PCF N7 interface",
        "tools": ["UERANSIM", "httpx", "Wireshark N7 capture"],
        "pass_criteria": "PCF rejects unauthorized QoS class request. UE bounded to subscribed 5QI. Npcf API requires auth.",
        "fail_criteria": "PCF grants higher 5QI than subscribed. Unauth Npcf API call modifies active PCC rules.",
        "standard": "3GPP TS 23.503 | 3GPP TS 29.512 | 3GPP TS 33.501",
        "severity_if_fail": "MEDIUM",
        "duration": "20–40 minutes",
        "environment": "Active — full 5GC lab with PCF required",
        "cvss": "6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N)",
    },

    "NR-011": {
        "title": "O-RAN E2 Interface Fuzzing",
        "what": "Fuzz the O-RAN E2 interface between Near-RT RIC and E2 nodes (gNB/CU/DU) to identify memory corruption, parsing errors, or denial-of-service vulnerabilities in the ASN.1 E2AP protocol.",
        "how": [
            "1. Set up Near-RT RIC (e.g., O-RAN SC RIC) connected to a test E2 node.",
            "2. Generate valid E2AP baseline messages (E2 Setup Request, RIC Subscription Request).",
            "3. Apply TelSec fuzzer mutations: bit-flip, boundary, truncation on ASN.1 fields.",
            "4. Send 1000+ fuzzed E2AP PDUs to the E2 node at 10 msg/sec.",
            "5. Monitor E2 node for: crashes (SIGABRT/SIGSEGV), memory spikes, protocol resets.",
            "6. Log any anomalous SCTP ABORT or E2 Setup Failure responses.",
        ],
        "when": "Only in isolated O-RAN lab. Never against production RAN. Requires E2 node SCTP access.",
        "where": "O-RAN E2 interface — SCTP association between Near-RT RIC and gNB/CU (port 36422)",
        "tools": ["TelSec protocol fuzzer (Scapy)", "O-RAN SC Near-RT RIC", "Valgrind/ASAN on E2 node"],
        "pass_criteria": "E2 node handles all malformed PDUs gracefully with E2 Error Indication. No crashes or memory leaks.",
        "fail_criteria": "E2 node crashes, hangs, or returns memory content in error messages. Unhandled exceptions observed.",
        "standard": "O-RAN WG3 E2AP specification v3.0 | 3GPP TS 38.401 | GSMA FS.40",
        "severity_if_fail": "HIGH",
        "duration": "1–4 hours",
        "environment": "Active — isolated O-RAN lab only",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    "NR-012": {
        "title": "Mass Fake UE Registration Attack",
        "what": "Evaluate AMF resilience to a coordinated mass SUPI registration attack where thousands of UEs with fake IMSIs attempt to register simultaneously, simulating a botnet-driven telecom DoS.",
        "how": [
            "1. Configure UERANSIM with 1000 UE instances using sequential fake SUPIs.",
            "2. Launch simultaneous registration: ueransim-gnb --multi-ue 1000",
            "3. Measure: AMF memory usage, CPU%, legitimate UE registration latency during attack.",
            "4. Check whether AMF applies: per-PLMN rate limits, SUPI blocklists, congestion indicators.",
            "5. Verify AMF sends Reject with cause 5GMM #22 (Congestion) to fake UEs.",
            "6. Verify legitimate test UE can still register during the attack.",
        ],
        "when": "In isolated lab or with explicit operator coordination. Never on live network.",
        "where": "5G AMF — NGAP N2 interface, NAS Registration procedure",
        "tools": ["UERANSIM (multi-UE)", "Docker resource monitor", "Prometheus/Grafana (5GC metrics)"],
        "pass_criteria": "AMF rate-limits fake registrations. Legitimate UE registers within 2x normal latency. No crash.",
        "fail_criteria": "AMF CPU/RAM exhausted. Legitimate UE registration fails. AMF does not send congestion cause.",
        "standard": "3GPP TS 23.502 §4.2.2 | 3GPP TS 24.501 §6.5 | GSMA FS.40",
        "severity_if_fail": "CRITICAL",
        "duration": "30–60 minutes",
        "environment": "Active, isolated — coordinate with operator",
        "cvss": "8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    # ================================================================
    # 4G / LTE
    # ================================================================

    "LTE-001": {
        "title": "LTE Cell Discovery & eNB Inventory",
        "what": "Enumerate LTE cells (eNBs) across supported bands. Record EARFCN, PCI, RSRP, MCC/MNC, TAC, eNB-ID and verify against authorized cell inventory.",
        "how": [
            "1. Run LTE-Cell-Scanner: LTE-Cell-Scanner --freq-start 1805e6 --freq-end 1880e6 (Band 3)",
            "2. Repeat for Band 7 (2620–2690 MHz) and Band 20 (791–821 MHz).",
            "3. For each PCI found, record EARFCN, RSRP, MCC/MNC from MIB/SIB1.",
            "4. Extract TAC and eNB-ID from SIB1 (cellIdentity IE).",
            "5. Cross-reference against authorized eNB list from config/targets.yaml.",
            "6. Flag any unknown eNB-ID or TAC not matching operator's network plan.",
        ],
        "when": "First step in 4G audit. Run passive before any active Diameter/NAS tests.",
        "where": "LTE PBCH/PDCCH/SIB — passive RF (EARFCN scanning)",
        "tools": ["LTE-Cell-Scanner", "srsRAN", "RTL-SDR", "tshark"],
        "pass_criteria": "All discovered eNBs in authorized list. No unknown PCI/TAC combinations.",
        "fail_criteria": "Unknown eNB-ID or TAC found. eNB with same PLMN but anomalous signal parameters.",
        "standard": "GSMA FS.11 | 3GPP TS 36.101 (EARFCN) | 3GPP TS 36.331 (SIB1)",
        "severity_if_fail": "HIGH",
        "duration": "20–45 minutes",
        "environment": "Passive RF",
    },

    "LTE-002": {
        "title": "IMSI Paging Attack",
        "what": "Verify that the network pages subscribers using TMSI/S-TMSI and never exposes IMSI on the paging channel. IMSI paging allows passive attackers to correlate subscriber identity with location.",
        "how": [
            "1. Using srsRAN UE in monitor mode, capture all Paging messages on PDCCH.",
            "2. Decode the Paging PDU (3GPP TS 36.331 §6.5): check UE-Identity type.",
            "   - s-TMSI = PASS (normal paging)",
            "   - imsi = FAIL (identity exposure)",
            "3. If IMSI paging observed: note the IMSI, EARFCN, timestamp.",
            "4. Also send a crafted paging with the test UE's IMSI from a rogue eNB — check UE response.",
        ],
        "when": "After LTE-001. Monitor for at least 30 minutes to catch periodic IMSI paging events.",
        "where": "LTE PDCCH Paging Channel — RRC Paging message",
        "tools": ["srsRAN (monitor mode)", "LTE Wireshark dissector", "tshark"],
        "pass_criteria": "All paging messages use S-TMSI. No IMSI appears on PCH.",
        "fail_criteria": "Paging message contains IMSI (imsi choice in UE-IdentityIndex). Subscriber trackable by IMSI.",
        "standard": "GSMA FS.11 | 3GPP TS 33.401 §8.3 | 3GPP TS 36.331 §6.5",
        "severity_if_fail": "HIGH",
        "duration": "30–60 minutes",
        "environment": "Passive RF monitoring",
        "cvss": "7.5 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    },

    "LTE-003": {
        "title": "Diameter S6a HSS Probing",
        "what": "Verify that the LTE HSS (Home Subscriber Server) on the S6a Diameter interface requires mutual authentication (IPSec or SCTP/TLS) and does not disclose subscriber data to unauthenticated Diameter peers.",
        "how": [
            "1. Configure a Diameter test client (Wireshark + FreeDiameter) with a crafted Origin-Host.",
            "2. Send Update-Location-Request (ULR) to HSS on port 3868: include test IMSI.",
            "3. Observe response: ULA with Subscription-Data = FAIL (data returned without auth).",
            "4. If using IPSec: verify SA exists before any Diameter messages exchanged.",
            "5. Test with Origin-Host not in the whitelist: should return DIAMETER_UNKNOWN_PEER (3010).",
            "6. Capture and inspect all AVPs in the response for subscriber data leakage.",
        ],
        "when": "After LTE-001. Direct IP access to HSS S6a interface required.",
        "where": "LTE S6a interface — HSS Diameter server (port 3868 or 3869/TLS)",
        "tools": ["FreeDiameter client", "Wireshark Diameter dissector", "tshark", "SigPloit Diameter"],
        "pass_criteria": "HSS returns DIAMETER_UNKNOWN_PEER or AUTH_FAILED for unknown Origin-Host. No subscriber data returned.",
        "fail_criteria": "HSS returns ULA with Subscription-Data to unauthenticated peer. Origin-Host not validated.",
        "standard": "GSMA FS.19-D1 | 3GPP TS 29.272 | 3GPP TS 33.401 §13.2",
        "severity_if_fail": "CRITICAL",
        "duration": "20–40 minutes",
        "environment": "Active — IP access to S6a interface required",
        "cvss": "9.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
    },

    "LTE-004": {
        "title": "Diameter CCR Flood — PCRF DoS",
        "what": "Verify the LTE PCRF (Policy and Charging Rules Function) implements Diameter overload control (RFC 7683) and does not degrade under Credit-Control-Request flooding.",
        "how": [
            "1. Establish a legitimate Diameter Gx session with the PCRF as a test PCEF.",
            "2. Send 1000 CCR-Initial (CCR-I) messages at 100 req/sec using FreeDiameter.",
            "3. Measure PCRF response latency baseline vs load (should not exceed 3x).",
            "4. Check whether PCRF sends DIAMETER_TOO_BUSY (3004) at threshold.",
            "5. Verify PCRF applies per-peer rate limiting (Origin-Host based).",
            "6. After test: confirm legitimate GX sessions still functional.",
        ],
        "when": "Run in maintenance window. Coordinate with operator — may impact active policy sessions.",
        "where": "LTE Gx interface — PCRF Diameter server",
        "tools": ["FreeDiameter", "SigPloit Diameter flood module", "Wireshark"],
        "pass_criteria": "PCRF sends DIAMETER_TOO_BUSY above threshold. Latency within 3x baseline. No crash.",
        "fail_criteria": "PCRF crashes, stops responding, or no rate limiting applied. Legitimate sessions disrupted.",
        "standard": "GSMA FS.19-D1 | 3GPP TS 29.212 | RFC 7683 (Diameter Overload)",
        "severity_if_fail": "HIGH",
        "duration": "30–60 minutes",
        "environment": "Active — isolated or with operator approval",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    "LTE-005": {
        "title": "AIR/MAR Authentication Bypass",
        "what": "Verify the HSS validates that Authentication-Information-Request (AIR) and Multimedia-Authentication-Request (MAR) originate from a whitelisted MME, and does not return authentication vectors to unauthorized requestors.",
        "how": [
            "1. Craft a Diameter AIR message with a fake Origin-Realm and Origin-Host (non-whitelisted MME).",
            "2. Send to HSS S6a endpoint — observe whether AIA response contains Auth-Vectors.",
            "3. Auth-Vectors returned = FAIL. DIAMETER_UNKNOWN_PEER returned = PASS.",
            "4. Repeat with spoofed Origin-Realm matching a known roaming partner.",
            "5. Verify HSS enforces Origin-Host whitelist independent of realm.",
        ],
        "when": "After LTE-003. Requires IP access to HSS S6a/Cx interface.",
        "where": "LTE S6a (HSS↔MME) and Cx (HSS↔P-CSCF) Diameter interfaces",
        "tools": ["FreeDiameter", "SigPloit", "Wireshark"],
        "pass_criteria": "HSS rejects AIR/MAR from unknown Origin-Host with DIAMETER_UNKNOWN_PEER or AUTH_FAILED.",
        "fail_criteria": "HSS returns AIA with Auth-Vectors to unauthenticated/spoofed MME identity.",
        "standard": "GSMA FS.19-D1 | 3GPP TS 29.272 §5.2.3.4 | 3GPP TS 33.401",
        "severity_if_fail": "CRITICAL",
        "duration": "20–30 minutes",
        "environment": "Active — S6a IP access required",
        "cvss": "9.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },

    "LTE-006": {
        "title": "NAS EEA0 Null Cipher Detection",
        "what": "Verify the LTE eNB/MME does not accept EEA0 (null ciphering) for NAS or RRC security. EEA0 means all NAS signalling transmitted in cleartext.",
        "how": [
            "1. Configure srsRAN UE to advertise UEA capability list: [EEA0, EEA1, EEA2] (EEA0 first/highest priority).",
            "2. Attach test UE to target eNB/MME.",
            "3. Capture Security Mode Command in NAS/RRC messages.",
            "4. Check 'UE Security Capability' and 'Selected Security Algorithms' IEs:",
            "   - selectedAlgorithm: eea0 (0) = FAIL",
            "   - selectedAlgorithm: eea1 or eea2 = PASS",
            "5. If EEA0 selected: all subsequent NAS messages will be in cleartext.",
        ],
        "when": "After LTE-001. Active UE attach to target MME required.",
        "where": "LTE NAS layer — Security Mode Command on MME→UE (EMM protocol)",
        "tools": ["srsRAN 4G UE", "tshark", "Wireshark with LTE-NAS dissector"],
        "pass_criteria": "MME selects EEA1 or EEA2. EEA0 never chosen regardless of UE capability list order.",
        "fail_criteria": "MME Security Mode Command selects EEA0. NAS messages transmitted in cleartext.",
        "standard": "GSMA TS33.401-E1 | 3GPP TS 33.401 §5.1.3 | CVE-2019-2025",
        "severity_if_fail": "HIGH",
        "duration": "15–25 minutes",
        "environment": "Active — registered test UE required",
        "cvss": "8.1 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    },

    "LTE-007": {
        "title": "RRC Connection Reject Flood",
        "what": "Verify the LTE eNB handles malformed or high-volume RRC Connection Requests without crashing or rejecting legitimate UEs. Tests eNB robustness against protocol-layer DoS.",
        "how": [
            "1. Configure srsRAN to send 200 RRC Connection Requests/second to target eNB.",
            "2. Use invalid or malformed establishment cause values in the requests.",
            "3. Monitor eNB: CPU usage, active RRC connections, rejection rate.",
            "4. Verify eNB sends RRC Connection Reject with wait timer (vs crashing/silent drop).",
            "5. Confirm a legitimate test UE can still attach during and after the flood.",
        ],
        "when": "Isolated lab or operator-coordinated test window required.",
        "where": "LTE air interface — RRC (Radio Resource Control) layer on RACH/CCCH",
        "tools": ["srsRAN customized", "OpenAirInterface", "tshark"],
        "pass_criteria": "eNB applies rateCounter and sends RRC Connection Reject with waitTime. No crash. Legit UE attaches.",
        "fail_criteria": "eNB crashes or becomes unresponsive. Legitimate UE cannot attach during test.",
        "standard": "3GPP TS 36.331 §5.3.3 | 3GPP TS 36.413 (S1AP)",
        "severity_if_fail": "HIGH",
        "duration": "20–40 minutes",
        "environment": "Active — isolated lab recommended",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    "LTE-008": {
        "title": "DNS & NRF Enumeration",
        "what": "Verify that internal LTE EPC DNS (used for MME/HSS/PGW resolution) and any NRF instances are not publicly accessible and do not expose internal network topology.",
        "how": [
            "1. Identify EPC DNS server IP from DHCP/config.",
            "2. Query: nslookup mme.epc.<realm> <EPC_DNS_IP>",
            "3. Attempt zone transfer: dig axfr <realm> @<EPC_DNS_IP>",
            "4. If zone transfer succeeds: enumerate all internal LTE node hostnames/IPs.",
            "5. Also probe any NRF endpoint for unauthenticated NF instance discovery (see NR-006 for method).",
            "6. Verify DNS is restricted: external resolvers should not resolve internal EPC FQDNs.",
        ],
        "when": "After LTE-001. IP access to EPC management network required.",
        "where": "EPC internal DNS + NRF (if hybrid)",
        "tools": ["dig", "nslookup", "nmap (port 53)", "dnsx"],
        "pass_criteria": "Zone transfer rejected. Internal FQDNs not resolvable from test host. NRF requires auth.",
        "fail_criteria": "Zone transfer succeeds exposing all EPC node IPs. Internal DNS externally accessible.",
        "standard": "GSMA FS.19-D1 | CIS DNS Security Benchmark | 3GPP TS 23.003",
        "severity_if_fail": "MEDIUM",
        "duration": "15–30 minutes",
        "environment": "Active — management network access",
        "cvss": "6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    },

    "LTE-009": {
        "title": "GTP-U TEID Prediction & Packet Injection",
        "what": "Verify the LTE SGW/PGW validates GTP-U source IP addresses and Tunnel Endpoint IDs. Sequential TEID allocation allows attackers to predict and inject into active user-plane tunnels.",
        "how": [
            "1. Establish authorized GTP-U session — note assigned TEID from Create Session Response.",
            "2. Probe adjacent TEIDs: craft GTP-U packets with TEID ±1,±2,±N from known TEID.",
            "3. Send Scapy GTP-U packets to SGW S1-U interface: GTPHeader(teid=X)/IP(dst='8.8.8.8')/ICMP()",
            "4. Monitor: does SGW forward injected packets? Check with tcpdump on the authorized UE.",
            "5. Also verify: GTP-U only accepted from known eNB source IPs (access control list).",
        ],
        "when": "After establishing a legitimate GTP session (test UE registered and has PDN connection).",
        "where": "LTE S1-U interface (eNB↔SGW) and S5/S8 (SGW↔PGW) — GTP-U UDP/2152",
        "tools": ["Scapy with GTP module", "tcpdump", "tshark"],
        "pass_criteria": "SGW rejects GTP-U from unknown source IPs. TEID enumeration gets no valid response. Injection fails.",
        "fail_criteria": "Injected GTP-U packets forwarded through tunnel. TEID scanning reveals active tunnels.",
        "standard": "GSMA FS.19-D1 | 3GPP TS 29.281 | 3GPP TS 33.401 §5.3",
        "severity_if_fail": "HIGH",
        "duration": "30–60 minutes",
        "environment": "Active — S1-U network access + registered test UE",
        "cvss": "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
    },

    "LTE-010": {
        "title": "VoLTE SIP Injection & SPIT",
        "what": "Verify the P-CSCF/S-CSCF enforces SIP message authentication and rejects unauthenticated INVITE/REGISTER messages that could enable SPIT (SPam over Internet Telephony) or call hijacking.",
        "how": [
            "1. Connect to IMS PDN (APN: ims) with test UE — obtain P-CSCF IP.",
            "2. Send unauthenticated SIP REGISTER to P-CSCF: no Authorization header.",
            "   SIP/2.0 REGISTER sip:<realm> ... (no Authorization)",
            "3. Expected: 401 Unauthorized with WWW-Authenticate challenge.",
            "4. Send unauthenticated SIP INVITE to test extension.",
            "5. Expected: 401 or 403 Forbidden (not connected).",
            "6. If call connects without auth: FAIL — SPIT/spoofed caller ID vector.",
        ],
        "when": "After VoLTE PDN established (LTE-001 complete, test SIM has IMS subscription).",
        "where": "LTE IMS — P-CSCF SIP interface (UDP/TCP 5060, TLS 5061)",
        "tools": ["SIPp", "Wireshark SIP dissector", "curl (SIP-over-HTTP testing)"],
        "pass_criteria": "P-CSCF returns 401 with digest challenge for all unauthenticated REGISTER/INVITE.",
        "fail_criteria": "SIP REGISTER accepted without Authorization. INVITE connected without caller authentication.",
        "standard": "GSMA FS.11 | 3GPP TS 24.229 (SIP IMS) | RFC 3261 §22 (SIP auth)",
        "severity_if_fail": "HIGH",
        "duration": "20–40 minutes",
        "environment": "Active — IMS PDN access required",
        "cvss": "8.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    },

    # ================================================================
    # 3G / SS7 / SIGTRAN
    # ================================================================

    "SS7-001": {
        "title": "SCCP Firewall GT Filter Bypass",
        "what": "Verify the SS7 SCCP firewall validates the full E.164 Global Title (GT) of incoming MAP messages, not just country code prefix. Firewalls checking only prefix can be bypassed by spoofed GTs within allowed country.",
        "how": [
            "1. Connect test STP to target SS7 gateway via M3UA/SCTP.",
            "2. Send a MAP sendRoutingInfo request with Source GT = +44<random-10-digits> (UK number).",
            "3. If UK is in allowed country whitelist: check whether firewall filters full E.164 or just +44.",
            "4. Try invalid GT formats: malformed length, out-of-range digits, E.164 with wrong NDC.",
            "5. If MAP response received (not rejected): firewall only checks country code prefix (FAIL).",
            "6. Document: firewall vendor, version, GT validation depth.",
        ],
        "when": "Start of SS7 audit. Requires SCTP connectivity to SS7 gateway/STP.",
        "where": "SS7 SCCP layer — MTP3/M3UA signaling gateway",
        "tools": ["SigPloit", "ss7MAPer", "Wireshark SS7/M3UA dissector", "SCTP tools"],
        "pass_criteria": "Firewall rejects all GTs not on per-entry whitelist. Full E.164 validated (not just prefix).",
        "fail_criteria": "MAP response received from non-whitelisted GT with matching country code. GT spoofing succeeds.",
        "standard": "GSMA FS.11 Cat.0 | 3GPP TS 29.002 | GSMA IR.82",
        "severity_if_fail": "HIGH",
        "duration": "30–60 minutes",
        "environment": "Active — M3UA/SCTP access to SS7 gateway",
        "cvss": "8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
    },

    "SS7-002": {
        "title": "Location Disclosure via sendRoutingInfo",
        "what": "Verify the HLR/VLR rejects or filters sendRoutingInfo (SRI-SM) MAP queries that are not from registered roaming partners. SRI-SM from arbitrary SS7 peers leaks subscriber VLR location.",
        "how": [
            "1. Send MAP sendRoutingInfo-ForSM with MSISDN of authorized test subscriber.",
            "2. Use SigPloit: python3 sigploit.py --attack SRI --msisdn +<test_number>",
            "3. Observe response: if VLR-Number or IMSI returned in RoutingInfoForSM-Res → FAIL.",
            "4. Check: does HLR validate Category of requesting entity (must be SMSC)?",
            "5. Try from multiple source GTs (different country codes) — firewall coverage test.",
        ],
        "when": "After SS7-001 (firewall baseline established). Test MSISDN must be authorized.",
        "where": "HLR — MAP D interface (HLR↔VLR) and MAP G interface (SGSN↔HLR)",
        "tools": ["SigPloit", "ss7MAPer", "Wireshark"],
        "pass_criteria": "HLR returns MAP error (Unknown subscriber, Absent subscriber) or firewall blocks. No VLR address exposed.",
        "fail_criteria": "HLR returns routingInfoForSM with vlr-Number or imsi to unauthenticated requestor.",
        "standard": "GSMA FS.11 Cat.1 | 3GPP TS 29.002 §7.6.2 | CVE-2014-3814",
        "severity_if_fail": "CRITICAL",
        "duration": "20–30 minutes",
        "environment": "Active — SS7 gateway connectivity",
        "cvss": "9.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
    },

    "SS7-003": {
        "title": "SMS Interception Path via forwardSM",
        "what": "Verify the network prevents MAP forwardSM interception by validating that the requesting SMSC is the legitimate registered SMSC for the subscriber and that SMS routing cannot be hijacked.",
        "how": [
            "1. After SRI-SM probe (SS7-002): obtain VLR number for test MSISDN.",
            "2. Craft MAP mt-forwardSM with spoofed SMSC GT targeting the obtained VLR.",
            "3. Observe: does SM delivery attempt reach the MSC/VLR?",
            "4. Check VLR/MSC: does it validate that mt-forwardSM originates from the MSISDN's registered SMSC?",
            "5. If delivery proceeds without SMSC validation: SMS hijacking path confirmed (advisory — do not deliver content).",
        ],
        "when": "After SS7-002. Advisory/passive analysis only — do not send to live subscriber.",
        "where": "SS7 MAP E interface (SMSC↔MSC/VLR) — mt-forwardSM operation",
        "tools": ["SigPloit", "ss7MAPer", "Wireshark"],
        "pass_criteria": "MSC/VLR validates SMSC GT against HLR-registered SMSC. Forged SMSC GT rejected.",
        "fail_criteria": "MSC accepts mt-forwardSM from arbitrary SMSC GT. SMS routing can be hijacked by anyone with SS7 access.",
        "standard": "GSMA FS.11 Cat.5 | 3GPP TS 29.002 §10.2",
        "severity_if_fail": "CRITICAL",
        "duration": "20–40 minutes",
        "environment": "Active — SS7 connectivity (advisory only, do not deliver SMS to live subscriber)",
        "cvss": "9.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)",
    },

    "SS7-004": {
        "title": "Voice Call Interception Path (MAP)",
        "what": "Assess whether MAP operations can be abused to redirect voice calls to an attacker-controlled MSC, enabling passive call interception.",
        "how": [
            "1. Test MAP updateLocation: send fake ULR from attacker-controlled MSC GT for test MSISDN.",
            "2. If HLR accepts updateLocation: new calls to test MSISDN routed to attacker MSC (FAIL).",
            "3. Also assess MAP insertSubscriberData: can subscriber routing be modified without HLR auth?",
            "4. Use SigPloit Call Redirect module in advisory mode — document but do not intercept real calls.",
        ],
        "when": "After SS7-001/002 baseline. Strictly advisory — documented with operator consent.",
        "where": "HLR D/C interfaces — updateLocation MAP operation",
        "tools": ["SigPloit", "ss7MAPer"],
        "pass_criteria": "HLR rejects updateLocation from non-whitelisted MSC GT. No call redirect possible.",
        "fail_criteria": "HLR accepts updateLocation from arbitrary GT. Call routing manipulable by SS7 peer.",
        "standard": "GSMA FS.11 Cat.3 | 3GPP TS 29.002 §8.1",
        "severity_if_fail": "CRITICAL",
        "duration": "20–30 minutes",
        "environment": "Active — strictly advisory, do not redirect real calls",
        "cvss": "9.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)",
    },

    "SS7-005": {
        "title": "SRI DoS Flood",
        "what": "Verify the HLR/STP applies rate limiting on sendRoutingInfo requests. High-volume SRI floods can exhaust HLR processing capacity, causing subscriber registration failures.",
        "how": [
            "1. Send 100 SRI-SM requests/second to HLR for 30 seconds using SigPloit flood module.",
            "2. Monitor HLR response latency and CPU (via SNMP/MIB or vendor console).",
            "3. Check: does STP/firewall apply per-source-GT rate limiting?",
            "4. Verify: after flood, legitimate SRI requests still receive responses within SLA.",
            "5. Document threshold where HLR latency exceeds 3x baseline.",
        ],
        "when": "Run in test window after baseline measured. Coordinate with HLR NOC.",
        "where": "HLR D interface — MAP sendRoutingInfo operation",
        "tools": ["SigPloit (flood module)", "SNMP MIB polling", "Wireshark"],
        "pass_criteria": "STP applies rate limiting. HLR remains responsive. Latency within 2x baseline under load.",
        "fail_criteria": "HLR response latency >10x baseline or HLR becomes unresponsive. No rate limiting detected.",
        "standard": "GSMA FS.11 Cat.6 | GSMA IR.82",
        "severity_if_fail": "HIGH",
        "duration": "20–30 minutes",
        "environment": "Active — coordinate with NOC",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    "SS7-006": {
        "title": "IMSI Harvesting via MAP",
        "what": "Verify that MAP operations cannot be used to harvest IMSI from MSISDN (phone number). The IMSI is a permanent subscriber identifier enabling long-term tracking and SIM cloning.",
        "how": [
            "1. Send MAP sendRoutingInfoForSM with SMSC-Address set to attacker GT, MSISDN = test number.",
            "2. Inspect routingInfoForSM response for 'imsi' field.",
            "3. Also try MAP anyTimeInterrogation (ATI) — query subscriber state including IMSI.",
            "4. ATI IMSI returned without auth = critical failure.",
            "5. Document all MAP operations that return IMSI without HLR authentication.",
        ],
        "when": "After SS7-001. Test MSISDN must be authorized.",
        "where": "HLR MAP interfaces — C (GMSC) and D (VLR) operations",
        "tools": ["SigPloit", "ss7MAPer"],
        "pass_criteria": "No MAP operation returns IMSI to unauthenticated requestor. ATI blocked by firewall.",
        "fail_criteria": "IMSI returned in SRI-SM response or ATI response without peer authentication.",
        "standard": "GSMA FS.11 Cat.1 | 3GPP TS 29.002",
        "severity_if_fail": "CRITICAL",
        "duration": "15–30 minutes",
        "environment": "Active — SS7 connectivity",
        "cvss": "9.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
    },

    "SS7-007": {
        "title": "Fake VLR Registration",
        "what": "Verify the HLR rejects MAP updateLocation requests from unauthorized VLRs. An attacker who registers a fake VLR can intercept all incoming calls and SMS for affected subscribers.",
        "how": [
            "1. Send MAP updateLocation with: IMSI of test subscriber, VLR-Number = attacker GT.",
            "2. Check HLR response: if MAP updateLocationAck returned = FAIL (subscriber now pointing to fake VLR).",
            "3. Verify: does HLR validate VLR GT against a whitelist of authorized roaming partner VLRs?",
            "4. After test: immediately restore by sending legitimate updateLocation from real VLR.",
        ],
        "when": "Critical test — perform only with operator NOC on standby to restore subscriber state immediately.",
        "where": "HLR D interface — MAP updateLocation",
        "tools": ["SigPloit", "Wireshark"],
        "pass_criteria": "HLR rejects updateLocation from non-whitelisted VLR GT with MAP System Failure or Unexpected Data.",
        "fail_criteria": "HLR returns updateLocationAck for fake VLR. Subscriber call/SMS routing hijacked.",
        "standard": "GSMA FS.11 Cat.3 | 3GPP TS 29.002 §8.1.2",
        "severity_if_fail": "CRITICAL",
        "duration": "15–20 minutes (with NOC standby)",
        "environment": "Active — NOC standby mandatory",
        "cvss": "9.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    },

    "SS7-008": {
        "title": "USSD Hijacking",
        "what": "Verify that MAP processUnstructuredSS-Request cannot be sent by unauthorized peers to execute USSD commands on the subscriber's behalf (e.g., balance queries, call forwarding activation).",
        "how": [
            "1. Send MAP processUnstructuredSS-Request with USSD string '*135#' (balance query) for test MSISDN.",
            "2. Observe: is USSD request forwarded to MSC/HLR and executed?",
            "3. If response received (balance/status info): USSD command executed without auth (FAIL).",
            "4. Also test: MAP unstructuredSS-Request to activate call forwarding (CFU).",
            "5. Document which USSD codes are exposed and the impact of each.",
        ],
        "when": "After SS7-001/002. Authorized test MSISDN required.",
        "where": "HLR MAP supplementary services interface",
        "tools": ["SigPloit USSD module", "Wireshark"],
        "pass_criteria": "USSD requests rejected by firewall or HLR for non-operator sources. No supplementary service modification.",
        "fail_criteria": "USSD command executes: balance returned, call forwarding activated, or other service changed.",
        "standard": "GSMA FS.11 Cat.5 | 3GPP TS 29.002 §7.7",
        "severity_if_fail": "HIGH",
        "duration": "15–30 minutes",
        "environment": "Active — carefully scoped, only for authorized test MSISDN",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    },

    "SS7-009": {
        "title": "Authentication Vector Retrieval (sendAuthInfo)",
        "what": "Verify the HLR does not return authentication vectors (RAND/SRES/Kc triplets) to MAP peers that have not been authenticated as authorized MSC/SGSN nodes. Retrieved vectors enable SIM cloning.",
        "how": [
            "1. Send MAP sendAuthenticationInfo with IMSI of test subscriber from attacker GT.",
            "2. SigPloit: python3 sigploit.py --attack AUTH_INFO --imsi <test_imsi>",
            "3. If sendAuthenticationInfoResult returned with AuthVector tuples: FAIL.",
            "4. Check: does HLR validate Origin GT is a known MSC before returning auth vectors?",
            "5. Try with multiple source GTs (legitimate roaming partner range) to test whitelist depth.",
        ],
        "when": "After SS7-001. Requires authorized test IMSI.",
        "where": "HLR D interface — MAP sendAuthenticationInfo",
        "tools": ["SigPloit", "Wireshark"],
        "pass_criteria": "HLR returns MAP Unexpected Data or Unknown Subscriber. No auth vectors returned to unauthorized peer.",
        "fail_criteria": "RAND/SRES/Kc authentication vectors returned. Enables SIM clone and session key derivation.",
        "standard": "GSMA FS.11 Cat.2 | 3GPP TS 29.002 §9.1.9 | CVE-2016-9929",
        "severity_if_fail": "CRITICAL",
        "duration": "15–25 minutes",
        "environment": "Active — SS7 connectivity",
        "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    },

    "SS7-010": {
        "title": "Cancel Location Attack",
        "what": "Verify the VLR/HLR rejects MAP cancelLocation requests from non-authoritative peers. A successful cancelLocation deregisters the subscriber, causing service denial (calls/SMS not delivered).",
        "how": [
            "1. Send MAP cancelLocation with IMSI of test subscriber, cancellation-type = updateProcedure.",
            "2. If VLR removes subscriber record: test UE loses service (FAIL).",
            "3. Observe VLR response: if cancelLocationAck returned from VLR = location was cancelled.",
            "4. Verify: does HLR validate that cancelLocation originates from its own signalling (self-generated on updateLocation)?",
            "5. After test: restore subscriber by forcing UE to re-register.",
        ],
        "when": "Run only with NOC on standby and ability to immediately restore. Test IMSI must be isolated subscriber.",
        "where": "VLR D interface — MAP cancelLocation",
        "tools": ["SigPloit", "Wireshark"],
        "pass_criteria": "VLR rejects cancelLocation from non-HLR sources. Subscriber service unaffected.",
        "fail_criteria": "VLR accepts cancelLocation — subscriber deregistered. Any MAP peer can cause subscriber service denial.",
        "standard": "GSMA FS.11 Cat.6 | 3GPP TS 29.002 §8.1.3",
        "severity_if_fail": "HIGH",
        "duration": "10–20 minutes (NOC standby required)",
        "environment": "Active — NOC standby mandatory, isolated test IMSI",
        "cvss": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
    },

    # ================================================================
    # ACTIVE EXPLOITATION — LOCATION TRACKING
    # ================================================================


    "TELSEC-LOC-001": {
        "title": "MAP Any-Time-Interrogation Location Disclosure",
        "purpose": "Verify SS7 firewall blocks unauthorized MAP_ATI from external/roaming interconnects",
        "what_tested": "MAP ATI operation on Gr/D interface (HLR)",
        "preconditions": [
            "SS7 firewall/STP in-line between interconnect and HLR",
            "Test attacker node with SCCP GT assigned",
            "Target MSISDN registered in HLR",
            "GSMA FS.11 Category 2/3 filter policy active",
        ],
        "execution_steps": [
            "1. Configure attacker node with valid-looking SCCP GT",
            "2. Send MAP_SEND_ROUTING_INFO to target HLR/HGW",
            "3. Capture response: extract IMSI + MSC/VLR address",
            "4. Send MAP_ATI to resolved MSC/VLR address",
            "5. Capture response: Cell-ID, LAC, IMEI",
            "6. Attempt with spoofed GT (another operator's address)",
            "7. Repeat from external IP and from roaming partner STP",
        ],
        "where_tested": "SS7 Firewall / STP Gateway / HLR-Gr interface",
        "when_to_run": "Post-firewall deployment; after any STP config change; quarterly periodic audit",
        "pass_criteria": [
            "SS7 firewall BLOCKS MAP_ATI from unauthorized GT addresses",
            "HLR returns MAP_ERROR (Unexpected Data Value / Facility Not Supported)",
            "No Cell-ID/LAC returned to attacker",
            "Alert triggered in security monitoring system",
        ],
        "fail_criteria": [
            "HLR responds with Cell-ID and LAC to unauthorized GT",
            "Attacker successfully derives subscriber location",
            "No alert generated in monitoring system",
            "Spoofed GT accepted without GT validation",
        ],
        "evidence_format": "Wireshark PCAP / SS7 Firewall log / STP alarm log",
        "severity": "Critical",
        "references": [
            "GSMA FS.11 Cat-2/Cat-3", "ITU-T X.805 Control Plane",
            "3GPP TS 29.002 MAP spec", "TEC/DOT TSTP framework",
        ],
        "standard": "GSMA FS.11 Cat-2/Cat-3 | ITU-T X.805 | 3GPP TS 29.002",
        "severity_if_fail": "Critical",
        "duration": "30–60 minutes",
        "environment": "Active — SS7 lab interconnect",
    },

    "TELSEC-LOC-002": {
        "title": "Diameter IDR-based Location Tracking (4G)",
        "purpose": "Verify HSS/MME reject unauthorized Diameter IDR from unknown Diameter peers",
        "what_tested": "Diameter S6a interface (MME↔HSS), IDR command",
        "preconditions": [
            "Diameter firewall/DRA active on S6a interface",
            "Test Diameter node configured with rogue Origin-Host/Realm",
            "Target subscriber in 4G network (IMSI known)",
            "GSMA FS.19 filter policy active on DRA",
        ],
        "execution_steps": [
            "1. Establish Diameter peer connection from rogue node to DRA",
            "2. Send Diameter CER (Capabilities-Exchange-Request)",
            "3. Upon CEA success, send IDR with target IMSI",
            "4. Attempt with unregistered Origin-Host/Realm",
            "5. Attempt AVP injection: add unauthorized AVP in IDR",
            "6. Send CLR (Cancel-Location-Request) for target IMSI",
        ],
        "where_tested": "DRA / HSS S6a interface / Diameter Firewall",
        "when_to_run": "Post-DRA configuration; after roaming agreement changes",
        "pass_criteria": [
            "DRA rejects CER from unregistered Diameter peers",
            "HSS returns DIAMETER_ERROR_USER_UNKNOWN or DIAMETER_UNABLE_TO_DELIVER",
            "AVP injection causes message rejection (Result-Code 5xxx)",
            "CLR from rogue peer blocked and alerted",
        ],
        "fail_criteria": [
            "DRA allows connection from unregistered Origin-Host",
            "HSS processes IDR and returns subscriber location",
            "Injected AVPs processed without error",
        ],
        "evidence_format": "Diameter trace logs / DRA peer table / HSS audit log",
        "severity": "Critical",
        "references": ["GSMA FS.19", "3GPP TS 29.272 (S6a)", "TS 33.210"],
        "standard": "GSMA FS.19 | 3GPP TS 29.272 | 3GPP TS 33.210",
        "severity_if_fail": "Critical",
        "duration": "20–40 minutes",
        "environment": "Active — Diameter lab / DRA access",
    },

    # ================================================================
    # ACTIVE EXPLOITATION — IDENTITY SPOOFING
    # ================================================================

    "TELSEC-ID-001": {
        "title": "Fake BTS IMSI Catcher Detection",
        "purpose": "Verify network-side detection of IMSI catching via rogue base station identity requests",
        "what_tested": "RRC/NAS identity procedures; Core network IMSI request filtering",
        "preconditions": [
            "Network has IMSI catcher detection capability (GSMA FS.24)",
            "Test environment with simulated UE",
            "Rogue BTS simulator (e.g., srsRAN or simulated)",
            "Network logging enabled at MME/AMF",
        ],
        "execution_steps": [
            "1. Deploy simulated rogue BTS with stronger signal than real cell",
            "2. Force test UE to camp on rogue BTS",
            "3. Send NAS Identity Request (identity type = IMSI)",
            "4. Capture IMSI in plaintext NAS message",
            "5. Attempt 2G fallback from 4G/5G (protocol downgrade)",
            "6. Test 5G SUCI concealment: verify IMSI not exposed",
            "7. Test whether AMF detects multiple IMSI request anomalies",
        ],
        "where_tested": "Radio Access Network / UE / MME-AMF / Core network auth nodes",
        "when_to_run": "Network rollout; after RAN configuration changes; annual security audit",
        "pass_criteria": [
            "4G/5G: IMSI not sent in cleartext (TMSI/SUCI used instead)",
            "5G SUCI: IMSI concealed using ECIES/Home Network Public Key",
            "AMF logs and alerts on repeated IMSI request patterns",
            "Protocol downgrade to 2G blocked by network policy",
        ],
        "fail_criteria": [
            "UE sends IMSI in plaintext to rogue BTS",
            "2G fallback succeeds exposing IMSI",
            "5G SUCI successfully correlated to IMSI by attacker",
            "No alert at core network for repeated identity requests",
        ],
        "evidence_format": "NAS message capture / UE IMSI request log / AMF security audit log",
        "severity": "Critical",
        "references": [
            "3GPP TS 33.501 §6.12", "TS 23.003", "GSMA FS.24", "TS 33.102 §6.3.1",
        ],
        "standard": "3GPP TS 33.501 §6.12 | GSMA FS.24 | 3GPP TS 33.102",
        "severity_if_fail": "Critical",
        "duration": "45–90 minutes",
        "environment": "Active — RAN lab with simulated UE + rogue BTS",
    },

    "TELSEC-ID-002": {
        "title": "MAP Send-IMSI MSISDN-to-IMSI Enumeration",
        "purpose": "Verify HLR/VLR reject unauthorized MAP SendIMSI requests",
        "what_tested": "MAP SendIMSI operation; HLR access controls",
        "preconditions": [
            "SS7 firewall deployed on HLR interconnect",
            "Attacker SCCP GT not in whitelist",
            "Target MSISDN registered in HLR",
        ],
        "execution_steps": [
            "1. Send MAP_SEND_IMSI with target MSISDN to HLR",
            "2. Capture: does HLR return IMSI?",
            "3. Repeat from multiple spoofed GTs (enumeration attempt)",
            "4. Try with valid roaming partner GT (boundary test)",
            "5. Send MAP_SRI with requestIMSI flag set",
        ],
        "where_tested": "HLR / VLR / SS7 Firewall",
        "when_to_run": "Post-firewall deployment; after HLR software upgrades",
        "pass_criteria": [
            "MAP SendIMSI blocked by SS7 firewall for non-whitelisted GTs",
            "HLR returns MAP_ERROR (Teleservice Not Provisioned)",
            "Enumeration attempts trigger rate-limiting alert",
        ],
        "fail_criteria": [
            "IMSI returned to unauthorized SCCP GT",
            "No rate limiting on repeated SendIMSI requests",
            "Roaming partner GT boundary bypass successful",
        ],
        "evidence_format": "SS7 Firewall log / HLR MAP trace / STP CDRs",
        "severity": "High",
        "references": ["GSMA FS.11 Cat-1", "3GPP TS 29.002 §7.3.1.1"],
        "standard": "GSMA FS.11 Cat-1 | 3GPP TS 29.002 §7.3.1.1",
        "severity_if_fail": "High",
        "duration": "20–30 minutes",
        "environment": "Active — SS7 lab",
    },

    # ================================================================
    # ACTIVE EXPLOITATION — INTERCEPTION & FRAUD
    # ================================================================

    "TELSEC-INT-001": {
        "title": "MAP SRI-SM Based SMS Interception via SMSC Rerouting",
        "purpose": "Verify network blocks unauthorized SRI-SM enabling SMS intercept via rogue SMSC",
        "what_tested": "MAP SRI-SM operation; HLR MSISDN-to-SMSC routing table",
        "preconditions": [
            "Target MSISDN registered in HLR",
            "SS7 firewall with FS.11 Cat-1/Cat-2 rules active",
            "Legitimate SMSC address registered for target MSISDN",
            "Attacker has rogue SMSC address to inject",
        ],
        "execution_steps": [
            "1. Send MAP_SRI_FOR_SM with target MSISDN to HLR",
            "2. Capture HLR response: IMSI + MSC address",
            "3. Register rogue SMSC via MAP_REGISTER_SS (call forwarding variant)",
            "4. Send test SMS to target MSISDN from external number",
            "5. Verify if SMS delivered to rogue SMSC instead of real device",
            "6. Attempt MAP_UPDATE_LOCATION to update subscriber MSC",
            "7. Test with spoofed SMSC return address",
        ],
        "where_tested": "HLR / SS7 Firewall / SMSC / SMS Home Routing Node",
        "when_to_run": "Post-deployment; after SMS Home Routing changes; after roaming interconnect additions",
        "pass_criteria": [
            "SMS Home Routing blocks direct SRI-SM from external GTs",
            "HLR returns anonymized routing info (SMSHRN, not real IMSI)",
            "Rogue SMSC injection attempt rejected",
            "MAP_UPDATE_LOCATION from unauthorized GT blocked",
        ],
        "fail_criteria": [
            "Real IMSI + MSC returned to unauthorized SCCP GT",
            "SMS successfully rerouted to rogue SMSC",
            "Call forwarding registered to attacker-controlled number",
        ],
        "evidence_format": "SS7 trace / HLR access log / SMS-HRS routing table diff",
        "severity": "Critical",
        "references": ["GSMA FS.11 Cat-2", "GSMA FS.26 (SMS Security)", "3GPP TS 29.002 §7.3.2.1"],
        "standard": "GSMA FS.11 Cat-2 | GSMA FS.26 | 3GPP TS 29.002 §7.3.2.1",
        "severity_if_fail": "Critical",
        "duration": "30–60 minutes",
        "environment": "Active — SS7 lab + SMS Home Router",
    },

    "TELSEC-INT-002": {
        "title": "GTP-C TEID Hijacking (Session Theft)",
        "purpose": "Verify PGW/UPF reject GTP sessions with spoofed TEIDs from unauthorized SGSNs/SGWs",
        "what_tested": "GTP-C Create-Session-Request; TEID validation at PGW",
        "preconditions": [
            "GTP firewall or border gateway deployed on Gn/S5/S8 interface",
            "Known valid TEID range of active subscriber sessions",
            "Attacker positioned to inject GTP-C messages",
            "Target subscriber with active data session",
        ],
        "execution_steps": [
            "1. Enumerate active TEIDs via crafted Echo-Request probes",
            "2. Send Create-Session-Request with cloned TEID to PGW",
            "3. Attempt Modify-Bearer-Request to redirect data plane",
            "4. Send Delete-Session-Request to drop legitimate session",
            "5. Test with mismatched IMSI/APN in Create-Session",
            "6. Attempt GTP-in-GTP encapsulation attack",
        ],
        "where_tested": "PGW / S-GW / GTP Firewall / Gi/SGi interface",
        "when_to_run": "Post-core-network deployment; after APN changes; when new roaming GTP peers added",
        "pass_criteria": [
            "GTP firewall rejects Create-Session from non-whitelisted GTP peers",
            "PGW validates IMSI against serving SGSN/SGW in whitelist",
            "Modify-Bearer with mismatched TEID rejected",
            "Tunnel encapsulation anomaly detected and blocked",
        ],
        "fail_criteria": [
            "PGW accepts Create-Session from rogue SGSN/SGW",
            "Existing session hijacked via Modify-Bearer",
            "Data plane traffic rerouted to attacker-controlled endpoint",
        ],
        "evidence_format": "GTP trace log / PGW CDR anomaly / Firewall block log",
        "severity": "Critical",
        "references": ["GSMA FS.20 (GTP Security)", "3GPP TS 29.274", "GSMA IR.77 (IPX GTP security)"],
        "standard": "GSMA FS.20 | 3GPP TS 29.274 | GSMA IR.77",
        "severity_if_fail": "Critical",
        "duration": "30–60 minutes",
        "environment": "Active — N3/Gn/S5 network segment access",
    },

    "TELSEC-INT-003": {
        "title": "Diameter Gy/Ro Charging Bypass (Prepaid Fraud)",
        "purpose": "Verify OCS/PCRF reject unauthorized charging manipulation via Diameter Gy/Ro interface",
        "what_tested": "Diameter Gy CCR-I/CCR-U/CCR-T; OCS quota enforcement",
        "preconditions": [
            "OCS active with prepaid subscriber balance configured",
            "DRA/Diameter firewall on Gy interface",
            "PGW configured to forward Gy to OCS",
            "Test subscriber with known prepaid balance (e.g., ₹10)",
        ],
        "execution_steps": [
            "1. Intercept Gy CCR-I (Credit Control Request - Initial)",
            "2. Craft modified CCA-I (Answer) with inflated quota grant",
            "3. Send CCR-U without valid Session-Id to bypass quota check",
            "4. Inject Abort-Session-Request (ASR) mid-session",
            "5. Attempt to replay valid CCR-I from previous session",
            "6. Test missing/invalid Rating-Group AVP handling at OCS",
        ],
        "where_tested": "OCS / PCRF / DRA Gy interface / PGW",
        "when_to_run": "Post OCS deployment; after tariff plan changes; quarterly fraud audit",
        "pass_criteria": [
            "OCS rejects CCR with invalid/missing mandatory AVPs",
            "Session-Id replay rejected (duplicate detection active)",
            "Quota inflation attempt returns DIAMETER_UNABLE_TO_COMPLY",
            "ASR injection rejected from non-authorized origin",
        ],
        "fail_criteria": [
            "OCS grants inflated quota from crafted CCA",
            "Replayed CCR-I creates duplicate charging session",
            "AVP injection modifies balance without authorization",
        ],
        "evidence_format": "OCS charging log / Diameter trace / CDR comparison",
        "severity": "Critical",
        "references": ["GSMA FS.19", "3GPP TS 32.299 (Gy)", "TS 29.219", "GSMA FASG Fraud guidelines"],
        "standard": "GSMA FS.19 | 3GPP TS 32.299 | 3GPP TS 29.219",
        "severity_if_fail": "Critical",
        "duration": "30–60 minutes",
        "environment": "Active — OCS/Gy lab",
    },

    # ================================================================
    # ACTIVE EXPLOITATION — DoS/DDoS
    # ================================================================

    "TELSEC-DOS-001": {
        "title": "SS7 MAP Reset / MSC-VLR Mass Deregistration",
        "purpose": "Verify MSC/VLR and SS7 firewall prevent bulk MAP_RESET attacks causing mass service outage",
        "what_tested": "MAP Reset operation; MSC subscriber deregistration defense; SS7 rate limiting",
        "preconditions": [
            "SS7 firewall with rate limiting rules active",
            "MSC/VLR with subscriber base (simulated)",
            "STP gateway logging enabled",
            "Alerting system connected to NOC/SOC",
        ],
        "execution_steps": [
            "1. Send single MAP_RESET to MSC and observe response",
            "2. Ramp up MAP_RESET rate: 100 → 1000 → 10000 msg/sec",
            "3. Simultaneously send MAP_CANCEL_LOCATION for multiple IMSIs",
            "4. Measure: % subscribers deregistered within 60 seconds",
            "5. Test STP failover response under flood",
            "6. Attempt from spoofed OPC (Origin Point Code)",
            "7. Test recovery time after attack cessation",
        ],
        "where_tested": "SS7 Firewall / STP / MSC-VLR",
        "when_to_run": "Annual resilience testing; after MSC software upgrade; disaster recovery drills",
        "pass_criteria": [
            "SS7 firewall rate-limits MAP_RESET below threshold (<10/min from single GT)",
            "MAP_RESET from unknown OPC blocked immediately",
            "Less than 0.1% of subscribers affected",
            "SOC alert triggered within 30 seconds of attack start",
        ],
        "fail_criteria": [
            "Mass subscriber deregistration (>5% base) within 60 seconds",
            "No rate limiting on MAP_RESET operations",
            "No alert generated at NOC/SOC",
            "STP crashes or becomes unreachable",
        ],
        "evidence_format": "MSC subscriber count before/after / STP counters / Firewall rate-limit log",
        "severity": "Critical",
        "references": ["GSMA FS.11 Cat-2", "ETSI TS 102 656", "3GPP TS 29.002", "ITU-T X.805 Availability"],
        "standard": "GSMA FS.11 Cat-2 | ETSI TS 102 656 | ITU-T X.805",
        "severity_if_fail": "Critical",
        "duration": "20–45 minutes",
        "environment": "Active — NOC standby required",
    },

    "TELSEC-DOS-002": {
        "title": "Diameter DWR Storm Peer Exhaustion",
        "purpose": "Verify DRA handles Diameter watchdog flooding without service degradation",
        "what_tested": "Diameter DWR/DWA watchdog mechanism; DRA connection table and processing capacity",
        "preconditions": [
            "DRA deployed on Diameter interconnect interfaces",
            "DOIC per RFC 7683 configured",
            "Diameter peer connection limits defined",
            "Legitimate Diameter traffic baseline measured",
        ],
        "execution_steps": [
            "1. Establish maximum allowed Diameter peer connections to DRA",
            "2. Flood DWR messages at 10,000/sec from all connections",
            "3. Monitor DRA CPU, memory, connection table fill rate",
            "4. Simultaneously send legitimate S6a AIR from test MME",
            "5. Measure latency degradation on legitimate traffic",
            "6. Test DRA DOIC OLR (Overload-Report) generation",
            "7. Attempt new peer connections beyond limit during flood",
        ],
        "where_tested": "DRA / HSS S6a/S6d / DRA DOIC module",
        "when_to_run": "Post-DRA deployment; capacity planning tests; after peering agreement changes",
        "pass_criteria": [
            "DRA activates DOIC and sends OLR to overloaded peers",
            "Legitimate S6a AIR processed within +20% of baseline latency",
            "New peer connections rejected above configured limit",
            "DRA does not crash or restart during flood",
        ],
        "fail_criteria": [
            "Legitimate authentication requests dropped/timeout",
            "DRA crashes, reboots, or loses peer connections",
            "No OLR generated; no overload protection activated",
        ],
        "evidence_format": "DRA connection metrics / S6a latency graph / OLR message capture",
        "severity": "High",
        "references": ["RFC 7683 (DOIC)", "GSMA FS.19", "3GPP TS 29.272", "RFC 3539"],
        "standard": "RFC 7683 (DOIC) | GSMA FS.19 | 3GPP TS 29.272",
        "severity_if_fail": "High",
        "duration": "20–40 minutes",
        "environment": "Active — Diameter lab",
    },

    # ================================================================
    # ACTIVE EXPLOITATION — AUTHENTICATION ATTACKS
    # ================================================================

    "TELSEC-AUTH-001": {
        "title": "2G/3G Downgrade Attack via Protocol Fallback",
        "purpose": "Verify network policy blocks forced downgrade from 4G/5G to 2G/3G",
        "what_tested": "Network-side downgrade protection; UE capability filtering at MME/AMF",
        "preconditions": [
            "Network has 2G/3G layers active in same coverage area",
            "Test UE with 4G/5G capability in 4G/5G coverage",
            "MME/AMF configured with minimum ciphering algorithm policy",
        ],
        "execution_steps": [
            "1. Test UE attaches to 4G network normally",
            "2. Send RRC Release with redirect to 2G ARFCN from rogue eNB",
            "3. Measure: does UE fall back to 2G GERAN?",
            "4. On 2G: send A3/A8 auth challenge without AUTN",
            "5. Capture: does UE respond with SRES without verifying network?",
            "6. Attempt 3G to 2G downgrade (UMTS → GSM)",
            "7. Test Network Slicing restriction of 2G fallback in 5G NSA",
        ],
        "where_tested": "eNB/gNB / MME/AMF / UE (simulated)",
        "when_to_run": "Network launch; after RAN configuration changes; after UE software updates",
        "pass_criteria": [
            "Rogue eNB redirect to 2G rejected by UE (if barred)",
            "MME/AMF refuses re-attach on 2G if policy set",
            "UE rejects auth challenge without AUTN",
            "SQN/AUTN mismatch triggers SYNC_FAILURE not silent failure",
        ],
        "fail_criteria": [
            "UE successfully falls back to 2G on rogue signal",
            "2G auth succeeds without network authentication (AUTN absent)",
            "IMSI captured in cleartext on 2G link",
        ],
        "evidence_format": "UE QXDM/NEMO log / Core network trace / Protocol capture on air interface",
        "severity": "Critical",
        "references": ["3GPP TS 33.102 §6.3", "TS 33.401 §7.2", "TS 33.501 §6.1", "GSMA FS.11"],
        "standard": "3GPP TS 33.102 | 3GPP TS 33.501 | GSMA FS.11",
        "severity_if_fail": "Critical",
        "duration": "30–60 minutes",
        "environment": "Active — RAN lab with 2G/3G/4G/5G coverage",
    },

    "TELSEC-AUTH-002": {
        "title": "Diameter S6a AIR Spoofing (Authentication Info Request)",
        "purpose": "Verify HSS rejects AIR from unregistered/rogue MME",
        "what_tested": "Diameter S6a AIR/AIA; HSS peer validation",
        "preconditions": [
            "HSS with S6a interface active",
            "DRA with peer whitelist configured",
            "Rogue test Diameter node configured",
            "Target IMSI registered in HSS",
        ],
        "execution_steps": [
            "1. From rogue node: send Diameter AIR with target IMSI",
            "2. Attempt with valid-format Origin-Host",
            "3. Without mTLS: attempt plain TCP Diameter connection",
            "4. With mTLS: attempt with invalid/self-signed certificate",
            "5. Send AIR with IMSI not in HSS (negative test)",
            "6. Flood HSS with rapid AIR requests (rate limit test)",
        ],
        "where_tested": "HSS / DRA / Diameter Firewall (S6a)",
        "when_to_run": "Post-HSS deployment; after MME pool changes; after certificate rotation",
        "pass_criteria": [
            "DRA blocks AIR from unregistered Origin-Host",
            "HSS rejects connection without valid mTLS certificate",
            "Self-signed certificate causes TLS handshake failure",
            "DIAMETER_ERROR_USER_UNKNOWN for invalid IMSI",
        ],
        "fail_criteria": [
            "HSS returns authentication vectors to rogue MME",
            "Plain TCP Diameter connection accepted",
            "Invalid certificate accepted (mTLS not enforced)",
        ],
        "evidence_format": "HSS access log / DRA peer log / TLS handshake trace",
        "severity": "Critical",
        "references": ["3GPP TS 29.272", "TS 33.210 (Network Domain Security)", "GSMA FS.19", "RFC 5746"],
        "standard": "3GPP TS 29.272 | 3GPP TS 33.210 | GSMA FS.19",
        "severity_if_fail": "Critical",
        "duration": "20–40 minutes",
        "environment": "Active — Diameter S6a lab",
    },

    # ================================================================
    # 5G SECURITY — SBA INTERFACE
    # ================================================================

    "TELSEC-5G-SBA-001": {
        "title": "Unauthorized NF Registration via NRF API",
        "purpose": "Verify NRF rejects NF registration requests from unauthorized network functions",
        "what_tested": "Nnrf_NFManagement_NFRegister API; NRF access control; OAuth 2.0 client auth at NRF",
        "preconditions": [
            "5G core deployed with NRF as NF registry",
            "mTLS enforced on all SBI interfaces per TS 33.501 §13",
            "OAuth 2.0 client credentials configured",
            "Test rogue NF with self-signed certificate",
        ],
        "execution_steps": [
            "1. Send HTTP/2 PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId} with NF profile body",
            "2. Attempt without OAuth token (no Authorization header)",
            "3. Attempt with expired OAuth token",
            "4. Attempt with valid token but wrong NF-Type scope",
            "5. Attempt with self-signed mTLS certificate",
            "6. Attempt NF registration with existing legitimate NF's nfInstanceId",
            "7. Register rogue AMF and attempt to serve UEs",
        ],
        "where_tested": "NRF / SCP (Service Communication Proxy) / API Gateway",
        "when_to_run": "5G core deployment; after NRF software upgrade; after adding new NF instances",
        "pass_criteria": [
            "NRF returns HTTP 401 without valid OAuth token",
            "HTTP 403 for wrong NF-Type scope in token",
            "mTLS handshake failure with invalid certificate",
            "HTTP 409 Conflict for nfInstanceId collision",
            "Rogue AMF registration blocked and SOC alerted",
        ],
        "fail_criteria": [
            "NRF accepts NF registration without OAuth token",
            "Self-signed certificate accepted in mTLS handshake",
            "nfInstanceId collision overwrites legitimate NF profile",
        ],
        "evidence_format": "NRF access log / SBI trace (HTTP/2) / OAuth token audit log / mTLS certificate log",
        "severity": "Critical",
        "references": [
            "3GPP TS 33.501 §13.1", "TS 29.510 (NRF)",
            "GSMA FS.40 §5.4", "RFC 6749 (OAuth 2.0)", "ETSI NFV SEC-012",
        ],
        "standard": "3GPP TS 33.501 §13 | TS 29.510 | GSMA FS.40",
        "severity_if_fail": "Critical",
        "duration": "20–40 minutes",
        "environment": "Active — 5GC lab with NRF",
    },

    "TELSEC-5G-SBA-002": {
        "title": "NF Service OAuth Token Replay / Scope Escalation",
        "purpose": "Verify NFs reject replayed or scope-escalated OAuth tokens",
        "what_tested": "OAuth 2.0 token validation at consumer NFs; token lifetime; scope binding",
        "preconditions": [
            "NRF/NF-Auth server issuing short-lived access tokens",
            "Token expiry configured (e.g., 300 seconds)",
            "Test token captured from legitimate NF exchange",
            "NF consumer configured to validate token claims",
        ],
        "execution_steps": [
            "1. Capture valid access token from AMF→UDM exchange",
            "2. Replay same token after expiry window (>300s)",
            "3. Replay token to different NF than intended audience",
            "4. Modify token scope claim (base64 decode, change, re-encode)",
            "5. Use AMF token to access SMF endpoint (cross-NF replay)",
            "6. Test token revocation: revoke token and retry API call",
            "7. Attempt JWT algorithm confusion: RS256 → HS256",
        ],
        "where_tested": "UDM / SMF / PCF / AUSF (as resource NFs)",
        "when_to_run": "Post-5G core deployment; after auth server changes",
        "pass_criteria": [
            "Expired token returns HTTP 401 Unauthorized",
            "Token presented to wrong audience returns HTTP 403",
            "Scope-modified token fails signature validation (HTTP 401)",
            "Revoked token rejected within propagation time",
        ],
        "fail_criteria": [
            "Expired token accepted beyond expiry window",
            "Token valid at unintended NF audience",
            "Scope escalation succeeds (subscriber data accessed)",
        ],
        "evidence_format": "HTTP/2 API trace / OAuth server audit log / Token introspection log",
        "severity": "Critical",
        "references": [
            "3GPP TS 33.501 §13.3", "TS 29.510 §6.1.6",
            "RFC 7519 (JWT)", "RFC 7009 (Token Revocation)", "CVE-2015-9235",
        ],
        "standard": "3GPP TS 33.501 §13.3 | TS 29.510 | RFC 7519",
        "severity_if_fail": "Critical",
        "duration": "20–40 minutes",
        "environment": "Active — 5GC lab with OAuth2 server",
    },

    # ================================================================
    # 5G SECURITY — NETWORK SLICE
    # ================================================================

    "TELSEC-5G-SL-001": {
        "title": "Network Slice Isolation Verification",
        "purpose": "Verify user data, signaling, and resources of one slice cannot be accessed from another",
        "what_tested": "SMF/UPF slice isolation; AMF NSSAI enforcement; data plane isolation between N6 instances",
        "preconditions": [
            "Minimum two network slices provisioned (e.g., eMBB + URLLC)",
            "Test UE subscribed to Slice-A only (S-NSSAI-A)",
            "Slice-B traffic active with test data flow",
            "UPF configured with separate PFCP sessions per slice",
        ],
        "execution_steps": [
            "1. Attach test UE with Slice-A credentials",
            "2. Request PDU session establishment on Slice-B S-NSSAI",
            "3. Attempt to read Slice-B UPF traffic from Slice-A UPF",
            "4. Inject crafted PFCP message targeting Slice-B SEID from Slice-A SMF context",
            "5. Attempt to exhaust Slice-B resources from Slice-A UE",
            "6. Test NSSF: send manipulated NSSAI in Registration Request",
            "7. Verify audit trail: log cross-slice attempts",
        ],
        "where_tested": "AMF / NSSF / SMF (per slice) / UPF (per slice) / N6 interface",
        "when_to_run": "Slice commissioning; after slice policy changes; periodic isolation audit (quarterly)",
        "pass_criteria": [
            "PDU session on Slice-B rejected for Slice-A-only subscriber",
            "Cross-slice PFCP injection returns PFCP Session Not Found",
            "Resource exhaustion in one slice doesn't affect another",
            "Cross-slice access attempts logged and alerted",
        ],
        "fail_criteria": [
            "PDU session established on unauthorized slice",
            "Data from Slice-B visible in Slice-A UPF context",
            "NSSAI manipulation succeeds in slice assignment bypass",
        ],
        "evidence_format": "AMF slice assignment log / PFCP session table / UPF traffic capture per slice",
        "severity": "High",
        "references": ["3GPP TS 33.501 §A.9", "TS 23.501 §5.15", "GSMA FS.40 §6.2", "ENISA 5G §3.4"],
        "standard": "3GPP TS 33.501 §A.9 | TS 23.501 | GSMA FS.40",
        "severity_if_fail": "High",
        "duration": "30–60 minutes",
        "environment": "Active — multi-slice 5GC lab",
    },

    # ================================================================
    # 5G SECURITY — gNB INTERFACE
    # ================================================================

    "TELSEC-5G-GNB-001": {
        "title": "NG-AP (N2) Message Injection from Rogue gNB",
        "purpose": "Verify AMF rejects NGAP messages from unauthenticated gNBs",
        "what_tested": "NGAP InitialUEMessage / UEContextSetupRequest; AMF peer authentication; N2 interface security",
        "preconditions": [
            "AMF with N2 interface active",
            "Legitimate gNB registered with AMF",
            "IPSec/TLS on N2 interface configured",
            "Test rogue gNB simulator with spoofed gNB-ID",
        ],
        "execution_steps": [
            "1. Connect rogue gNB to AMF N2 interface (SCTP)",
            "2. Send NGAP NGSetupRequest with spoofed GlobalRANNodeID",
            "3. On success: inject InitialUEMessage with crafted NAS PDU",
            "4. Without IPSec: attempt plain SCTP connection to N2",
            "5. With expired certificate: attempt TLS handshake",
            "6. Send UEContextReleaseCommand for active UE context",
            "7. Inject PathSwitchRequest (forced handover to rogue gNB)",
        ],
        "where_tested": "AMF / N2 Interface / IPSec Gateway / SCTP transport layer",
        "when_to_run": "gNB commissioning; after AMF software upgrade; after adding new gNB",
        "pass_criteria": [
            "AMF rejects NGSetupRequest from unregistered gNB-ID",
            "Plain SCTP connection refused (IPSec mandatory)",
            "Expired certificate causes TLS handshake rejection",
            "PathSwitchRequest from rogue gNB rejected",
        ],
        "fail_criteria": [
            "Rogue gNB successfully completes NGSetup with AMF",
            "NAS PDU injected via rogue gNB reaches UDM/AUSF",
            "Plain N2 connection accepted (IPSec not enforced)",
        ],
        "evidence_format": "AMF NGAP log / IPSec SA establishment log / SCTP association trace",
        "severity": "Critical",
        "references": ["3GPP TS 38.413 (NGAP)", "TS 33.501 §9.2", "TS 33.511 §4.2", "O-RAN WG11 v4.0"],
        "standard": "3GPP TS 38.413 | 3GPP TS 33.501 | 3GPP TS 33.511",
        "severity_if_fail": "Critical",
        "duration": "30–60 minutes",
        "environment": "Active — 5G RAN lab with rogue gNB simulator",
    },

    "TELSEC-5G-GNB-002": {
        "title": "Xn Interface Handover Hijacking",
        "purpose": "Verify gNB-to-gNB Xn interface rejects unauthorized handover requests",
        "what_tested": "XnAP XnSetup / HandoverRequest; Xn interface IPSec; Source/Target gNB authentication",
        "preconditions": [
            "Two gNBs in Xn peering relationship",
            "IPSec on Xn interface configured",
            "UE with active session under Source gNB",
            "Rogue gNB simulator with valid-looking gNB-ID",
        ],
        "execution_steps": [
            "1. Rogue gNB sends XnSetupRequest to legitimate gNB",
            "2. On XnSetup success: send HandoverRequest for active UE",
            "3. Inject handover with modified security capabilities (downgrade UE algorithms)",
            "4. Attempt to strip AS security context in handover",
            "5. Replay HandoverRequest for already-completed handover",
        ],
        "where_tested": "gNB (source + target) / Xn Interface / IPSec GW",
        "when_to_run": "After Xn peering setup; after gNB software update",
        "pass_criteria": [
            "Rogue gNB XnSetup rejected (not in neighbor whitelist)",
            "Security capability downgrade in HO Request rejected",
            "Handover replay rejected (sequence number check)",
        ],
        "fail_criteria": [
            "Rogue gNB completes XnSetup and receives HO target role",
            "Algorithm downgrade in HO accepted",
            "UE security context lost/reset after handover",
        ],
        "evidence_format": "gNB XnAP log / IPSec SA log / UE security capability log",
        "severity": "High",
        "references": ["3GPP TS 38.423 (XnAP)", "TS 33.501 §6.7", "TS 33.511 §4.3", "O-RAN WG4 Security"],
        "standard": "3GPP TS 38.423 | 3GPP TS 33.501 | 3GPP TS 33.511",
        "severity_if_fail": "High",
        "duration": "30–45 minutes",
        "environment": "Active — 5G RAN lab with Xn peering",
    },

    # ================================================================
    # RECON & INTELLIGENCE
    # ================================================================

    "TELSEC-RECON-001": {
        "title": "IMSI/MSISDN Enumeration via MAP SRI",
        "purpose": "Determine exposure of subscriber routing information to external parties without authorization",
        "what_tested": "MAP SRI (Send-Routing-Info) at HLR/HGW; SS7 firewall category 2 filtering",
        "preconditions": [
            "SS7 firewall active on international and national interconnect",
            "SMS Home Routing (SHR) deployed",
            "Set of test MSISDNs (active, inactive, ported-out)",
        ],
        "execution_steps": [
            "1. Send MAP_SRI for active MSISDN — note response content",
            "2. Send MAP_SRI for inactive MSISDN — note error code",
            "3. Send MAP_SRI for ported-out number — note NRTRDE response",
            "4. Enumerate range: sequential MSISDN batch (100 numbers)",
            "5. Measure: is IMSI returned vs. anonymized routing number?",
            "6. Test SHR: does home routing return real MSC or virtual?",
            "7. Measure time between requests before rate-limit trigger",
        ],
        "where_tested": "HLR / SMS Home Routing / SS7 Firewall / STP",
        "when_to_run": "Post-SHR deployment; post-interconnect change",
        "pass_criteria": [
            "SHR returns anonymized MSRN, not real MSC/IMSI",
            "GSMA IMSI-anonymization active (SMSHRN used)",
            "Enumeration rate-limited after N requests/minute",
            "Inactive MSISDN returns MAP_ERROR not timing info",
        ],
        "fail_criteria": [
            "Real IMSI returned in SRI response",
            "Real MSC address exposed (enables location tracking)",
            "No rate limiting on bulk enumeration",
        ],
        "evidence_format": "MAP trace / SHR routing table / Firewall rate-limit log",
        "severity": "High",
        "references": ["GSMA FS.11 Cat-2", "FS.26 §4.2", "IR.70 (SHR)", "3GPP TS 29.002 §7.3.1"],
        "standard": "GSMA FS.11 Cat-2 | GSMA FS.26 | GSMA IR.70",
        "severity_if_fail": "High",
        "duration": "20–40 minutes",
        "environment": "Active — SS7 interconnect lab",
    },

    "TELSEC-RECON-002": {
        "title": "STP/DRA Node Discovery via SCCP/Diameter",
        "purpose": "Map internal SS7/Diameter topology from interconnect to expose network architecture",
        "what_tested": "SCCP management (SCMG) responses; Diameter CEX; STP routing table exposure",
        "preconditions": [
            "Access to SS7/Diameter interconnect test port",
            "Point code and GT of at least one known STP node",
            "SCCP management messages not filtered",
        ],
        "execution_steps": [
            "1. Send SCCP Subsystem-Status-Test to gateway STP",
            "2. Observe SSA/SSP response and extract subsystem info",
            "3. Send ANSI/ITU Capability messages to discover adjacent STPs",
            "4. Diameter: send CER to DRA and inspect CEX capabilities",
            "5. Extract: supported applications, vendor IDs, Origin-Realm",
            "6. Attempt Diameter route discovery via DWR to peer tables",
        ],
        "where_tested": "STP / DRA / SS7 Gateway / Diameter Border Agent",
        "when_to_run": "Pre-engagement reconnaissance phase; network topology validation audit",
        "pass_criteria": [
            "STP returns only allowed SSA for legitimate subsystems",
            "Internal node addresses not exposed in error messages",
            "DRA Origin-Host reveals only public-facing FQDN",
        ],
        "fail_criteria": [
            "Internal STP/DRA node IPs/Point Codes exposed",
            "Full subsystem listing returned to external querier",
            "Diameter route table extractable from CEX capabilities",
        ],
        "evidence_format": "SCCP/Diameter packet capture / STP MIB query log",
        "severity": "Medium",
        "references": ["GSMA FS.07 §4", "FS.11 §4.3", "ITU-T Q.714", "3GPP TS 29.173", "RFC 6733 §5.3"],
        "standard": "GSMA FS.07 | GSMA FS.11 | ITU-T Q.714",
        "severity_if_fail": "Medium",
        "duration": "15–30 minutes",
        "environment": "Active — SS7/Diameter interconnect access",
    },

    # ================================================================
    # PROTOCOL FUZZING
    # ================================================================

    "TELSEC-FUZZ-001": {
        "title": "ASN.1 BER-Encoded MAP Message Fuzzing",
        "purpose": "Identify parsing vulnerabilities in HLR/MSC MAP stack from malformed ASN.1-encoded messages",
        "what_tested": "MAP codec robustness; HLR/MSC error handling for malformed ASN.1 BER TLV structures",
        "preconditions": [
            "Test HLR/MSC accessible on SS7 lab interconnect",
            "Protocol analyzer connected to capture responses",
            "Baseline MAP operation confirmed working",
            "Node health monitoring active (CPU, memory, process state)",
        ],
        "execution_steps": [
            "1. Capture valid MAP_ATI message as baseline",
            "2. Fuzz Phase 1 — Boundary: max-length TAG values",
            "3. Fuzz Phase 2 — Truncated: incomplete TLV sequences",
            "4. Fuzz Phase 3 — Type confusion: wrong ASN.1 type for field",
            "5. Fuzz Phase 4 — Nested: deeply nested SEQUENCE structures",
            "6. Fuzz Phase 5 — Encoding: indefinite-length BER forms",
            "7. Monitor: node stability, crash, unexpected reset, high CPU",
            "8. After each crash: document message that triggered it",
        ],
        "where_tested": "HLR / MSC / SGSN / GSM-MAP codec layer",
        "when_to_run": "Before accepting new NE software version; after MAP codec updates",
        "pass_criteria": [
            "Node returns MAP_ERROR or TCAP ABORT for all malformed messages",
            "No process restart/crash throughout fuzzing campaign",
            "CPU/memory within normal range (±10% of baseline)",
        ],
        "fail_criteria": [
            "Node crashes or restarts due to malformed input",
            "Unhandled exception in MAP stack (core dump)",
            "Memory leak observed (RSS grows >20% over test period)",
        ],
        "evidence_format": "Fuzzing tool output log / Node process health graph / Core dump / Wireshark capture",
        "severity": "High",
        "references": ["3GPP TS 29.002", "ITU-T Q.773", "GSMA FS.11 §5", "OWASP Fuzzing Guide", "NIST SP 800-115"],
        "standard": "3GPP TS 29.002 | ITU-T Q.773 | GSMA FS.11 §5",
        "severity_if_fail": "High",
        "duration": "1–4 hours",
        "environment": "Active — isolated HLR/MSC lab node",
    },

    "TELSEC-FUZZ-002": {
        "title": "Diameter AVP Injection and Boundary Fuzzing",
        "purpose": "Identify AVP processing flaws in HSS/PCRF/OCS",
        "what_tested": "Diameter AVP parser; mandatory AVP enforcement; AVP value boundary checking",
        "preconditions": [
            "Test Diameter node with valid peer connection to target",
            "Base valid CCR or AIR message confirmed working",
            "Target NE health monitoring active",
        ],
        "execution_steps": [
            "1. Inject unknown Vendor-Specific AVP (random Vendor-Id)",
            "2. Set mandatory bit on non-mandatory AVP",
            "3. Send duplicate copies of single-occurrence mandatory AVPs",
            "4. Overflow: AVP length field larger than actual data",
            "5. Underflow: AVP length field smaller than data",
            "6. Grouped AVP with 50+ levels of nesting",
            "7. UTF-8 invalid byte sequences in string AVPs",
            "8. Negative/zero values in unsigned integer AVPs",
        ],
        "where_tested": "HSS / OCS / PCRF / DRA / S6a|Gx|Gy interfaces",
        "when_to_run": "NE software acceptance testing; annual pentest",
        "pass_criteria": [
            "Unknown mandatory AVP returns DIAMETER_AVP_UNSUPPORTED (5001)",
            "Duplicate AVP returns DIAMETER_AVP_OCCURS_TOO_MANY_TIMES (5009)",
            "Overflow AVP rejected with DIAMETER_INVALID_AVP_LENGTH (5014)",
            "No crash or service disruption for all fuzz cases",
        ],
        "fail_criteria": [
            "Any fuzz input causes NE crash/restart",
            "Invalid AVP accepted and processed without error code",
            "Buffer overflow leads to memory corruption",
        ],
        "evidence_format": "Diameter trace with Result-Code per fuzz case / NE health graph",
        "severity": "High",
        "references": ["RFC 6733 §4.1", "3GPP TS 29.272", "GSMA FS.19 §6"],
        "standard": "RFC 6733 §4.1 | 3GPP TS 29.272 | GSMA FS.19",
        "severity_if_fail": "High",
        "duration": "1–4 hours",
        "environment": "Active — isolated Diameter NE lab",
    },

    "TELSEC-FUZZ-003": {
        "title": "5G HTTP/2 SBI JSON Schema Fuzzing",
        "purpose": "Identify API vulnerabilities in 5G NFs from malformed JSON payloads",
        "what_tested": "NF REST API input validation; JSON parser robustness; OpenAPI schema enforcement",
        "preconditions": [
            "Valid OAuth token for target NF API",
            "OpenAPI spec for target NF available (from 3GPP TS 29.5xx)",
            "HTTP/2 client tool configured for SBI testing",
            "Target NF health monitoring active",
        ],
        "execution_steps": [
            "1. Send valid API request as baseline",
            "2. Fuzz: missing required JSON fields",
            "3. Fuzz: extra unexpected JSON fields",
            "4. Fuzz: wrong data types (integer where string expected)",
            "5. Fuzz: extremely long string values (>65535 chars)",
            "6. Fuzz: deeply nested JSON objects (100+ levels)",
            "7. Fuzz: SQL/NoSQL injection in string fields",
            "8. Fuzz: null bytes, Unicode surrogates in string values",
            "9. Fuzz: HTTP/2 stream multiplexing abuse (rapid open/close)",
        ],
        "where_tested": "AMF/SMF/UDM/AUSF/NRF/NEF REST APIs (SBI)",
        "when_to_run": "5G core NF software acceptance; API version upgrade",
        "pass_criteria": [
            "Missing required fields return HTTP 400 Bad Request",
            "Schema violations return HTTP 422 Unprocessable Entity",
            "Injection attempts return HTTP 400 (no DB error leaked)",
            "No NF restart/crash throughout fuzzing campaign",
        ],
        "fail_criteria": [
            "NF crashes on malformed JSON input",
            "SQL/NoSQL error message leaked in HTTP response body",
            "NF processes requests with missing mandatory fields",
        ],
        "evidence_format": "HTTP/2 API trace / NF log with error responses / NF process health metrics",
        "severity": "High",
        "references": ["3GPP TS 29.501 (SBI)", "TS 29.510", "OWASP API Security Top 10", "RFC 9113 (HTTP/2)"],
        "standard": "3GPP TS 29.501 | OWASP API Top 10 | RFC 9113",
        "severity_if_fail": "High",
        "duration": "1–4 hours",
        "environment": "Active — 5GC NF lab",
    },

    # ================================================================
    # COMPLIANCE MAPPING
    # ================================================================

    "TELSEC-COMP-001": {
        "title": "GSMA FS.11 Category 1-3 Firewall Completeness Check",
        "purpose": "Verify SS7 firewall implements all mandatory FS.11 Cat-1, Cat-2, Cat-3 filtering rules",
        "what_tested": "SS7 firewall rule completeness; all FS.11 attack categories",
        "preconditions": [
            "SS7 firewall deployed and policy file version obtained",
            "FS.11 v6.0 (or latest) checklist available",
            "Test tool capable of generating all FS.11 threat scenarios",
            "Firewall logging configured per FS.11 §8 requirements",
        ],
        "execution_steps": [
            "1. For each FS.11 Category 1 item: generate test message and verify BLOCK + correct MAP_ERROR",
            "2. For each Category 2 item: verify firewall action (block/alert/log per policy)",
            "3. For Category 3: send location-correlated message sequences and verify detection",
            "4. Check firewall logs: all blocked messages logged with source GT, destination, operation, timestamp",
            "5. Verify: alerts sent to SOC for Category 1/2 violations",
            "6. Generate compliance report: % rules tested, % passing",
        ],
        "where_tested": "SS7 Firewall / STP / All interconnect-facing interfaces",
        "when_to_run": "Post-deployment; after any firewall policy update; annual compliance audit",
        "pass_criteria": [
            "100% of FS.11 Category 1 rules implemented and tested",
            "All Category 2 rules implemented per operator policy",
            "All blocked events logged with mandatory fields",
            "SOC alert integration confirmed working",
        ],
        "fail_criteria": [
            "Any FS.11 Category 1 rule not implemented",
            "Blocked events not logged or log fields incomplete",
            "No SOC alert for Category 1 violations",
        ],
        "evidence_format": "Firewall policy diff vs FS.11 checklist / Block log export / SOC alert screenshot",
        "severity": "Critical",
        "references": [
            "GSMA FS.11 v6.0", "GSMA FS.19 v4.0", "GSMA FS.40 v3.0",
            "3GPP TS 33.117 §4.2", "TEC/DOT TSTP framework", "TRAI Telecom Security Regulations",
        ],
        "standard": "GSMA FS.11 v6.0 | 3GPP TS 33.117 | TEC/DOT ITSAR",
        "severity_if_fail": "Critical",
        "duration": "1–2 days",
        "environment": "Active — Operator SS7 production interconnect (read-only audit mode)",
    },
}


def get_tstp(test_id: str) -> "Dict[str, Any] | None":
    """Return TSTP entry for a given test ID, or None if not found."""
    return TSTP.get(test_id)


def get_all_tstp_ids() -> "list[str]":
    """Return all test IDs that have TSTP entries."""
    return list(TSTP.keys())
