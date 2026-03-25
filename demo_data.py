"""
TelSec - Demo Data Generator
==============================
Generates realistic simulated findings for cloud demo mode.
These represent real-world telecom vulnerabilities discovered
in authorized penetration tests (sanitized, no real target data).

Used when:
  - No real SS7/LTE/5G target is configured
  - DEMO_MODE=true in environment
  - Running on Streamlit Community Cloud
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any


def _ts(offset_seconds: int) -> str:
    """Return ISO timestamp offset from now."""
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


# ---------------------------------------------------------------------------
# Realistic pre-built CVE-mapped findings
# ---------------------------------------------------------------------------

DEMO_FINDINGS: List[Dict[str, Any]] = [

    # ===================== 2G / GSM =====================
    {
        "test_id": "GSM-002",
        "name": "A5/0 Null Cipher Negotiation Detected",
        "generation": "2G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cve": "CVE-2013-4747",
        "gsma_ref": "FS.11 Cat.1",
        "threegpp_ref": "TS 33.102 §6.1",
        "affected_component": "GSM BTS / MS Ciphering Mode",
        "finding": (
            "The BTS at 935.2 MHz (ARFCN 1, LAC 1234, CellID 5678) negotiated "
            "A5/0 (null cipher) with the test MS. All SDCCH and TCH traffic "
            "is transmitted unencrypted. Captured 47 SDCCH frames in cleartext."
        ),
        "impact": (
            "Any attacker with a ≥15 USD RTL-SDR dongle can passively intercept "
            "all voice calls and SMS messages within range (~2km urban, ~10km rural)."
        ),
        "recommendation": (
            "1. Disable A5/0 in BSC configuration immediately. "
            "2. Enforce minimum A5/1; prefer A5/3 (KASUMI). "
            "3. Alert if any MS attempts to negotiate A5/0."
        ),
        "raw_output": "grgsm_livemon: SDCCH frame captured\nCiphering Mode Command: A5/0\nIMSI: 404300000000XXX (redacted)\nTMSI: 0xDEAD1234",
        "tool_used": "gr-gsm (simulated)",
        "duration_seconds": 45.2,
        "timestamp": _ts(-3600),
    },
    {
        "test_id": "GSM-001",
        "name": "GSM Cell Discovery — 4 BTSes Found",
        "generation": "2G",
        "status": "PASS",
        "severity": "INFO",
        "cvss_score": 0.0,
        "gsma_ref": "FS.11",
        "threegpp_ref": "TS 45.005",
        "affected_component": "GSM BTS / BCCH",
        "finding": "Discovered 4 GSM cells in GSM900/1800 bands. All match authorized cell list.",
        "recommendation": "Maintain authorized cell database and run weekly scans.",
        "raw_output": "kal -s GSM900\nchan: 1 (935.2MHz) ARFCN:1 MCC:404 MNC:30 LAC:1234\nchan: 15 (937.2MHz) ARFCN:15 MCC:404 MNC:30 LAC:1234\nchan: 47 (941.4MHz) ARFCN:47 MCC:404 MNC:45 LAC:5678\nchan: 62 (943.4MHz) ARFCN:62 MCC:404 MNC:45 LAC:5678",
        "tool_used": "kalibrate-rtl (simulated)",
        "duration_seconds": 62.0,
        "timestamp": _ts(-3700),
    },
    {
        "test_id": "GSM-003",
        "name": "IMSI Transmitted in Cleartext",
        "generation": "2G",
        "status": "FAIL",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "gsma_ref": "FS.11 Cat.1",
        "threegpp_ref": "TS 33.102 §6.2",
        "affected_component": "GSM MM Layer / SDCCH",
        "finding": (
            "Identity Response (IMSI) captured in cleartext on SDCCH during initial "
            "attach. Network did not assign TMSI on first Location Update, causing "
            "IMSI to be retransmitted on subsequent attaches."
        ),
        "impact": "Subscriber IMSI permanently linked to physical location — enables tracking.",
        "recommendation": (
            "Configure VLR to assign TMSI immediately on first successful attach. "
            "Verify TMSI assignment in Location Update Accept messages."
        ),
        "raw_output": "IDENTITY RESPONSE\n  IMSI: 404xxxxxxxxxx (redacted)\n  Frame: 0x054800...",
        "tool_used": "gr-gsm (simulated)",
        "duration_seconds": 32.1,
        "timestamp": _ts(-3650),
    },

    # ===================== 3G / SS7 =====================
    {
        "test_id": "SS7-002",
        "name": "Subscriber Location Disclosed via sendRoutingInfo",
        "generation": "3G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cve": "CVE-2014-3814",
        "gsma_ref": "FS.11 Cat.1",
        "threegpp_ref": "TS 29.002 §7.6.2",
        "affected_component": "HLR / sendRoutingInfo-ForSM",
        "finding": (
            "sendRoutingInfo MAP probe returned real-time subscriber location: "
            "E.212→E.214 IMSI resolution succeeded. Response contained VLR address "
            "(SS7 GT: 919xxxxxxxx), allowing cell-level location derivation. "
            "No authentication challenge issued to the requesting entity."
        ),
        "impact": (
            "Any SS7-interconnected entity globally can track any subscriber's "
            "real-time location to within ~500m without the subscriber's knowledge."
        ),
        "recommendation": (
            "1. Deploy GSMA FS.11 compliant SS7 firewall blocking unsolicited SRI-SM. "
            "2. Distinguish MTC-SRI (legitimate) from tracking SRI via correlation. "
            "3. Implement GSMA IR.82 security settings immediately."
        ),
        "raw_output": "SigPloit SRI probe:\nMSISDN: +91xxxxxxxxxx -> IMSI: 404xxxxxxxxxx\nVLR-number: +919xxxxxxxx\nMSC: 404-030-xxxxx\nreturned: location-info PRESENT",
        "tool_used": "SigPloit (simulated)",
        "duration_seconds": 3.4,
        "timestamp": _ts(-3500),
    },
    {
        "test_id": "SS7-009",
        "name": "Authentication Vectors Returned Without Auth",
        "generation": "3G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cve": "CVE-2016-9929",
        "gsma_ref": "FS.11 Cat.2",
        "threegpp_ref": "TS 29.002 §9.1.9",
        "affected_component": "HLR / sendAuthentication-Info",
        "finding": (
            "HLR responded to sendAuthentication-Info MAP query with 5 authentication "
            "vectors (RAND/SRES/Kc triplets) for IMSI 404xxxxxxxxxx. No mutual "
            "authentication of the requesting MSC/SGSN was performed."
        ),
        "impact": "Attacker can derive Kc session key and decrypt intercepted GSM traffic.",
        "recommendation": (
            "Block sendAuthentication-Info from all entities not in the explicit "
            "HLR whitelist. This is a CRITICAL P0 — restrict immediately."
        ),
        "raw_output": "SEND-AUTHENTICATION-INFO-RES\n  RAND: a3f2b1e4...\n  SRES: 9d2c...\n  Kc:   7f3a1b...\n  (5 vectors returned)",
        "tool_used": "SigPloit (simulated)",
        "duration_seconds": 2.1,
        "timestamp": _ts(-3400),
    },
    {
        "test_id": "SS7-003",
        "name": "SMS Interception via forwardSM",
        "generation": "3G",
        "status": "WARNING",
        "severity": "CRITICAL",
        "cvss_score": 9.5,
        "gsma_ref": "FS.11 Cat.5",
        "threegpp_ref": "TS 29.002 §10.2",
        "affected_component": "SMSC / forwardSM / SRI-for-SM",
        "finding": (
            "SMS interception attack path is viable: SRI-for-SM responds with subscriber "
            "VLR without content filtering. forwardSM rerouting test (passive advisory) "
            "indicates SMSC does not validate source GT vs HLR-registered MSC."
        ),
        "recommendation": "Block GT spoofing on SS7 firewall. Require HLR-authenticated SMS routing.",
        "tool_used": "SigPloit (simulated)",
        "duration_seconds": 4.7,
        "timestamp": _ts(-3300),
    },
    {
        "test_id": "SS7-001",
        "name": "SCCP Firewall — GT Filter Bypassed",
        "generation": "3G",
        "status": "FAIL",
        "severity": "HIGH",
        "cvss_score": 8.6,
        "gsma_ref": "FS.11 Cat.0",
        "threegpp_ref": "TS 29.002",
        "affected_component": "SS7 SCCP Firewall",
        "finding": (
            "SCCP GT whitelist bypass achieved by spoofing source GT "
            "+44xxxxxxxxxx (UK roaming partner). Firewall only validates GT prefix "
            "(country code), not full E.164 address or SCCP CgPA correlation."
        ),
        "recommendation": "Upgrade firewall rules to full E.164 GT validation with CgPA/CdPA correlation.",
        "tool_used": "SigPloit (simulated)",
        "duration_seconds": 8.3,
        "timestamp": _ts(-3200),
    },

    # ===================== 4G / LTE =====================
    {
        "test_id": "LTE-003",
        "name": "Diameter S6a HSS Location Disclosure",
        "generation": "4G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "gsma_ref": "FS.19-D1",
        "threegpp_ref": "TS 29.272 clause 5.2",
        "affected_component": "LTE HSS / Diameter S6a",
        "finding": (
            "Update-Location-Request (ULR) sent without TLS to HSS on port 3868. "
            "HSS returned Update-Location-Answer with full subscription profile: "
            "MSISDN, QoS profile, APN list, and last-seen TAI (tracking area). "
            "Origin-Host not validated against whitelist."
        ),
        "impact": "Any IP-reachable entity can enumerate subscriber data from HSS.",
        "recommendation": "Mandate mTLS on all Diameter S6a. Validate Origin-Host against registered MME list.",
        "raw_output": "ULA [Result-Code: DIAMETER_SUCCESS]\n  Subscription-Data AVP present\n  MSISDN: 919xxxxxxxx\n  Last-TAI: MCC=404 MNC=30 TAC=0x1A2B\n  APN-Config: internet, ims",
        "tool_used": "SigPloit Diameter (simulated)",
        "duration_seconds": 5.8,
        "timestamp": _ts(-2800),
    },
    {
        "test_id": "LTE-006",
        "name": "EEA0 (Null Cipher) Accepted on NAS",
        "generation": "4G",
        "status": "FAIL",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "cve": "CVE-2019-2025",
        "gsma_ref": "TS33.401-E1",
        "threegpp_ref": "TS 33.401 §5.1.3",
        "affected_component": "LTE eNB / NAS Security Mode Command",
        "finding": (
            "eNB accepted EEA0 (null cipher) in Security Mode Command when test UE "
            "proposed UEA capability list of [EEA0, EEA1, EEA2]. Network selected "
            "EEA0 instead of least-preferred algorithm — configuration error. "
            "NAS messages transmitted without encryption during this session."
        ),
        "recommendation": "Set eNB/MME algorithm priority: EEA2 > EEA1 > never-accept EEA0 in production.",
        "tool_used": "srsRAN 4G (simulated)",
        "duration_seconds": 18.4,
        "timestamp": _ts(-2600),
    },
    {
        "test_id": "LTE-009",
        "name": "GTP-U TEID Prediction & Packet Injection",
        "generation": "4G",
        "status": "FAIL",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "gsma_ref": "FS.19-D1",
        "threegpp_ref": "TS 29.281",
        "affected_component": "LTE PGW/SGW / GTP-U",
        "finding": (
            "GTP-U TEID enumeration via sequential scanning succeeded. "
            "Injected 100-byte UDP payload into existing GTP tunnel (TEID=0x00001234) "
            "targeting SGW at 10.0.0.100:2152. Payload was successfully forwarded "
            "to UE without validation. No GTP-U source authentication in place."
        ),
        "recommendation": "Deploy IPSec on all N3/S1-U/S5-U GTP-U interfaces. Filter GTP to known SGW/PGW IPs.",
        "tool_used": "Scapy GTP-U (simulated)",
        "duration_seconds": 12.2,
        "timestamp": _ts(-2400),
    },
    {
        "test_id": "LTE-004",
        "name": "Diameter CCR Flood — PCRF Response Degraded",
        "generation": "4G",
        "status": "FAIL",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "gsma_ref": "FS.19-D1",
        "threegpp_ref": "TS 29.212",
        "affected_component": "LTE PCRF / Diameter Gx",
        "finding": (
            "1,000 Credit-Control-Request (CCR-I) messages flooded to PCRF over 10s. "
            "PCRF response latency increased from 8ms baseline to 847ms at 80 req/sec. "
            "No rate limiting detected on Gx interface. PCRF did not assert overload."
        ),
        "recommendation": "Implement Diameter overload control (RFC 7683) on Gx. Limit CCR rate per peer.",
        "tool_used": "SigPloit Diameter (simulated)",
        "duration_seconds": 25.0,
        "timestamp": _ts(-2200),
    },
    {
        "test_id": "LTE-001",
        "name": "LTE Cell Discovery — 3 eNBs Found",
        "generation": "4G",
        "status": "PASS",
        "severity": "INFO",
        "cvss_score": 0.0,
        "gsma_ref": "FS.11",
        "threegpp_ref": "TS 36.101",
        "affected_component": "LTE eNB / EARFCN",
        "finding": "Discovered 3 LTE eNBs. EARFCN: 1800 (B3), 2850 (B7), 6200 (B20). All match authorized list.",
        "recommendation": "Maintain authorized eNB/PCI database. Alert on new EARFCN appearances.",
        "tool_used": "LTE-Cell-Scanner (simulated)",
        "duration_seconds": 48.0,
        "timestamp": _ts(-3100),
    },

    # ===================== 5G / NR =====================
    {
        "test_id": "NR-002",
        "name": "SUCI Null Protection Scheme Detected (IMSI Exposed)",
        "generation": "5G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 8.7,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "gsma_ref": "TS33.501-A1",
        "threegpp_ref": "TS 33.501 §6.12.2",
        "affected_component": "5G UE / AMF / SUCI concealment",
        "finding": (
            "SUCI in registration request uses protection scheme 0 (null/no encryption). "
            "FMI (MSIN) transmitted in cleartext: suci-0-404-30-0-0-0-0000123456. "
            "AMF did not reject null-scheme SUCI — both UE and network misconfigured. "
            "IMSI permanently exposed in all registration messages."
        ),
        "impact": (
            "Passive NAS monitoring via rogue gNB can track any subscriberidentity "
            "without active attack. 5G privacy guarantees completely nullified."
        ),
        "recommendation": (
            "1. Configure UE USIM with ECIES public key (Profile A or B). "
            "2. Configure home network public key in AMF/UDM. "
            "3. AMF must reject null-scheme SUCI for non-emergency calls."
        ),
        "raw_output": "Registration Request:\n  SUCI: suci-0-404-30-0-0-0-0000123456\n  Scheme-ID: 0 (NULL — MSIN EXPOSED)\n  MSIN: 0000123456",
        "tool_used": "TelSec SUCI decoder + srsRAN 5G (simulated)",
        "duration_seconds": 6.2,
        "timestamp": _ts(-1800),
    },
    {
        "test_id": "NR-005",
        "name": "UDM REST API Accessible Without OAuth2 Token",
        "generation": "5G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "gsma_ref": "FS.40-5G1",
        "threegpp_ref": "TS 33.501 §13.3",
        "affected_component": "5G UDM / Nudm-UEAuthentication API",
        "finding": (
            "GET /nudm-uecm/v1/imsi-404300000000001/registrations returned HTTP 200 "
            "with full registration context (AMF address, TAI, PDU sessions) without "
            "any OAuth2 Bearer token in request. Origin NF validation missing."
        ),
        "impact": (
            "Any internet-accessible 5GC can have its entire subscriber database "
            "enumerated. Subscriber privacy catastrophically violated."
        ),
        "recommendation": (
            "Enforce OAuth2 client_credentials flow for all NF-to-NF SBA calls. "
            "NRF must issue tokens with proper scope and NF identity binding."
        ),
        "raw_output": "GET /nudm-uecm/v1/imsi-404300000000001/registrations HTTP/2 200\n{\"3gppRegistration\":{\"amfInstanceId\":\"xxxx\",\"guami\":{\"plmnId\":{\"mcc\":\"404\",\"mnc\":\"30\"},\"amfId\":\"cafe01\"},\"registrationResult\":\"3GPP_ACCESS\"}}",
        "tool_used": "httpx SBA prober (simulated)",
        "duration_seconds": 1.8,
        "timestamp": _ts(-1600),
    },
    {
        "test_id": "NR-006",
        "name": "NRF Returns Full NF Instance List Unauthenticated",
        "generation": "5G",
        "status": "FAIL",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "gsma_ref": "FS.40-5G1",
        "threegpp_ref": "TS 29.510 §5.2.2",
        "affected_component": "5G NRF / Nnrf-NFManagement API",
        "finding": (
            "GET http://nrf:7777/nnrf-nfm/v1/nf-instances returned all 12 NF instances "
            "including IP:port of AMF (29518), SMF (29502), UDM (29503), AUSF (29509). "
            "No authentication required. Full 5GC topology exposed to any HTTP client."
        ),
        "recommendation": "Restrict NRF /nf-instances to authenticated internal NFs. Apply network segmentation.",
        "raw_output": "HTTP/2 200\n[{\"nfInstanceId\":\"amf-01\",\"nfType\":\"AMF\",\"ipv4Addresses\":[\"10.0.0.1\"],\"allowedNfTypes\":[\"SMF\",\"PCF\"],...}]",
        "tool_used": "httpx SBA prober (simulated)",
        "duration_seconds": 0.9,
        "timestamp": _ts(-1500),
    },
    {
        "test_id": "NR-003",
        "name": "NAS 5G-EA0 Downgrade — Null Cipher Accepted",
        "generation": "5G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.3,
        "cve": "CVE-2019-25104",
        "gsma_ref": "FS.40-5G1",
        "threegpp_ref": "TS 33.501 §6.7.3",
        "affected_component": "5G AMF / NAS Security Mode Command",
        "finding": (
            "Security Mode Command sent with 5G-EA0 (null cipher) and 5G-IA0 "
            "(null integrity). Test UE accepted both. All subsequent NAS messages "
            "transmitted without confidentiality or integrity protection. "
            "Attack viable from rogue gNB position."
        ),
        "impact": "Full NAS plaintext exposure; registration, PDU session, and mobility messages interceptable.",
        "recommendation": "Configure AMF to mandate minimum 5G-EA1/5G-IA1. Never allow EA0/IA0 in production.",
        "tool_used": "srsRAN 5G (simulated)",
        "duration_seconds": 14.7,
        "timestamp": _ts(-1400),
    },
    {
        "test_id": "NR-008",
        "name": "SMF PDU Session Created Without Authorization",
        "generation": "5G",
        "status": "FAIL",
        "severity": "CRITICAL",
        "cvss_score": 9.0,
        "gsma_ref": "FS.40-5G1",
        "threegpp_ref": "TS 29.502",
        "affected_component": "5G SMF / Nsmf-PDUSession API",
        "finding": (
            "POST /nsmf-pdusession/v1/sm-contexts with fake SUPI returned HTTP 201 Created. "
            "SMF established PDU session for non-existent subscriber without AMF authorization check. "
            "Bearer token absent — zero authentication on session establishment API."
        ),
        "recommendation": "Mandatory OAuth2 on Nsmf-PDUSession. Validate AMF NF instance ID before processing.",
        "tool_used": "httpx SBA prober (simulated)",
        "duration_seconds": 2.3,
        "timestamp": _ts(-1300),
    },
    {
        "test_id": "NR-007",
        "name": "Network Slice Isolation — Cross-Slice Access Possible",
        "generation": "5G",
        "status": "WARNING",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "gsma_ref": "FS.37-R1",
        "threegpp_ref": "TS 33.501 §5.11",
        "affected_component": "5G AMF / NSSF / UPF",
        "finding": (
            "Test UE subscribed to S-NSSAI SST=1 (eMBB) successfully established "
            "PDU session in S-NSSAI SST=2 (URLLC — restricted to enterprise customers). "
            "NSSF allowed-NSSAI list not enforced at session establishment — "
            "only checked at registration."
        ),
        "recommendation": "NSSF must enforce S-NSSAI authorization at both registration and PDU session setup.",
        "tool_used": "UERANSIM (simulated)",
        "duration_seconds": 11.2,
        "timestamp": _ts(-1200),
    },
    {
        "test_id": "NR-001",
        "name": "5G AMF Port Scan — NG-AP Exposed",
        "generation": "5G",
        "status": "PASS",
        "severity": "INFO",
        "cvss_score": 0.0,
        "gsma_ref": "FS.40",
        "threegpp_ref": "TS 38.413",
        "affected_component": "5G AMF / NG-AP",
        "finding": "AMF on 10.0.0.1 responds on 38412 (NGAP) and 29518 (Namf). Restricted to lab gNB IP.",
        "recommendation": "Confirm ACL restricts 38412 to authorized gNB IPs only.",
        "tool_used": "nmap (simulated)",
        "duration_seconds": 8.4,
        "timestamp": _ts(-2000),
    },
]




def get_demo_findings(
    generations: list[str] | None = None,
    include_passes: bool = True,
) -> list[dict]:
    """
    Return demo findings, optionally filtered by generation.

    Args:
        generations: List of ['2G','3G','4G','5G'] to include. None=all.
        include_passes: Include PASS/INFO results.

    Returns:
        List of finding dicts sorted by CVSS descending.
    """
    findings = DEMO_FINDINGS
    if generations:
        findings = [f for f in findings if f["generation"] in generations]
    if not include_passes:
        findings = [f for f in findings if f["status"] not in ("PASS", "SKIPPED")]
    return sorted(findings, key=lambda f: f.get("cvss_score", 0), reverse=True)


def get_demo_cells() -> list[dict]:
    """Return simulated discovered cells for topology/UI display."""
    return [
        {"arfcn": 1, "freq": "935.2 MHz", "band": "GSM900", "mcc": "404", "mnc": "30", "lac": "1234", "cell_id": "5678"},
        {"arfcn": 15, "freq": "937.2 MHz", "band": "GSM900", "mcc": "404", "mnc": "30", "lac": "1234", "cell_id": "5679"},
        {"earfcn": 1800, "freq": "1815 MHz", "band": "B3", "pci": 42, "rsrp": -85},
        {"earfcn": 2850, "freq": "2680 MHz", "band": "B7", "pci": 17, "rsrp": -92},
        {"nr_arfcn": 520020, "freq": "3.5 GHz", "band": "n78", "pci": 501, "ss_rsrp": -78},
    ]
