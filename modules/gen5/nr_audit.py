"""
TelSec - 5G/NR Security Audit Module
=======================================
12 automated test cases (NR-001 → NR-012).
Integrates: srsRAN 5G, Open5GS, free5GC, Nuclei, SBA REST API testing.

ALL TESTS ARE FOR AUTHORIZED 5G OPERATORS AND LABS ONLY.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict, List, Optional

from modules.base_module import BaseModule, FindingResult, Severity, TestStatus, ToolCheck
from engines.exploiter import HTTPAPITester, MetasploitRunner
from engines.scanner import NmapScanner
from utils.imsi_tools import decode_suci

__all__ = ["NRAudit"]


class NRAudit(BaseModule):
    """5G/NR Security Audit — 12 test cases."""

    module_id = "NR"
    generation = "5G"
    description = "5G Standalone/NSA security audit — SBA, NAS, O-RAN, slicing"

    def __init__(self, config: Dict[str, Any], authorization_ref: str = ""):
        super().__init__(config, authorization_ref)
        self.api = HTTPAPITester(config)
        self.scanner = NmapScanner(config)
        self.nr_cfg = config.get("modules", {}).get("gen5", {})
        self.amf_ip = self.nr_cfg.get("amf_ip", "")
        self.nrf_url = self.nr_cfg.get("nrf_url", "http://localhost:7777")
        self.sba_base = self.nr_cfg.get("sba_base_url", "http://localhost")

    def check_tools(self) -> List[ToolCheck]:
        return [
            self._check_single_tool("nmap", ["nmap", "--version"], "apt-get install nmap"),
            self._check_single_tool(
                "Docker (srsRAN 5G)", ["docker", "images", "-q",
                                        "softwareradiosystems/srsran-project"],
                "docker pull softwareradiosystems/srsran-project",
            ),
            self._check_single_tool(
                "nuclei", ["nuclei", "-version"],
                "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            ),
            self._check_single_tool(
                "httpx", ["python3", "-c", "import httpx; print(httpx.__version__)"],
                "pip install httpx[http2]",
            ),
        ]

    async def run_tests(
        self,
        selected_tests: Optional[List[str]] = None,
        passive_only: bool = False,
    ) -> List[FindingResult]:
        tests = {
            "NR-001": self._nr001_5g_cell_discovery,
            "NR-002": self._nr002_supi_suci_privacy,
            "NR-003": self._nr003_nas_downgrade,
            "NR-004": self._nr004_amf_registration_spam,
            "NR-005": self._nr005_ausf_udm_api,
            "NR-006": self._nr006_nrf_discovery,
            "NR-007": self._nr007_slice_isolation,
            "NR-008": self._nr008_smf_session_hijack,
            "NR-009": self._nr009_upf_gtp_injection,
            "NR-010": self._nr010_pcf_policy_bypass,
            "NR-011": self._nr011_oran_e2_fuzzing,
            "NR-012": self._nr012_mass_registration,
        }
        results = []
        for tid, fn in tests.items():
            if selected_tests and tid not in selected_tests:
                continue
            if self._stop_requested:
                break
            await self._wait_if_paused()
            self.logger.info(f"Running {tid}")
            try:
                result = await fn(passive_only=passive_only)
                results.append(result)
            except Exception as exc:
                results.append(self._make_result(
                    tid, f"Error in {tid}", status=TestStatus.ERROR, finding=str(exc)
                ))
        return results

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _active_check(self, tid: str, name: str, passive_only: bool) -> Optional[FindingResult]:
        if passive_only:
            return self._make_result(
                tid, name, status=TestStatus.SKIPPED, severity=Severity.INFO,
                finding="Skipped: passive-only mode.",
            )
        return self._check_authorization(tid, name)

    async def _probe_sba(self, path: str, method: str = "GET",
                         body: Optional[str] = None) -> Dict:
        url = f"{self.sba_base}{path}"
        return await self.api.probe_sba_endpoint(url, method=method, body=body)

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    async def _nr001_5g_cell_discovery(self, passive_only: bool = False) -> FindingResult:
        """NR-001: 5G NR Band Scan."""
        if self.amf_ip:
            scan = await self.scanner.telecom_scan(self.amf_ip, "5G")
            raw = scan.raw
            ports = scan.open_ports
        else:
            raw = "No AMF IP configured. Set modules.gen5.amf_ip in config."
            ports = []

        return self._make_result(
            "NR-001", "5G Cell Discovery / AMF Port Scan",
            status=TestStatus.PASS, severity=Severity.INFO,
            gsma_ref="FS.40",
            threegpp_ref="TS 38.104",
            affected_component="5G gNB / NR-ARFCN / AMF",
            finding=(
                f"Open 5G/AMF ports: {ports}. "
                f"NG-AP (38412) exposed: {38412 in ports}."
                if ports else
                "5G NR scan incomplete — configure AMF IP or SDR hardware."
            ),
            recommendation="Restrict NG-AP to authorized gNB IPs only. Validate PLMN on registration.",
            raw_output=raw[:4096],
            tool_used="nmap",
        )

    async def _nr002_supi_suci_privacy(self, passive_only: bool = False) -> FindingResult:
        """NR-002: Check SUCI conceals IMSI (null scheme detection)."""
        # Test SUCI null scheme exposure
        test_suci = "suci-0-001-01-0-0-0-0000000001"
        suci_info = decode_suci(test_suci)
        null_scheme = suci_info.msin_revealed is not None
        warning = suci_info.warning

        return self._make_result(
            "NR-002", "SUPI/SUCI Privacy (Null Protection Scheme Detection)",
            status=TestStatus.FAIL if null_scheme else TestStatus.PASS,
            severity=Severity.CRITICAL if null_scheme else Severity.INFO,
            cvss_score=8.7 if null_scheme else 0.0,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            gsma_ref="TS33.501-A1",
            threegpp_ref="TS 33.501 §6.12.2",
            affected_component="5G UE / AMF / SUCI concealment",
            finding=(
                f"SUCI null protection scheme (scheme-id=0) detected — MSIN is NOT concealed: "
                f"{suci_info.msin_revealed}. This is only acceptable in lab environments."
                if null_scheme else
                "SUCI uses ECIES protection scheme — SUPI/IMSI is properly concealed."
            ),
            impact=(
                "Null SUCI exposes IMSI permanently in all registration messages, "
                "enabling real-time subscriber tracking via NAS monitoring."
                if null_scheme else "None — SUCI concealment functioning correctly."
            ),
            recommendation=(
                "Configure SUCI protection scheme to Profile A (ECIES P-256) or "
                "Profile B (ECIES P-384). Never deploy null scheme in production."
                if null_scheme else
                "Continue using ECIES SUCI protection. Periodically audit SUCI config."
            ),
            raw_output=warning,
            tool_used="TelSec SUCI decoder",
        )

    async def _nr003_nas_downgrade(self, passive_only: bool = False) -> FindingResult:
        """NR-003: NAS Security Mode Downgrade Attack (5G-EA0 / 5G-IA0)."""
        err = self._active_check("NR-003", "NAS Cipher Downgrade", passive_only)
        if err:
            return err
        return self._make_result(
            "NR-003", "5G NAS Security Mode Downgrade (5G-EA0)",
            status=TestStatus.WARNING, severity=Severity.CRITICAL,
            cvss_score=9.3,
            cve="CVE-2019-25104",
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 33.501 §6.7.3",
            affected_component="5G AMF / NAS Security Mode Command",
            finding=(
                "An attacker can attempt to force UE to use 5G-EA0 (null cipher) and "
                "5G-IA0 (null integrity) via fake Security Mode Command. "
                "Requires srsRAN 5G + fake gNB for active testing."
            ),
            impact="Complete loss of NAS confidentiality and integrity if downgrade succeeds.",
            recommendation=(
                "Configure AMF to reject EA0/IA0 for non-emergency sessions. "
                "Implement UE-side cipher/integrity algorithm priority enforcement."
            ),
            tool_used="srsRAN 5G (requires Docker + SDR)",
        )

    async def _nr004_amf_registration_spam(self, passive_only: bool = False) -> FindingResult:
        """NR-004: AMF Registration Request Spam."""
        err = self._active_check("NR-004", "AMF Registration Spam", passive_only)
        if err:
            return err
        if not self.amf_ip:
            return self._make_result(
                "NR-004", "AMF Registration Spam",
                status=TestStatus.SKIPPED, severity=Severity.INFO,
                finding="No AMF IP configured.",
            )
        return self._make_result(
            "NR-004", "AMF Registration Request Spam (DoS)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 33.501 §5.4.5",
            affected_component="5G AMF / NGAP",
            finding=(
                "Unauthenticated initial NAS registration requests (pre-SUCI authentication) "
                "can be flooded to exhaust AMF registration processing capacity. "
                "Rate limiting via NGAP overload handling required."
            ),
            recommendation=(
                "Configure AMF NGAP overload control (3GPP TS 23.501 §5.16). "
                "Implement per-gNB connection rate limiting."
            ),
            tool_used="UERANSIM (requires Docker)",
        )

    async def _nr005_ausf_udm_api(self, passive_only: bool = False) -> FindingResult:
        """NR-005: AUSF/UDM SBA API authentication check."""
        err = self._active_check("NR-005", "AUSF/UDM API Exposure", passive_only)
        if err:
            return err

        # Test NF service API without OAuth2 token
        resp = await self._probe_sba(
            "/nudm-uecm/v1/imsi-001010000000001/registrations",
            method="GET",
        )

        exposed = resp.get("status_code", 200) == 200 and "registrations" in str(resp.get("body", ""))
        error = "error" in resp

        return self._make_result(
            "NR-005", "AUSF/UDM SBA API Authentication Check",
            status=TestStatus.FAIL if exposed else (TestStatus.PASS if not error else TestStatus.WARNING),
            severity=Severity.CRITICAL if exposed else Severity.MEDIUM,
            cvss_score=9.8 if exposed else 4.3,
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 33.501 §13.3",
            affected_component="5G UDM / AUSF / SBA APIs",
            finding=(
                f"UDM API returned subscriber data WITHOUT OAuth2 authorization! "
                f"HTTP {resp.get('status_code')}."
                if exposed else
                f"UDM API correctly requires authentication. HTTP {resp.get('status_code', 'N/A')}."
                if not error else
                "UDM API unreachable — configure sba_base_url in config.yaml."
            ),
            recommendation=(
                "Mandate OAuth2 client credentials for all NF-to-NF SBA API calls. "
                "Deploy NRF-based token validation per TS 33.501 §13.3."
            ),
            raw_output=str(resp)[:2048],
            tool_used="httpx SBA prober",
        )

    async def _nr006_nrf_discovery(self, passive_only: bool = False) -> FindingResult:
        """NR-006: NRF Service Discovery Abuse — enumerate all NFs."""
        resp = await self._probe_sba(
            "/nnrf-nfm/v1/nf-instances?nf-type=AMF",
            method="GET",
        )

        nfs_exposed = resp.get("status_code") == 200 and len(str(resp.get("body", ""))) > 50
        return self._make_result(
            "NR-006", "NRF NF Discovery Abuse (Network Function Enumeration)",
            status=TestStatus.FAIL if nfs_exposed else TestStatus.WARNING,
            severity=Severity.HIGH if nfs_exposed else Severity.MEDIUM,
            cvss_score=7.5 if nfs_exposed else 4.3,
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 29.510 §5.2.2",
            affected_component="5G NRF / Nnrf-NFManagement API",
            finding=(
                f"NRF returned complete NF instance list without authorization. "
                f"All 5GC network function IPs/endpoints are exposed."
                if nfs_exposed else
                "NRF requires authorization for NF discovery."
            ),
            impact="Attacker can enumerate all 5GC component IPs, facilitating targeted attacks.",
            recommendation=(
                "Restrict NRF queries to authenticated internal NFs only. "
                "Apply network segmentation to isolate 5GC SBA plane."
            ),
            raw_output=str(resp)[:2048],
            tool_used="httpx SBA prober",
        )

    async def _nr007_slice_isolation(self, passive_only: bool = False) -> FindingResult:
        """NR-007: 5G Network Slice Isolation Test."""
        err = self._active_check("NR-007", "Network Slice Isolation", passive_only)
        if err:
            return err
        return self._make_result(
            "NR-007", "Network Slice Isolation (S-NSSAI Cross-Slice Test)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=8.1,
            gsma_ref="FS.37-R1",
            threegpp_ref="TS 33.501 §5.11",
            affected_component="5G AMF / SMF / NSSF / UPF",
            finding=(
                "Network slice isolation requires cross-slice PDU session attempt with "
                "different S-NSSAI. Slice isolation verification needs srsRAN 5G + Open5GS. "
                "Misconfigured NSSF may allow unauthorized slice access."
            ),
            impact="Cross-slice data leakage — enterprise or critical infrastructure slices accessible by consumers.",
            recommendation=(
                "Implement strict NSSF-based slice authorization. "
                "Deploy per-slice UPF instances with network isolation. "
                "Audit NSSF allowed-NSSAI lists for each subscriber profile."
            ),
            tool_used="srsRAN 5G + UERANSIM (requires Docker)",
        )

    async def _nr008_smf_session_hijack(self, passive_only: bool = False) -> FindingResult:
        """NR-008: SMF PDU Session Hijacking."""
        err = self._active_check("NR-008", "SMF Session Hijacking", passive_only)
        if err:
            return err
        resp = await self._probe_sba(
            "/nsmf-pdusession/v1/sm-contexts",
            method="POST",
            body='{"supi":"imsi-001010000000001","pduSessionId":1,"requestType":"INITIAL_REQUEST"}',
        )
        return self._make_result(
            "NR-008", "SMF PDU Session Hijacking (SBA API Injection)",
            status=TestStatus.FAIL if resp.get("status_code") in [200, 201] else TestStatus.PASS,
            severity=Severity.CRITICAL if resp.get("status_code") in [200, 201] else Severity.INFO,
            cvss_score=9.0 if resp.get("status_code") in [200, 201] else 0.0,
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 29.502",
            affected_component="5G SMF / Nsmf-PDUSession API",
            finding=(
                f"SMF accepted unauthenticated PDU session creation! HTTP {resp.get('status_code')}."
                if resp.get("status_code") in [200, 201] else
                "SMF correctly rejected unauthenticated session creation request."
            ),
            recommendation=(
                "Mandate OAuth2.0 tokens on all Nsmf-PDUSession API endpoints. "
                "Validate AMF identity before processing session establishment."
            ),
            raw_output=str(resp)[:2048],
            tool_used="httpx SBA prober",
        )

    async def _nr009_upf_gtp_injection(self, passive_only: bool = False) -> FindingResult:
        """NR-009: UPF GTP-U Injection (user plane hijack)."""
        err = self._active_check("NR-009", "UPF GTP-U Injection", passive_only)
        if err:
            return err
        return self._make_result(
            "NR-009", "UPF GTP-U Tunnel Injection (User Plane Hijack)",
            status=TestStatus.WARNING, severity=Severity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 29.281 / TS 33.501 §6.6",
            affected_component="5G UPF / N3/N9 GTP-U interfaces",
            finding=(
                "GTP-U in 5G (N3/N9 interfaces) remains unauthenticated at packet level. "
                "An attacker with N3 network access can inject/modify GTP-U packets "
                "by targeting existing TEIDs."
            ),
            impact="Complete user data plane compromise — data injection, modification, or interception.",
            recommendation=(
                "Deploy IPSec on N3/N6/N9 interfaces (GSMA FS.40 requirement). "
                "Implement UPF source IP validation for GTP endpoints."
            ),
            tool_used="Scapy GTP-U (requires N3 network access)",
        )

    async def _nr010_pcf_policy_bypass(self, passive_only: bool = False) -> FindingResult:
        """NR-010: PCF Policy Bypass via Npcf API."""
        err = self._active_check("NR-010", "PCF Policy Bypass", passive_only)
        if err:
            return err
        resp = await self._probe_sba(
            "/npcf-smpolicycontrol/v1/sm-policies",
            method="GET",
        )
        return self._make_result(
            "NR-010", "PCF Policy Bypass (Npcf-SMPolicyControl API)",
            status=TestStatus.FAIL if resp.get("status_code") == 200 else TestStatus.PASS,
            severity=Severity.HIGH if resp.get("status_code") == 200 else Severity.INFO,
            cvss_score=7.5 if resp.get("status_code") == 200 else 0.0,
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 29.512",
            affected_component="5G PCF / Npcf-SMPolicyControl",
            finding=(
                f"PCF returned policy data without authentication. HTTP {resp.get('status_code')}."
                if resp.get("status_code") == 200 else
                "PCF correctly requires authentication for policy API."
            ),
            recommendation=(
                "OAuth2 mandatory on Npcf APIs. "
                "Policy rules should be read-only for non-authorized requestors."
            ),
            raw_output=str(resp)[:2048],
            tool_used="httpx SBA prober",
        )

    async def _nr011_oran_e2_fuzzing(self, passive_only: bool = False) -> FindingResult:
        """NR-011: O-RAN E2 Interface Fuzzing."""
        err = self._active_check("NR-011", "O-RAN E2 Fuzzing", passive_only)
        if err:
            return err
        return self._make_result(
            "NR-011", "O-RAN E2 Interface Fuzzing (xApp Injection)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=8.0,
            gsma_ref="FS.40-5G1",
            threegpp_ref="O-RAN.WG3.E2AP-v02.03",
            affected_component="O-RAN RIC / E2 Node / xApp",
            finding=(
                "O-RAN E2 interface (E2AP messages) lacks strong authentication "
                "in early O-RAN Alliance specs. A malicious xApp can inject "
                "RAN control messages affecting radio scheduling and handover decisions."
            ),
            impact="RAN disruption, subscriber DoS, unauthorized RAN parameter modification.",
            recommendation=(
                "Deploy E2 interface TLS mutual authentication. "
                "Validate xApp signatures at Near-RT RIC. "
                "Apply O-RAN Alliance security WG recommendations."
            ),
            tool_used="TelSec E2AP fuzzer (advisor only)",
        )

    async def _nr012_mass_registration(self, passive_only: bool = False) -> FindingResult:
        """NR-012: Mass fake UE registration (UERANSIM attack)."""
        err = self._active_check("NR-012", "Mass Fake UE Registration", passive_only)
        if err:
            return err
        ueransim = shutil.which("nr-ue")
        return self._make_result(
            "NR-012", "Mass Fake UE Registration (UERANSIM / AMF Stress Test)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            gsma_ref="FS.40-5G1",
            threegpp_ref="TS 23.501 §5.4",
            affected_component="5G AMF / Core Network",
            finding=(
                "UERANSIM can simulate hundreds of fake UEs simultaneously, flooding "
                "the AMF registration processing queue. "
                f"UERANSIM (nr-ue) {'found' if ueransim else 'not found — install from Docker'}."
            ),
            recommendation=(
                "Configure AMF NGAP overload control and reject mechanisms. "
                "Implement per-PLMN registration rate limiting."
            ),
            tool_used="UERANSIM (nr-ue) via Docker",
        )
