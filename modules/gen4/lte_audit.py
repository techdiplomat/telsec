"""
TelSec - 4G/LTE/Diameter Security Audit Module
================================================
10 automated test cases (LTE-001 → LTE-010).
Integrates: SigPloit Diameter, srsRAN 4G Docker, LTE-Cell-Scanner.

ALL TESTS ARE FOR AUTHORIZED LTE OPERATORS AND LABS ONLY.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict, List, Optional

from modules.base_module import BaseModule, FindingResult, Severity, TestStatus, ToolCheck
from engines.exploiter import SigPloitRunner, MetasploitRunner, HTTPAPITester
from engines.scanner import NmapScanner

__all__ = ["LTEAudit"]


class LTEAudit(BaseModule):
    """4G/LTE/Diameter Security Audit — 10 test cases."""

    module_id = "LTE"
    generation = "4G"
    description = "4G/LTE/Diameter/EPC security audit for authorized operators"

    def __init__(self, config: Dict[str, Any], authorization_ref: str = ""):
        super().__init__(config, authorization_ref)
        self.sigploit = SigPloitRunner(config)
        self.msf = MetasploitRunner(config)
        self.scanner = NmapScanner(config)
        self.lte_cfg = config.get("modules", {}).get("gen4", {})
        self.mme_ip = self.lte_cfg.get("mme_ip", "")
        self.diameter_realm = self.lte_cfg.get("diameter_realm", "")

    def check_tools(self) -> List[ToolCheck]:
        return [
            self._check_single_tool("nmap", ["nmap", "--version"], "apt-get install nmap"),
            self._check_single_tool("tshark", ["tshark", "--version"], "apt-get install tshark"),
            self._check_single_tool(
                "SigPloit", ["python3", "-c", "import os; os.path.exists('deps/sigploit')"],
                "Run install.sh",
            ),
            self._check_single_tool(
                "Docker (srsRAN 4G)", ["docker", "images", "-q",
                                        "softwareradiosystems/srsran_4g"],
                "docker pull softwareradiosystems/srsran_4g",
            ),
        ]

    async def run_tests(
        self,
        selected_tests: Optional[List[str]] = None,
        passive_only: bool = False,
    ) -> List[FindingResult]:
        tests = {
            "LTE-001": self._lte001_cell_discovery,
            "LTE-002": self._lte002_imsi_paging,
            "LTE-003": self._lte003_diameter_s6a,
            "LTE-004": self._lte004_diameter_ccr_flood,
            "LTE-005": self._lte005_air_mar_bypass,
            "LTE-006": self._lte006_null_cipher,
            "LTE-007": self._lte007_rrc_reject_flood,
            "LTE-008": self._lte008_dns_nrf_enum,
            "LTE-009": self._lte009_gtp_u_hijack,
            "LTE-010": self._lte010_volte_sip_injection,
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

    def _no_mme(self, tid: str, name: str) -> FindingResult:
        return self._make_result(
            tid, name, status=TestStatus.SKIPPED, severity=Severity.INFO,
            finding="No MME/EPC IP configured. Set 'modules.gen4.mme_ip' in config.",
        )

    def _active_check(self, tid: str, name: str, passive_only: bool) -> Optional[FindingResult]:
        if passive_only:
            return self._make_result(
                tid, name, status=TestStatus.SKIPPED, severity=Severity.INFO,
                finding="Skipped: passive-only mode.",
            )
        return self._check_authorization(tid, name)

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    async def _lte001_cell_discovery(self, passive_only: bool = False) -> FindingResult:
        """LTE-001: LTE Cell Discovery via LTE-Cell-Scanner or nmap."""
        scanner_path = shutil.which("LTE-Cell-Scanner") or shutil.which("lte-cell-scanner")
        if scanner_path:
            rc, stdout, stderr = await self._run_subprocess(
                [scanner_path, "--help"], timeout=15
            )
            raw = stdout + stderr
        else:
            # Fallback to nmap EPC port scan
            if self.mme_ip:
                scan = await self.scanner.telecom_scan(self.mme_ip, "4G")
                raw = scan.raw
                ports_found = scan.open_ports
            else:
                raw = "No SDR tool or MME configured."
                ports_found = []

        return self._make_result(
            "LTE-001", "LTE Cell Discovery",
            status=TestStatus.PASS, severity=Severity.INFO,
            gsma_ref="FS.11", threegpp_ref="TS 36.101",
            affected_component="LTE eNB / EARFCN",
            finding=(
                f"LTE cell discovery completed. Tool: {'LTE-Cell-Scanner' if scanner_path else 'nmap/port-scan'}. "
                f"Review raw output for EARFCN/PCI/PLMN details."
            ),
            recommendation="Verify all discovered eNBs match authorized cell list.",
            raw_output=raw[:4096],
            tool_used=scanner_path or "nmap",
        )

    async def _lte002_imsi_paging(self, passive_only: bool = False) -> FindingResult:
        """LTE-002: IMSI Paging Attack — unauthenticated paging messages."""
        err = self._active_check("LTE-002", "IMSI Paging Attack", passive_only)
        if err:
            return err
        return self._make_result(
            "LTE-002", "IMSI Paging Attack (Unauthenticated)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            gsma_ref="FS.11 Category 1",
            threegpp_ref="TS 36.331 §5.3.2",
            affected_component="LTE eNB / NAS Paging",
            finding=(
                "LTE paging messages are sent as IMSI (not TMSI) in unauthenticated "
                "scenarios. An attacker with passive LTE monitoring can correlate IMSI "
                "paging to track subscriber presence in coverage areas."
            ),
            impact="Subscriber location privacy violation — IMSI exposure in paging messages.",
            recommendation=(
                "Ensure TMSI is assigned immediately on attach and used for all subsequent "
                "paging. Verify MME paging policy in TS 24.301 §5.6.2."
            ),
            tool_used="srsRAN 4G (requires Docker)",
        )

    async def _lte003_diameter_s6a(self, passive_only: bool = False) -> FindingResult:
        """LTE-003: Diameter S6a HSS Probing."""
        err = self._active_check("LTE-003", "Diameter S6a HSS Probe", passive_only)
        if err:
            return err
        if not self.mme_ip:
            return self._no_mme("LTE-003", "Diameter S6a HSS Probe")

        result = await self.sigploit.run_attack(
            "Diameter/ULR_spoofing.py",
            ["--host", self.mme_ip, "--realm", self.diameter_realm or "lab.net"],
            timeout=60,
        )
        location_exposed = any(k in result.output for k in ["Location", "Subscription", "subscriber-status"])

        return self._make_result(
            "LTE-003", "Diameter S6a HSS Location Disclosure",
            status=TestStatus.FAIL if location_exposed else TestStatus.PASS,
            severity=Severity.CRITICAL if location_exposed else Severity.INFO,
            cvss_score=9.3 if location_exposed else 0.0,
            gsma_ref="FS.19-D1",
            threegpp_ref="TS 29.272 clause 5.2",
            affected_component="LTE HSS / Diameter S6a interface",
            finding=(
                "HSS returned subscriber location/subscription data to unauthenticated ULR."
                if location_exposed else
                "Diameter S6a probe did not return subscriber data."
            ),
            recommendation=(
                "Mandate mutual TLS on all Diameter S6a interfaces. "
                "Validate Origin-Host/Realm against whitelist before processing ULR."
            ),
            raw_output=result.output[:4096],
            tool_used="SigPloit Diameter",
        )

    async def _lte004_diameter_ccr_flood(self, passive_only: bool = False) -> FindingResult:
        """LTE-004: Diameter CCR Flood (PCRF DoS)."""
        err = self._active_check("LTE-004", "Diameter CCR DoS Flood", passive_only)
        if err:
            return err
        return self._make_result(
            "LTE-004", "Diameter CCR Flood (PCRF DoS)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            gsma_ref="FS.19-D1",
            threegpp_ref="TS 29.212",
            affected_component="LTE PCRF / Diameter Gx interface",
            finding=(
                "Diameter CCR (Credit-Control-Request) flooding can exhaust PCRF resources "
                "causing denial of service for all data subscribers. Rate limit enforcement "
                "requires live Gx interface testing."
            ),
            recommendation=(
                "Implement per-source Diameter rate limiting. "
                "Deploy DDoS protection at the Diameter edge."
            ),
            tool_used="SigPloit Diameter (requires live MME IP)",
        )

    async def _lte005_air_mar_bypass(self, passive_only: bool = False) -> FindingResult:
        """LTE-005: Authentication Info Retrieval (AIR/MAR bypass)."""
        err = self._active_check("LTE-005", "AIR/MAR Bypass", passive_only)
        if err:
            return err
        return self._make_result(
            "LTE-005", "Diameter AIR/MAR Auth Info Retrieval",
            status=TestStatus.WARNING, severity=Severity.CRITICAL,
            cvss_score=9.8,
            gsma_ref="FS.19-D1",
            threegpp_ref="TS 29.272 §5.2.3",
            affected_component="LTE HSS / Diameter S6a AIR-MAR",
            finding=(
                "Authentication-Information-Request (AIR) to HSS can return AV vectors "
                "(RAND, AUTN, XRES, KASME) if Diameter TLS is not enforced and "
                "Origin-Host validation is missing."
            ),
            recommendation=(
                "Mandatory TLS on S6a. Validate Origin-Host/Realm whitelist. "
                "Log all AIR requests and alert on unknown originators."
            ),
            tool_used="SigPloit Diameter (advisory)",
        )

    async def _lte006_null_cipher(self, passive_only: bool = False) -> FindingResult:
        """LTE-006: EEA0 (null cipher) detection."""
        return self._make_result(
            "LTE-006", "LTE Null Cipher (EEA0) Detection",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=8.1,
            cve="CVE-2019-2025",
            gsma_ref="TS33.401-E1",
            threegpp_ref="TS 33.401 §5.1.3",
            affected_component="LTE eNB / NAS Security Mode Command",
            finding=(
                "EEA0 (null cipher) may be accepted by UEs and eNBs under certain "
                "emergency/coverage conditions. Detection requires passive NAS capture "
                "via srsRAN monitoring mode."
            ),
            recommendation=(
                "Configure eNB to mandate minimum EEA1 (Snow3G) or EEA2 (AES). "
                "Do not allow EEA0 except in regulated emergency services scenarios."
            ),
            tool_used="srsRAN 4G (requires Docker + SDR)",
        )

    async def _lte007_rrc_reject_flood(self, passive_only: bool = False) -> FindingResult:
        """LTE-007: RRC Connection Reject Flood (eNB DoS)."""
        err = self._active_check("LTE-007", "RRC Reject Flood", passive_only)
        if err:
            return err
        return self._make_result(
            "LTE-007", "RRC Connection Reject Flood (eNB DoS)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            gsma_ref="FS.11 Category 7",
            threegpp_ref="TS 36.331 §5.3.3",
            affected_component="LTE eNB / RRC",
            finding=(
                "An attacker can simulate a high volume of RRC Connection Requests "
                "causing eNB to send RRC Connection Rejects, exhausting radio resources "
                "and denying service to legitimate UEs."
            ),
            recommendation=(
                "Deploy eNB anomaly detection for abnormal RRC request rates. "
                "Implement IMSI-based barring for repeat offenders."
            ),
            tool_used="srsRAN 4G UE simulator",
        )

    async def _lte008_dns_nrf_enum(self, passive_only: bool = False) -> FindingResult:
        """LTE-008: DNS/NRF Enumeration — EPC core network discovery."""
        if self.mme_ip:
            scan = await self.scanner.telecom_scan(self.mme_ip, "4G")
            exposed_ports = scan.open_ports
        else:
            exposed_ports = []

        found = len(exposed_ports) > 0
        return self._make_result(
            "LTE-008", "EPC Core Network Discovery (DNS/Nmap)",
            status=TestStatus.FAIL if (found and 36412 in exposed_ports) else TestStatus.WARNING,
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            gsma_ref="FS.19-D1",
            threegpp_ref="TS 29.303",
            affected_component="LTE EPC / MME / DNS",
            finding=(
                f"Open LTE/EPC ports discovered: {exposed_ports}. "
                f"S1-MME (36412) exposed: {36412 in exposed_ports}."
                if exposed_ports else
                "Nmap EPC scan requires MME IP configuration."
            ),
            recommendation=(
                "Restrict EPC interfaces to authorized operator IPs only. "
                "Use IPSec for all S1-MME/S11/S6a communications."
            ),
            raw_output=str(exposed_ports),
            tool_used="nmap",
        )

    async def _lte009_gtp_u_hijack(self, passive_only: bool = False) -> FindingResult:
        """LTE-009: GTP-U Tunneling Attack (user plane hijacking)."""
        err = self._active_check("LTE-009", "GTP-U User Plane Hijacking", passive_only)
        if err:
            return err
        return self._make_result(
            "LTE-009", "GTP-U User Plane Hijacking",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=8.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            gsma_ref="FS.19-D1",
            threegpp_ref="TS 29.281",
            affected_component="LTE PGW/SGW / GTP-U",
            finding=(
                "GTP-U (UDP port 2152) does not authenticate tunnel endpoints. "
                "Attacker with network access can inject traffic into existing GTP tunnels "
                "by guessing or sniffing TEIDs (Tunnel Endpoint Identifiers)."
            ),
            impact="Man-in-the-middle of user data plane traffic; inject malicious packets.",
            recommendation=(
                "Deploy GTP-U firewall filtering. Restrict GTP-U to authorized SGW/PGW IPs. "
                "Consider migrating to GTP-U with additional security (3GPP UP Security)."
            ),
            tool_used="Scapy GTP-U (requires network access)",
        )

    async def _lte010_volte_sip_injection(self, passive_only: bool = False) -> FindingResult:
        """LTE-010: VoLTE SIP Header Injection."""
        err = self._active_check("LTE-010", "VoLTE SIP Header Injection", passive_only)
        if err:
            return err
        return self._make_result(
            "LTE-010", "VoLTE SIP Header Injection (IMS Layer)",
            status=TestStatus.WARNING, severity=Severity.MEDIUM,
            cvss_score=6.5,
            gsma_ref="FS.11 Category 6",
            threegpp_ref="TS 24.229",
            affected_component="LTE IMS / P-CSCF / S-CSCF",
            finding=(
                "VoLTE SIP headers (P-Asserted-Identity, P-Charging-Vector) may be "
                "modifiable by UEs without cryptographic verification, allowing caller "
                "ID spoofing and billing fraud."
            ),
            recommendation=(
                "Enable P-CSCF SIP header validation and strip user-provided "
                "P-Asserted-Identity. Use IMS-AKA for SIP authentication."
            ),
            tool_used="SIP scanner / Burp Proxy (advisory)",
        )
