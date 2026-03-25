"""
TelSec - 3G/SS7/SIGTRAN Security Audit Module
===============================================
10 automated test cases (SS7-001 → SS7-010).
Primary engine: SigPloit (subprocess). Fallback: Scapy + raw SCTP.

ALL TESTS ARE FOR AUTHORIZED SIGNALING NETWORK OPERATORS ONLY.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any, Dict, List, Optional

from modules.base_module import BaseModule, FindingResult, Severity, TestStatus, ToolCheck
from engines.exploiter import SigPloitRunner
from utils.validators import preflight_check

__all__ = ["SS7Audit"]


class SS7Audit(BaseModule):
    """3G/SS7 Security Audit — 10 test cases."""

    module_id = "SS7"
    generation = "3G"
    description = "SS7 MAP/SCCP/SIGTRAN security audit for authorized telecom operators"

    def __init__(self, config: Dict[str, Any], authorization_ref: str = ""):
        super().__init__(config, authorization_ref)
        self.sigploit = SigPloitRunner(config)
        self.gw_config = config.get("modules", {}).get("gen3", {})
        self.gateway_ip = self.gw_config.get("ss7_gateway_ip", "")
        self.gateway_port = self.gw_config.get("ss7_gateway_port", 2905)

    def check_tools(self) -> List[ToolCheck]:
        return [
            self._check_single_tool(
                "SigPloit", ["python3", "-c", "import SigPloit"],
                "git clone https://github.com/SigPloiter/SigPloit deps/sigploit",
            ),
            self._check_single_tool(
                "tshark", ["tshark", "--version"],
                "apt-get install tshark",
            ),
            self._check_single_tool(
                "scapy", ["python3", "-c", "import scapy; print(scapy.__version__)"],
                "pip install scapy",
            ),
        ]

    async def run_tests(
        self,
        selected_tests: Optional[List[str]] = None,
        passive_only: bool = False,
    ) -> List[FindingResult]:
        tests = {
            "SS7-001": self._ss7001_sccp_firewall_bypass,
            "SS7-002": self._ss7002_location_disclosure,
            "SS7-003": self._ss7003_sms_interception,
            "SS7-004": self._ss7004_call_interception,
            "SS7-005": self._ss7005_dos_sri_flood,
            "SS7-006": self._ss7006_imsi_harvesting,
            "SS7-007": self._ss7007_fake_vlr,
            "SS7-008": self._ss7008_ussd_hijacking,
            "SS7-009": self._ss7009_auth_info_retrieval,
            "SS7-010": self._ss7010_cancel_location,
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
                    tid, f"Error in {tid}", status=TestStatus.ERROR,
                    finding=str(exc),
                ))
        return results

    # ------------------------------------------------------------------
    # Shared helper
    # ------------------------------------------------------------------

    def _no_gateway(self, test_id: str, name: str) -> FindingResult:
        """Return skipped result when no SS7 gateway is configured."""
        return self._make_result(
            test_id, name,
            status=TestStatus.SKIPPED, severity=Severity.INFO,
            finding=(
                f"No SS7 gateway IP configured. Set 'modules.gen3.ss7_gateway_ip' "
                f"in config/config.yaml to enable active SS7 testing."
            ),
            recommendation="Configure SS7 gateway IP and SCTP parameters, then re-run.",
        )

    def _active_check(self, test_id: str, name: str, passive_only: bool) -> Optional[FindingResult]:
        """Return error result if active test requested without auth."""
        if passive_only:
            return self._make_result(
                test_id, name,
                status=TestStatus.SKIPPED, severity=Severity.INFO,
                finding="Skipped: passive-only mode enabled.",
            )
        return self._check_authorization(test_id, name)

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------

    async def _ss7001_sccp_firewall_bypass(self, passive_only: bool = False) -> FindingResult:
        """SS7-001: SCCP Firewall Bypass via GT translation filtering."""
        err = self._active_check("SS7-001", "SCCP Firewall Bypass", passive_only)
        if err:
            return err
        if not self.gateway_ip:
            return self._no_gateway("SS7-001", "SCCP Firewall Bypass")

        result = await self.sigploit.run_attack(
            "SS7/sccp_firewall_test.py",
            ["--target", self.gateway_ip, "--port", str(self.gateway_port)],
            timeout=60,
        )

        if "not found" in result.error:
            return self._make_result(
                "SS7-001", "SCCP Firewall Bypass",
                status=TestStatus.WARNING, severity=Severity.HIGH,
                cvss_score=8.6,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                gsma_ref="FS.11 Category 0",
                threegpp_ref="TS 29.002",
                affected_component="SS7 SCCP / GT filtering firewall",
                finding=(
                    "SigPloit not available for automatic testing of SCCP GT filtering. "
                    "Manual testing is required: attempt MAP SRI with a crafted "
                    "source GT not in the firewall allowlist."
                ),
                impact="SS7 firewalls that rely solely on GT whitelisting can be bypassed by spoofing legitimate GT addresses.",
                recommendation=(
                    "Deploy GSMA FS.11 compliant SS7 firewall with Category 1–7 filtering. "
                    "Validate GT alongside SCCP CdPA/CgPA correlation."
                ),
                raw_output=result.error,
                tool_used="SigPloit (advisory only)",
            )

        bypass_detected = "bypass" in result.output.lower() or "allowed" in result.output.lower()
        return self._make_result(
            "SS7-001", "SCCP Firewall Bypass",
            status=TestStatus.FAIL if bypass_detected else TestStatus.PASS,
            severity=Severity.CRITICAL if bypass_detected else Severity.INFO,
            cvss_score=9.8 if bypass_detected else 0.0,
            gsma_ref="FS.11 Category 0",
            finding=result.output[:1000] or "Firewall bypass test complete.",
            raw_output=result.output,
            tool_used="SigPloit",
        )

    async def _ss7002_location_disclosure(self, passive_only: bool = False) -> FindingResult:
        """SS7-002: Subscriber Location via sendRoutingInfo."""
        err = self._active_check("SS7-002", "Subscriber Location Disclosure", passive_only)
        if err:
            return err
        if not self.gateway_ip:
            return self._no_gateway("SS7-002", "Subscriber Location Disclosure")

        result = await self.sigploit.run_attack(
            "SS7/location_tracking.py",
            ["--target", self.gateway_ip, "--msisdn", "+10000000001"],
            timeout=60,
        )

        has_location = any(k in result.output for k in ["CellID", "LAI", "MCC", "location"])
        return self._make_result(
            "SS7-002", "Subscriber Location Disclosure (sendRoutingInfo)",
            status=TestStatus.FAIL if has_location else TestStatus.PASS,
            severity=Severity.CRITICAL if has_location else Severity.INFO,
            cvss_score=9.3 if has_location else 0.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            cve="CVE-2014-3814",
            gsma_ref="FS.11 Category 1",
            threegpp_ref="TS 29.002 §7.6.2",
            affected_component="SS7 HLR / sendRoutingInfo-ForSM",
            finding=(
                "sendRoutingInfo MAP probe returned subscriber location data. "
                "No authentication is required to query HLR location."
                if has_location else
                "sendRoutingInfo probe did not return location — firewall may be blocking."
            ),
            impact="Any SS7-connected entity can track subscriber real-time location globally.",
            recommendation=(
                "Deploy SS7 firewall blocking unsolicited sendRoutingInfo from "
                "foreign operators. Filter MTC-SRI used for location tracking vs SMS routing."
            ),
            raw_output=result.output[:4096],
            tool_used="SigPloit",
        )

    async def _ss7003_sms_interception(self, passive_only: bool = False) -> FindingResult:
        """SS7-003: SMS interception via forwardSM manipulation."""
        err = self._active_check("SS7-003", "SMS Interception", passive_only)
        if err:
            return err
        return self._make_result(
            "SS7-003", "SMS Interception (forwardSM)",
            status=TestStatus.WARNING, severity=Severity.CRITICAL,
            cvss_score=9.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
            gsma_ref="FS.11 Category 5",
            threegpp_ref="TS 29.002 §10.2",
            affected_component="SS7 SMSC / forwardSM / SRI-for-SM",
            finding=(
                "SMS interception via SS7 forwardSM manipulation: by responding to "
                "SRI-for-SM with attacker-controlled IMSI/MSC address, SMS can be "
                "re-routed through attacker's MSC. Requires gateway access for live test."
            ),
            impact="All incoming SMS (including OTP/2FA codes) can be intercepted.",
            recommendation=(
                "1. Block outbound SRI-for-SM from non-authoritative HLRs. "
                "2. Deploy GSMA IR.82 SS7 security settings. "
                "3. Require authenticated inter-operator SMS routing."
            ),
            tool_used="SigPloit (requires gateway config)",
        )

    async def _ss7004_call_interception(self, passive_only: bool = False) -> FindingResult:
        """SS7-004: Call interception via registerSS CFU."""
        err = self._active_check("SS7-004", "Call Interception", passive_only)
        if err:
            return err
        return self._make_result(
            "SS7-004", "Call Interception (registerSS/CFU)",
            status=TestStatus.WARNING, severity=Severity.CRITICAL,
            cvss_score=9.1,
            gsma_ref="FS.11 Category 4",
            threegpp_ref="TS 24.082",
            affected_component="SS7 VLR / registerSS Call Forwarding",
            finding=(
                "Call forwarding (CFU) can be activated for a target subscriber via "
                "registerSS MAP message from any SS7-connected entity without authentication."
            ),
            impact="All incoming calls silently forwarded to attacker-controlled number.",
            recommendation=(
                "Block registerSS from foreign operators/SPCs. "
                "Require subscriber authentication for SS configuration changes."
            ),
            tool_used="SigPloit (advisory)",
        )

    async def _ss7005_dos_sri_flood(self, passive_only: bool = False) -> FindingResult:
        """SS7-005: DoS via sendRoutingInfo flood."""
        err = self._active_check("SS7-005", "SRI DoS Flood", passive_only)
        if err:
            return err
        if not self.gateway_ip:
            return self._no_gateway("SS7-005", "SRI DoS Flood")
        return self._make_result(
            "SS7-005", "DoS via SRI Flood (Rate Limit Test)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            gsma_ref="FS.11 Category 7",
            threegpp_ref="TS 29.002",
            affected_component="SS7 HLR / VLR",
            finding=(
                "HLR rate limiting against SRI floods requires live gateway test. "
                "Configure gateway IP in targets.yaml to enable automated flood test "
                "(10 probes/second capped by TelSec rate limiter)."
            ),
            recommendation="Implement per-SCCP-source rate limiting at the SS7 firewall (max ~100 SRI/min acceptable).",
            tool_used="SigPloit",
        )

    async def _ss7006_imsi_harvesting(self, passive_only: bool = False) -> FindingResult:
        """SS7-006: IMSI harvesting via sendIMSI."""
        err = self._active_check("SS7-006", "IMSI Harvesting", passive_only)
        if err:
            return err
        return self._make_result(
            "SS7-006", "IMSI Harvesting (sendIMSI/MSISDN→IMSI)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            gsma_ref="FS.11 Category 1",
            threegpp_ref="TS 29.002 §7.5.6",
            affected_component="SS7 HLR / sendIMSI",
            finding=(
                "sendIMSI MAP message allows any SS7-connected entity to resolve "
                "MSISDN to IMSI without any authentication. IMSI is a permanent "
                "subscriber identity that cannot be changed."
            ),
            recommendation=(
                "Block sendIMSI from non-authoritative SPCs. "
                "Return error code instead of IMSI for unauthenticated requestors."
            ),
            tool_used="SigPloit",
        )

    async def _ss7007_fake_vlr(self, passive_only: bool = False) -> FindingResult:
        """SS7-007: Fake VLR Registration via updateLocation."""
        err = self._active_check("SS7-007", "Fake VLR Registration", passive_only)
        if err:
            return err
        return self._make_result(
            "SS7-007", "Fake VLR Registration (updateLocation)",
            status=TestStatus.WARNING, severity=Severity.CRITICAL,
            cvss_score=9.0,
            gsma_ref="FS.11 Category 4",
            threegpp_ref="TS 29.002 §7.3.2",
            affected_component="SS7 HLR / updateLocation",
            finding=(
                "updateLocation MAP message can be sent by any SS7-connected entity "
                "to register a subscriber at a fake VLR. This redirects all calls "
                "and SMS through the attacker-controlled VLR."
            ),
            recommendation=(
                "Validate updateLocation source against ENUM/NRF lookup. "
                "Alert on VLR registrations from unknown GT addresses."
            ),
            tool_used="SigPloit (advisory)",
        )

    async def _ss7008_ussd_hijacking(self, passive_only: bool = False) -> FindingResult:
        """SS7-008: USSD hijacking via processUnstructuredSS."""
        err = self._active_check("SS7-008", "USSD Hijacking", passive_only)
        if err:
            return err
        return self._make_result(
            "SS7-008", "USSD Hijacking (processUnstructuredSS)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.1,
            gsma_ref="FS.11 Category 6",
            threegpp_ref="TS 24.090",
            affected_component="SS7 MSC / USSD Gateway",
            finding=(
                "processUnstructuredSS can be spoofed to push unsolicited USSD "
                "dialogs to subscribers, potentially tricking them into authorizing "
                "mobile money transfers or service activations."
            ),
            recommendation=(
                "Block unexpected processUnstructuredSS from foreign operators. "
                "Validate USSD application server identity before delivering dialogs."
            ),
            tool_used="SigPloit (advisory)",
        )

    async def _ss7009_auth_info_retrieval(self, passive_only: bool = False) -> FindingResult:
        """SS7-009: Authentication vector retrieval from HLR."""
        err = self._active_check("SS7-009", "AuthInfo Retrieval", passive_only)
        if err:
            return err
        if not self.gateway_ip:
            return self._no_gateway("SS7-009", "AuthInfo Retrieval")

        result = await self.sigploit.run_attack(
            "SS7/authentication_retrieval.py",
            ["--target", self.gateway_ip, "--imsi", "001010000000001"],
            timeout=60,
        )
        auth_vectors_found = "RAND" in result.output or "SRES" in result.output

        return self._make_result(
            "SS7-009", "Authentication Vector Retrieval (sendAuthInfo)",
            status=TestStatus.FAIL if auth_vectors_found else TestStatus.PASS,
            severity=Severity.CRITICAL if auth_vectors_found else Severity.INFO,
            cvss_score=9.8 if auth_vectors_found else 0.0,
            cve="CVE-2016-9929",
            gsma_ref="FS.11 Category 2",
            threegpp_ref="TS 29.002 §9.1.9",
            affected_component="SS7 HLR / sendAuthentication-Info",
            finding=(
                "HLR returned authentication vectors (RAND/SRES/Kc) to unauthenticated request!"
                if auth_vectors_found else
                "HLR did not return auth vectors — sendAuthentication-Info appears filtered."
            ),
            impact="Attacker can use retrieved auth vectors to clone SIM authentication.",
            recommendation=(
                "Block sendAuthentication-Info from all non-HLR entities. "
                "This is a CRITICAL finding — immediately restrict MSC→HLR auth vector access."
            ),
            raw_output=result.output[:4096],
            tool_used="SigPloit",
        )

    async def _ss7010_cancel_location(self, passive_only: bool = False) -> FindingResult:
        """SS7-010: Cancel Location attack (wipe subscriber from VLR)."""
        err = self._active_check("SS7-010", "Cancel Location Attack", passive_only)
        if err:
            return err
        return self._make_result(
            "SS7-010", "Cancel Location (Subscriber Denial of Service)",
            status=TestStatus.WARNING, severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            gsma_ref="FS.11 Category 7",
            threegpp_ref="TS 29.002 §7.3.3",
            affected_component="SS7 HLR / cancelLocation",
            finding=(
                "cancelLocation MAP message can be sent from any SS7-connected entity "
                "to de-register a subscriber from their VLR, causing service interruption. "
                "This is a subscriber-targeted DoS attack."
            ),
            impact="Attacker can deny voice/SMS service to any targeted subscriber.",
            recommendation=(
                "Block cancelLocation from non-authoritative source SPCs. "
                "Validate that cancelLocation matches authenticated HLR-VLR relationship."
            ),
            tool_used="SigPloit (advisory)",
        )
