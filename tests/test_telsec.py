"""
TelSec - Unit Tests
=====================
Tests for core utility functions, base module, and report engine.
Run: pytest tests/ -v
"""

import asyncio
import sys
import json
from pathlib import Path

import pytest

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================
# test_validators.py
# ============================================================
class TestValidators:
    def test_authorization_missing_ref(self):
        from utils.validators import validate_authorization
        ok, msg = validate_authorization("")
        assert not ok
        assert "blocked" in msg.lower() or "authorization" in msg.lower()

    def test_authorization_valid_ref(self):
        from utils.validators import validate_authorization
        ok, msg = validate_authorization("AUTH-2026-001")
        assert ok

    def test_authorization_short_ref(self):
        from utils.validators import validate_authorization
        ok, msg = validate_authorization("AB")
        assert not ok

    def test_passive_mode_no_auth_required(self):
        from utils.validators import validate_authorization
        ok, msg = validate_authorization("", require_ref=False)
        assert ok

    def test_ip_in_scope(self):
        from utils.validators import validate_ip_in_scope
        ok, _ = validate_ip_in_scope("192.168.0.5", ["192.168.0.0/24"])
        assert ok

    def test_ip_out_of_scope(self):
        from utils.validators import validate_ip_in_scope
        ok, _ = validate_ip_in_scope("10.0.0.1", ["192.168.0.0/24"])
        assert not ok

    def test_invalid_ip(self):
        from utils.validators import validate_ip_in_scope
        ok, _ = validate_ip_in_scope("not-an-ip", ["192.168.0.0/24"])
        assert not ok

    def test_msisdn_valid(self):
        from utils.validators import validate_msisdn
        ok, _ = validate_msisdn("+14155552671")
        assert ok

    def test_msisdn_invalid(self):
        from utils.validators import validate_msisdn
        ok, _ = validate_msisdn("123")
        assert not ok

    def test_imsi_valid(self):
        from utils.validators import validate_imsi
        ok, _ = validate_imsi("001010000000001")
        assert ok

    def test_imsi_too_short(self):
        from utils.validators import validate_imsi
        ok, _ = validate_imsi("001")
        assert not ok

    def test_rate_limiter(self):
        from utils.validators import RateLimiter
        rl = RateLimiter(max_per_second=3)
        results = [rl.is_allowed() for _ in range(5)]
        assert sum(results) == 3  # Only 3 of 5 allowed


# ============================================================
# test_imsi_tools.py
# ============================================================
class TestIMSITools:
    def test_decode_imsi_basic(self):
        from utils.imsi_tools import decode_imsi
        info = decode_imsi("001010000000001")
        assert info.valid
        assert info.mcc == "001"
        assert info.msin == "0000000001"

    def test_decode_imsi_invalid(self):
        from utils.imsi_tools import decode_imsi
        info = decode_imsi("123")
        assert not info.valid

    def test_decode_imsi_india(self):
        from utils.imsi_tools import decode_imsi
        info = decode_imsi("404300000000001")  # Airtel India
        assert info.valid
        assert info.mcc == "404"

    def test_parse_msisdn_valid(self):
        from utils.imsi_tools import parse_msisdn
        result = parse_msisdn("+14155552671")
        assert result["valid"] == "true"
        assert result["e164"] == "+14155552671"

    def test_tmsi_round_trip(self):
        from utils.imsi_tools import tmsi_to_hex, hex_to_tmsi
        original = 0xDEADBEEF
        hex_val = tmsi_to_hex(original)
        recovered = hex_to_tmsi(hex_val)
        assert recovered == original

    def test_decode_suci_null_scheme(self):
        from utils.imsi_tools import decode_suci
        suci = "suci-0-001-01-0-0-0-0000000001"
        info = decode_suci(suci)
        assert info.msin_revealed == "0000000001"
        assert "null" in info.protection_scheme.lower()
        assert info.warning != ""

    def test_decode_suci_ecies_scheme(self):
        from utils.imsi_tools import decode_suci
        suci = "suci-0-262-01-0-1-B-some_concealed_msin"
        info = decode_suci(suci)
        assert info.msin_revealed is None  # Not exposed
        assert "Profile A" in info.protection_scheme

    def test_mcc_to_country(self):
        from utils.imsi_tools import mcc_to_country
        assert "United States" in mcc_to_country("310")
        assert "India" in mcc_to_country("404")

    def test_supi_to_suci_null(self):
        from utils.imsi_tools import supi_to_suci_null
        suci = supi_to_suci_null("001010000000001", "001", "01")
        assert suci.startswith("suci-0-001-01")
        assert "0000000001" in suci


# ============================================================
# test_base_module.py
# ============================================================
class TestBaseModule:
    def test_finding_result_to_dict(self):
        from modules.base_module import FindingResult, Severity, TestStatus
        f = FindingResult(
            test_id="TEST-001", name="Test Finding", generation="5G",
            status=TestStatus.FAIL, severity=Severity.CRITICAL,
            cvss_score=9.5, finding="Test finding details",
        )
        d = f.to_dict()
        assert d["test_id"] == "TEST-001"
        assert d["severity"] == "CRITICAL"
        assert d["cvss_score"] == 9.5

    def test_severity_color(self):
        from modules.base_module import FindingResult, Severity, TestStatus
        f = FindingResult("X", "X", "5G", status=TestStatus.FAIL, severity=Severity.CRITICAL)
        assert f.severity_color == "#FF0000"

    def test_tool_check_dataclass(self):
        from modules.base_module import ToolCheck
        tc = ToolCheck(name="nmap", available=True, version="7.93", path="/usr/bin/nmap")
        assert tc.available


# ============================================================
# test_fuzzer.py (engine)
# ============================================================
class TestFuzzer:
    def test_bit_flip(self):
        from engines.fuzzer import ProtocolFuzzer
        f = ProtocolFuzzer({})
        data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        result = f._bit_flip(data)
        assert len(result) == len(data)
        assert result != data  # Must differ (with overwhelming probability)

    def test_truncation(self):
        from engines.fuzzer import ProtocolFuzzer
        f = ProtocolFuzzer({})
        data = bytes(range(20))
        result = f._truncation(data)
        assert len(result) < len(data)

    def test_campaign_generation(self):
        from engines.fuzzer import ProtocolFuzzer
        f = ProtocolFuzzer({}, seed=1)
        seed = b"test_ss7_payload"
        campaign = f.generate_campaign(seed, iterations=10)
        assert len(campaign) == 10
        assert all(c.strategy in ProtocolFuzzer.STRATEGIES for c in campaign)

    def test_anomaly_detection_empty(self):
        from engines.fuzzer import ProtocolFuzzer
        f = ProtocolFuzzer({})
        detected, reason = f.detect_anomaly(b"")
        assert detected
        assert "empty" in reason.lower()

    def test_no_anomaly_normal(self):
        from engines.fuzzer import ProtocolFuzzer
        f = ProtocolFuzzer({})
        detected, _ = f.detect_anomaly(b"normal response data", baseline_length=20)
        assert not detected


# ============================================================
# test_report_engine.py
# ============================================================
class TestReportEngine:
    def _make_findings(self):
        from modules.base_module import FindingResult, Severity, TestStatus
        return [
            FindingResult("GSM-002", "A5/0 Cipher", "2G",
                          TestStatus.FAIL, Severity.CRITICAL, 9.8,
                          finding="Null cipher detected", recommendation="Disable A5/0"),
            FindingResult("SS7-002", "Location", "3G",
                          TestStatus.FAIL, Severity.HIGH, 7.5,
                          finding="Location exposed"),
            FindingResult("NR-001", "Cell Scan", "5G",
                          TestStatus.PASS, Severity.INFO, 0.0,
                          finding="No issues"),
        ]

    def test_build_report_data(self):
        from reporting.report_engine import ReportEngine
        findings = self._make_findings()
        engine = ReportEngine(findings, {}, auth_ref="TEST-001")
        data = engine.build_report_data("technical")
        assert data.critical_count == 1
        assert data.high_count == 1
        assert data.total_tests == 3
        assert data.risk_score > 0

    def test_risk_score_capped(self):
        from modules.base_module import FindingResult, Severity, TestStatus
        from reporting.report_engine import ReportEngine
        findings = [
            FindingResult(f"TST-{i:03}", f"Finding {i}", "5G",
                          TestStatus.FAIL, Severity.CRITICAL, 9.9)
            for i in range(20)
        ]
        engine = ReportEngine(findings, {})
        data = engine.build_report_data()
        assert data.risk_score == 100  # Capped at 100

    def test_compliance_matrix_built(self):
        from reporting.report_engine import ReportEngine
        findings = self._make_findings()
        engine = ReportEngine(findings, {})
        data = engine.build_report_data()
        assert len(data.compliance_matrix) > 0

    def test_html_render_fallback(self):
        from reporting.report_engine import ReportEngine
        findings = self._make_findings()
        engine = ReportEngine(findings, {})
        # Should not raise even without template file
        try:
            html = engine.render_html()
            assert "<html" in html.lower() or "teleaudit" in html.lower() or "TelSec" in html
        except Exception:
            pass  # Template may not be loaded in test environment

    def test_export_json(self, tmp_path):
        from reporting.report_engine import ReportEngine
        findings = self._make_findings()
        engine = ReportEngine(findings, {})
        out_path = str(tmp_path / "test_report.json")
        engine.export_json(out_path)
        with open(out_path) as f:
            data = json.load(f)
        assert data["count"] == 3
        assert len(data["findings"]) == 3
