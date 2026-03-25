"""
TelSec - Reporting Engine
==========================
Aggregates findings from all module runs and produces:
  - Structured report data model
  - GSMA compliance matrix
  - CVSS scoring summary
  - HTML report (via Jinja2)
  - PDF export (via ReportLab)

Usage:
    engine = ReportEngine(findings, config)
    html = engine.render_html()
    engine.export_pdf("reports/audit_report.pdf")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from modules.base_module import FindingResult, Severity, TestStatus
from utils.logger import get_logger

logger = get_logger("report_engine")

TEMPLATES_DIR = Path(__file__).parent / "templates"

# ---------------------------------------------------------------------------
# GSMA compliance requirements database
# ---------------------------------------------------------------------------

GSMA_REQUIREMENTS: List[Dict[str, str]] = [
    {"id": "FS.11-C1", "doc": "FS.11", "category": "1 - Subscriber Privacy",
     "req": "IMSI shall not be disclosed over signaling interfaces"},
    {"id": "FS.11-C2", "doc": "FS.11", "category": "2 - Authentication",
     "req": "Authentication vectors must not be retrievable via MAP"},
    {"id": "FS.11-C3", "doc": "FS.11", "category": "3 - Integrity",
     "req": "Signaling messages must be integrity protected"},
    {"id": "FS.11-C4", "doc": "FS.11", "category": "4 - Location",
     "req": "Location data must not be disclosed without authorization"},
    {"id": "FS.11-C5", "doc": "FS.11", "category": "5 - SMS",
     "req": "SMS routing must be protected against interception"},
    {"id": "FS.11-C6", "doc": "FS.11", "category": "6 - Fraud",
     "req": "Signaling must be protected against toll fraud"},
    {"id": "FS.11-C7", "doc": "FS.11", "category": "7 - Availability",
     "req": "Network must be protected against DoS via signaling"},
    {"id": "FS.19-D1", "doc": "FS.19", "category": "Diameter Security",
     "req": "Diameter interconnect must use TLS/DTLS"},
    {"id": "FS.37-R1", "doc": "FS.37", "category": "5G Roaming",
     "req": "SEPP must be deployed for 5G roaming security"},
    {"id": "FS.40-5G1", "doc": "FS.40", "category": "5G Core",
     "req": "NF service authorization must use OAuth2/TLS"},
    {"id": "TS33.501-A1", "doc": "3GPP TS 33.501", "category": "SUCI",
     "req": "SUCI protection scheme must not be null (scheme 0) in production"},
    {"id": "TS33.401-E1", "doc": "3GPP TS 33.401", "category": "LTE Encryption",
     "req": "EEA0 (null cipher) must not be accepted in production"},
    {"id": "TS33.102-G1", "doc": "3GPP TS 33.102", "category": "GSM Cipher",
     "req": "A5/0 (no encryption) must not be accepted"},
]

# Mapping: test_id prefix → GSMA requirement IDs
FINDING_TO_GSMA: Dict[str, List[str]] = {
    "GSM-001": ["TS33.102-G1"],
    "GSM-002": ["TS33.102-G1", "FS.11-C1"],
    "GSM-003": ["FS.11-C1"],
    "GSM-004": ["FS.11-C1"],
    "SS7-001": ["FS.11-C3"],
    "SS7-002": ["FS.11-C4"],
    "SS7-003": ["FS.11-C5"],
    "SS7-005": ["FS.11-C7"],
    "SS7-006": ["FS.11-C1"],
    "SS7-009": ["FS.11-C2"],
    "LTE-002": ["FS.11-C1"],
    "LTE-003": ["FS.19-D1"],
    "LTE-004": ["FS.11-C7"],
    "LTE-005": ["FS.11-C2"],
    "LTE-006": ["TS33.401-E1"],
    "NR-002": ["TS33.501-A1"],
    "NR-003": ["TS33.501-A1"],
    "NR-005": ["FS.40-5G1"],
    "NR-006": ["FS.40-5G1"],
    "NR-007": ["FS.37-R1"],
}


@dataclass
class ComplianceItem:
    """Single GSMA compliance matrix row."""
    requirement_id: str
    doc: str
    category: str
    requirement: str
    test_ids: List[str] = field(default_factory=list)
    status: str = "NOT_TESTED"   # PASS | FAIL | NOT_TESTED | PARTIAL


@dataclass
class ReportData:
    """Complete structured report data."""
    title: str
    company: str
    auditor: str
    target_description: str
    classification: str
    generated_at: str
    auth_ref: str
    risk_score: int                   # 0-100
    findings: List[FindingResult]
    tools_used: List[str]
    compliance_matrix: List[ComplianceItem]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_tests: int
    passed_tests: int
    failed_tests: int
    top_findings: List[FindingResult] = field(default_factory=list)


class ReportEngine:
    """
    Builds a ReportData object from raw FindingResults and renders reports.
    """

    def __init__(
        self,
        findings: List[FindingResult],
        config: Dict[str, Any],
        auth_ref: str = "",
        auditor: str = "TelSec",
        target_description: str = "Authorized lab environment",
    ):
        self.findings = findings
        self.config = config
        self.auth_ref = auth_ref
        self.auditor = auditor
        self.target_description = target_description

        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self._env.filters["severity_color"] = self._severity_color
        self._env.filters["cvss_badge"] = self._cvss_badge

        logger.info(f"ReportEngine initialized with {len(findings)} findings")

    # ------------------------------------------------------------------
    # Data assembly
    # ------------------------------------------------------------------

    def build_report_data(
        self,
        report_type: str = "technical",
        company: Optional[str] = None,
    ) -> ReportData:
        """
        Assemble all report data from findings.

        Args:
            report_type: 'technical' | 'executive' | 'gsma' | '5g'
            company:     Override company name

        Returns:
            ReportData populated from findings
        """
        company = company or self.config.get("reporting", {}).get(
            "company_name", "Unknown"
        )
        classification = self.config.get("reporting", {}).get(
            "classification", "CONFIDENTIAL"
        )

        counts = self._count_by_severity()
        risk_score = self._calculate_risk_score(counts)
        compliance = self._build_compliance_matrix()

        # Sort findings by CVSS score descending
        sorted_findings = sorted(
            self.findings, key=lambda f: f.cvss_score, reverse=True
        )
        top_findings = [f for f in sorted_findings if f.status == TestStatus.FAIL][:5]

        tools_used = list({f.tool_used for f in self.findings if f.tool_used})

        passed = sum(1 for f in self.findings if f.status == TestStatus.PASS)
        failed = sum(1 for f in self.findings if f.status == TestStatus.FAIL)

        return ReportData(
            title=self._report_title(report_type),
            company=company,
            auditor=self.auditor,
            target_description=self.target_description,
            classification=classification,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            auth_ref=self.auth_ref,
            risk_score=risk_score,
            findings=sorted_findings,
            tools_used=tools_used,
            compliance_matrix=compliance,
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            info_count=counts["INFO"],
            total_tests=len(self.findings),
            passed_tests=passed,
            failed_tests=failed,
            top_findings=top_findings,
        )

    def _count_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.status == TestStatus.FAIL:
                counts[f.severity.value] += 1
        return counts

    def _calculate_risk_score(self, counts: Dict[str, int]) -> int:
        """Calculate 0–100 risk score from finding counts."""
        score = (
            counts["CRITICAL"] * 25
            + counts["HIGH"] * 10
            + counts["MEDIUM"] * 4
            + counts["LOW"] * 1
        )
        return min(100, score)

    def _build_compliance_matrix(self) -> List[ComplianceItem]:
        """Map findings to GSMA requirements."""
        items = []
        failing_test_ids = {
            f.test_id for f in self.findings if f.status == TestStatus.FAIL
        }
        tested_ids = {f.test_id for f in self.findings}

        for req in GSMA_REQUIREMENTS:
            mapped_tests = FINDING_TO_GSMA.get(req["id"], [])
            item = ComplianceItem(
                requirement_id=req["id"],
                doc=req["doc"],
                category=req["category"],
                requirement=req["req"],
                test_ids=mapped_tests,
            )
            if not mapped_tests:
                item.status = "NOT_TESTED"
            elif any(t in failing_test_ids for t in mapped_tests):
                item.status = "FAIL"
            elif all(t in tested_ids for t in mapped_tests):
                item.status = "PASS"
            else:
                item.status = "PARTIAL"
            items.append(item)
        return items

    def _report_title(self, report_type: str) -> str:
        titles = {
            "technical": "Telecom Security Penetration Test Report",
            "executive": "Executive Security Assessment Summary",
            "gsma": "GSMA Compliance Assessment Report",
            "5g": "5G Security Assessment (ETSI TS 33.501)",
        }
        return titles.get(report_type, "TelSec Security Report")

    # ------------------------------------------------------------------
    # Template rendering
    # ------------------------------------------------------------------

    def render_html(
        self,
        report_type: str = "technical",
        company: Optional[str] = None,
    ) -> str:
        """
        Render findings to HTML using Jinja2.

        Returns:
            HTML string
        """
        data = self.build_report_data(report_type=report_type, company=company)
        template_name = (
            "executive_summary.html.j2"
            if report_type == "executive"
            else "report.html.j2"
        )
        try:
            template = self._env.get_template(template_name)
            html = template.render(report=data)
            logger.info(f"HTML report rendered ({len(html)} chars)")
            return html
        except Exception as exc:
            logger.error(f"HTML render failed: {exc}")
            # Fallback to basic HTML
            return self._fallback_html(data)

    def _fallback_html(self, data: ReportData) -> str:
        """Generate basic HTML when template is unavailable."""
        rows = ""
        for f in data.findings:
            color = f.severity_color
            rows += (
                f"<tr><td>{f.test_id}</td><td>{f.name}</td>"
                f"<td style='color:{color}'>{f.severity.value}</td>"
                f"<td>{f.cvss_score}</td><td>{f.status.value}</td>"
                f"<td>{f.finding[:100]}</td></tr>"
            )
        return f"""<!DOCTYPE html>
<html><head><meta charset='UTF-8'><title>{data.title}</title>
<style>body{{font-family:Arial;margin:40px;}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;}}
th{{background:#1a1a2e;color:white;}}</style>
</head><body>
<h1>{data.title}</h1>
<p><b>Company:</b> {data.company} | <b>Date:</b> {data.generated_at} |
<b>Risk Score:</b> {data.risk_score}/100</p>
<h2>Findings Summary</h2>
<p>Critical: {data.critical_count} | High: {data.high_count} |
Medium: {data.medium_count} | Low: {data.low_count}</p>
<table><tr><th>Test ID</th><th>Name</th><th>Severity</th>
<th>CVSS</th><th>Status</th><th>Finding</th></tr>
{rows}</table>
</body></html>"""

    def export_json(self, output_path: str) -> str:
        """Export findings as JSON."""
        data = [f.to_dict() for f in self.findings]
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump({"findings": data, "count": len(data)}, fh, indent=2)
        logger.info(f"JSON report saved: {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # Jinja2 filters
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280",
        }.get(severity.upper(), "#6b7280")

    @staticmethod
    def _cvss_badge(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "INFO"
