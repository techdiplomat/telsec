"""
TelSec - PDF Report Exporter
==============================
Generates professional PDF audit reports using ReportLab.
Color-coded severity sections, CVSSv3 vector strings,
GSMA compliance matrix, recommendations table.
"""

from __future__ import annotations

import io
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False

from modules.base_module import FindingResult, Severity, TestStatus
from reporting.report_engine import ReportData
from utils.logger import get_logger

logger = get_logger("pdf_exporter")

# Colors
C_PRIMARY    = colors.HexColor("#1a1a2e")
C_SECONDARY  = colors.HexColor("#16213e")
C_ACCENT     = colors.HexColor("#0f3460")
C_CRITICAL   = colors.HexColor("#dc2626")
C_HIGH       = colors.HexColor("#ea580c")
C_MEDIUM     = colors.HexColor("#d97706")
C_LOW        = colors.HexColor("#2563eb")
C_INFO       = colors.HexColor("#6b7280")
C_PASS       = colors.HexColor("#16a34a")
C_FAIL       = colors.HexColor("#dc2626")
C_WHITE      = colors.white
C_LIGHT_GRAY = colors.HexColor("#f8f8f8")


def _severity_color(severity: str) -> object:
    return {
        "CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
        "MEDIUM": C_MEDIUM, "LOW": C_LOW, "INFO": C_INFO,
    }.get(severity.upper(), C_INFO)


class PDFExporter:
    """Generate a full audit PDF from a ReportData object."""

    def __init__(self, report_data: ReportData, logo_path: Optional[str] = None):
        if not _HAS_REPORTLAB:
            raise ImportError(
                "reportlab not installed. Run: pip install reportlab"
            )
        self.data = report_data
        self.logo_path = logo_path
        self.styles = getSampleStyleSheet()
        self._build_styles()

    def _build_styles(self) -> None:
        """Define custom paragraph styles."""
        self.style_h1 = ParagraphStyle(
            "H1Tel", parent=self.styles["Heading1"],
            fontSize=22, textColor=C_WHITE, backColor=C_PRIMARY,
            spaceBefore=0, spaceAfter=6, leftIndent=10, rightIndent=10,
            leading=28,
        )
        self.style_h2 = ParagraphStyle(
            "H2Tel", parent=self.styles["Heading2"],
            fontSize=14, textColor=C_PRIMARY,
            spaceBefore=12, spaceAfter=6, borderPad=4,
        )
        self.style_body = ParagraphStyle(
            "BodyTel", parent=self.styles["Normal"],
            fontSize=9, leading=13, spaceAfter=4,
        )
        self.style_finding_title = ParagraphStyle(
            "FindTitle", parent=self.styles["Normal"],
            fontSize=10, textColor=C_PRIMARY, leading=14,
            fontName="Helvetica-Bold",
        )
        self.style_code = ParagraphStyle(
            "Code", parent=self.styles["Code"],
            fontSize=7, backColor=C_LIGHT_GRAY, leading=10,
            leftIndent=6, rightIndent=6,
        )
        self.style_cover_title = ParagraphStyle(
            "CoverTitle", parent=self.styles["Normal"],
            fontSize=28, textColor=C_WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=10,
        )
        self.style_cover_sub = ParagraphStyle(
            "CoverSub", parent=self.styles["Normal"],
            fontSize=13, textColor=colors.HexColor("#aaaacc"),
            alignment=TA_CENTER, spaceAfter=6,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export(self, output_path: str) -> str:
        """
        Generate PDF to output_path.

        Args:
            output_path: Full path of output .pdf file

        Returns:
            Absolute path of generated PDF
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            leftMargin=2.2 * cm,
            rightMargin=2.2 * cm,
            title=self.data.title,
            author=self.data.auditor,
            subject="Telecom Security Audit",
            creator="TelSec v1.0.0",
        )

        story = []
        story += self._cover_page()
        story.append(PageBreak())
        story += self._exec_summary()
        story.append(PageBreak())
        story += self._scope_section()
        story += self._findings_section()
        story.append(PageBreak())
        story += self._compliance_matrix()
        story.append(PageBreak())
        story += self._recommendations()
        story += self._appendix()

        doc.build(story, onFirstPage=self._add_header_footer,
                  onLaterPages=self._add_header_footer)

        logger.info(f"PDF report generated: {output_path}")
        return os.path.abspath(output_path)

    def export_bytes(self) -> bytes:
        """Return PDF as raw bytes (for Streamlit download button)."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        story = (
            self._cover_page()
            + [PageBreak()]
            + self._exec_summary()
            + [PageBreak()]
            + self._findings_section()
        )
        doc.build(story)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _cover_page(self) -> list:
        items = []
        items.append(Spacer(1, 3 * cm))
        items.append(Paragraph("TelSec", self.style_cover_title))
        items.append(Paragraph(self.data.title, self.style_cover_sub))
        items.append(Spacer(1, 1 * cm))
        meta = [
            ["Company:", self.data.company],
            ["Date:", self.data.generated_at],
            ["Auditor:", self.data.auditor],
            ["Classification:", self.data.classification],
            ["Auth Reference:", self.data.auth_ref or "N/A"],
            ["Risk Score:", f"{self.data.risk_score}/100"],
        ]
        t = Table(meta, colWidths=[5 * cm, 10 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), C_SECONDARY),
            ("TEXTCOLOR", (0, 0), (0, -1), C_WHITE),
            ("TEXTCOLOR", (1, 0), (1, -1), C_PRIMARY),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (1, 0), (1, -1), [C_LIGHT_GRAY, C_WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        items.append(t)
        return items

    def _exec_summary(self) -> list:
        items = [Paragraph("Executive Summary", self.style_h2)]
        items.append(HRFlowable(width="100%", color=C_ACCENT))
        items.append(Spacer(1, 4 * mm))

        summary_text = (
            f"This report presents the results of a telecom security audit performed "
            f"on <b>{self.data.target_description}</b> on {self.data.generated_at}. "
            f"A total of <b>{self.data.total_tests}</b> tests were executed across "
            f"2G/GSM, 3G/SS7, 4G/LTE, and 5G/NR protocol stacks."
        )
        items.append(Paragraph(summary_text, self.style_body))
        items.append(Spacer(1, 4 * mm))

        sev_data = [
            ["Severity", "Count", "Impact"],
            ["CRITICAL", str(self.data.critical_count), "Immediate action required"],
            ["HIGH", str(self.data.high_count), "Address within 30 days"],
            ["MEDIUM", str(self.data.medium_count), "Address within 90 days"],
            ["LOW", str(self.data.low_count), "Address in next maintenance window"],
        ]
        t = Table(sev_data, colWidths=[4 * cm, 3 * cm, 9 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#fff0f0")),
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fff5f0")),
            ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fffbf0")),
            ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#f0f5ff")),
            ("TEXTCOLOR", (0, 1), (0, 1), C_CRITICAL),
            ("TEXTCOLOR", (0, 2), (0, 2), C_HIGH),
            ("TEXTCOLOR", (0, 3), (0, 3), C_MEDIUM),
            ("TEXTCOLOR", (0, 4), (0, 4), C_LOW),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        items.append(t)
        return items

    def _scope_section(self) -> list:
        items = [Paragraph("Scope & Methodology", self.style_h2)]
        items.append(HRFlowable(width="100%", color=C_ACCENT))
        items.append(Spacer(1, 4 * mm))
        items.append(Paragraph(
            f"<b>Target:</b> {self.data.target_description}", self.style_body
        ))
        tools_str = ", ".join(self.data.tools_used) if self.data.tools_used else "N/A"
        items.append(Paragraph(f"<b>Tools Used:</b> {tools_str}", self.style_body))
        items.append(Paragraph(
            f"<b>Tests Performed:</b> {self.data.total_tests} | "
            f"Passed: {self.data.passed_tests} | Failed: {self.data.failed_tests}",
            self.style_body,
        ))
        return items

    def _findings_section(self) -> list:
        items = [Paragraph("Security Findings", self.style_h2)]
        items.append(HRFlowable(width="100%", color=C_ACCENT))

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            sev_findings = [
                f for f in self.data.findings
                if f.severity == sev and f.status == TestStatus.FAIL
            ]
            if not sev_findings:
                continue
            items.append(Paragraph(
                f"{sev.value} Findings ({len(sev_findings)})", self.style_h2
            ))
            for finding in sev_findings:
                items += self._finding_card(finding)
        return items

    def _finding_card(self, f: FindingResult) -> list:
        sev_color = _severity_color(f.severity.value)
        items = []
        items.append(Spacer(1, 4 * mm))

        header_data = [[
            Paragraph(f"[{f.test_id}] {f.name}", self.style_finding_title),
            Paragraph(f.severity.value, ParagraphStyle(
                "SevBadge", fontSize=9, textColor=C_WHITE,
                backColor=sev_color, alignment=TA_CENTER,
            )),
        ]]
        ht = Table(header_data, colWidths=[13 * cm, 3 * cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_LIGHT_GRAY),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        items.append(ht)

        detail_rows = [
            ["CVSS Score", str(f.cvss_score), "CVE", f.cve or "N/A"],
            ["GSMA Ref", f.gsma_ref or "N/A", "3GPP Ref", f.threegpp_ref or "N/A"],
            ["Generation", f.generation, "Component", f.affected_component or "N/A"],
        ]
        dt = Table(detail_rows, colWidths=[3 * cm, 5 * cm, 3 * cm, 5 * cm])
        dt.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (0, -1), C_LIGHT_GRAY),
            ("BACKGROUND", (2, 0), (2, -1), C_LIGHT_GRAY),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        items.append(dt)

        for label, text in [
            ("Finding", f.finding),
            ("Impact", f.impact),
            ("Recommendation", f.recommendation),
        ]:
            if text:
                items.append(Paragraph(f"<b>{label}:</b> {text}", self.style_body))

        return items

    def _compliance_matrix(self) -> list:
        items = [Paragraph("GSMA Compliance Matrix", self.style_h2)]
        items.append(HRFlowable(width="100%", color=C_ACCENT))
        items.append(Spacer(1, 4 * mm))

        header = [["Req. ID", "Document", "Category", "Status"]]
        rows = header + [
            [
                item.requirement_id, item.doc,
                Paragraph(item.category[:50], self.style_body),
                item.status,
            ]
            for item in self.data.compliance_matrix
        ]

        t = Table(rows, colWidths=[3 * cm, 3 * cm, 9 * cm, 2.5 * cm])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), C_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT_GRAY]),
        ]
        for i, item in enumerate(self.data.compliance_matrix, start=1):
            color = {"PASS": C_PASS, "FAIL": C_FAIL}.get(item.status, C_INFO)
            style.append(("TEXTCOLOR", (3, i), (3, i), color))
            style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        items.append(t)
        return items

    def _recommendations(self) -> list:
        items = [Paragraph("Recommendations Roadmap", self.style_h2)]
        items.append(HRFlowable(width="100%", color=C_ACCENT))
        items.append(Spacer(1, 4 * mm))

        critical = [f for f in self.data.findings
                    if f.severity == Severity.CRITICAL and f.status == TestStatus.FAIL]
        high = [f for f in self.data.findings
                if f.severity == Severity.HIGH and f.status == TestStatus.FAIL]

        for label, findings, timeline in [
            ("Immediate Actions (Critical)", critical, "Within 24–72 hours"),
            ("Short-term Actions (High)", high, "Within 30 days"),
        ]:
            if findings:
                items.append(Paragraph(f"<b>{label}</b> — {timeline}", self.style_body))
                for f in findings:
                    items.append(Paragraph(
                        f"• [{f.test_id}] {f.recommendation}", self.style_body
                    ))
                items.append(Spacer(1, 3 * mm))
        return items

    def _appendix(self) -> list:
        return [
            PageBreak(),
            Paragraph("Technical Appendix", self.style_h2),
            HRFlowable(width="100%", color=C_ACCENT),
            Spacer(1, 4 * mm),
            Paragraph(
                "Full raw tool output and PCAP file references are available "
                "in the JSON export and the reports/ directory.",
                self.style_body,
            ),
        ]

    def _add_header_footer(self, canvas, doc) -> None:
        """Add page header and footer."""
        canvas.saveState()
        # Header
        canvas.setFillColor(C_PRIMARY)
        canvas.rect(0, A4[1] - 1.5 * cm, A4[0], 1.5 * cm, fill=True, stroke=False)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(2.2 * cm, A4[1] - 1 * cm, "TelSec — Telecom Security Audit")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            A4[0] - 2.2 * cm, A4[1] - 1 * cm, self.data.classification
        )
        # Footer
        canvas.setFillColor(C_LIGHT_GRAY)
        canvas.rect(0, 0, A4[0], 1.2 * cm, fill=True, stroke=False)
        canvas.setFillColor(C_INFO)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(2.2 * cm, 0.45 * cm,
                          f"Generated: {self.data.generated_at} | "
                          f"TelSec v1.0.0 | For authorized use only")
        canvas.drawRightString(A4[0] - 2.2 * cm, 0.45 * cm,
                               f"Page {canvas.getPageNumber()}")
        canvas.restoreState()
