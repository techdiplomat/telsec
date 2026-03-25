"""
TelSec — TstpRunner Engine
===========================
Reusable class used by all TelSec audit pages to render and store
test procedures in the TEC/DOT India + 3GPP TS 33.117 SCAS format.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import streamlit as st

# ── Severity colour palette ───────────────────────────────────────────────────
SEV_COLORS: Dict[str, str] = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#ca8a04",
    "Low":      "#16a34a",
    "Info":     "#2563eb",
}
SEV_BG: Dict[str, str] = {
    "Critical": "#fef2f2",
    "High":     "#fff7ed",
    "Medium":   "#fefce8",
    "Low":      "#f0fdf4",
    "Info":     "#eff6ff",
}

# ── Status badge helpers ──────────────────────────────────────────────────────
STATUS_COLOR = {"PASS": "#16a34a", "FAIL": "#dc2626", "PENDING": "#6b7280", "TESTED": "#2563eb"}


def _badge(label: str, color: str, bg: str = "transparent") -> str:
    return (
        f"<span style='background:{bg};color:{color};border:1.5px solid {color};"
        f"padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:600;"
        f"letter-spacing:0.04em'>{label}</span>"
    )


def _sev_badge(severity: str) -> str:
    c = SEV_COLORS.get(severity, "#6b7280")
    return _badge(severity.upper(), "#fff", c)


# ── Dataclass ─────────────────────────────────────────────────────────────────
@dataclass
class TstpRunner:
    """One complete test case in SCAS/TEC/DOT format."""
    test_id:         str
    test_name:       str
    purpose:         str
    what_tested:     str
    preconditions:   List[str]
    execution_steps: List[str]
    where_tested:    str
    when_to_run:     str
    pass_criteria:   List[str]
    fail_criteria:   List[str]
    evidence_format: str
    severity:        str
    references:      List[str]
    # optional extras kept for compatibility with older tstp_data.py entries
    cvss:            Optional[str] = None
    duration:        Optional[str] = None
    environment:     Optional[str] = None

    # ── Session-state key helpers ────────────────────────────────────────────
    def _verdict_key(self) -> str:
        return f"verdict_{self.test_id}"

    def _tested_key(self) -> str:
        return f"tested_{self.test_id}"

    # ── render_tstp_card ─────────────────────────────────────────────────────
    def render_tstp_card(self) -> None:
        """Render a full Streamlit TSTP card for this test case."""
        sev_col = SEV_COLORS.get(self.severity, "#6b7280")
        sev_bg  = SEV_BG.get(self.severity, "#f9fafb")

        # ── Header ──────────────────────────────────────────────────────────
        hdr_cols = st.columns([3, 1])
        with hdr_cols[0]:
            st.markdown(
                f"<div style='border-left:4px solid {sev_col};padding-left:12px'>"
                f"<h4 style='margin:0'>{self.test_id}</h4>"
                f"<p style='margin:2px 0;font-size:0.95rem;color:#94a3b8'>{self.test_name}</p>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with hdr_cols[1]:
            st.markdown(
                f"<div style='text-align:right;padding-top:8px'>{_sev_badge(self.severity)}</div>",
                unsafe_allow_html=True,
            )

        # ── Meta row ────────────────────────────────────────────────────────
        m1, m2, m3 = st.columns(3)
        if self.duration:
            m1.metric("⏱ Duration", self.duration)
        if self.environment:
            m2.metric("🌐 Env", self.environment[:28])
        if self.cvss:
            m3.metric("🎯 CVSS", self.cvss.split()[0])

        # ── Purpose / What ──────────────────────────────────────────────────
        with st.expander("🎯 Purpose & What is Tested", expanded=True):
            st.markdown(f"**Purpose:** {self.purpose}")
            st.markdown(f"**What Tested:** `{self.what_tested}`")
            st.markdown(f"**Where:** `{self.where_tested}`")
            st.markdown(f"**When:** {self.when_to_run}")

        # ── Pre-conditions ───────────────────────────────────────────────────
        with st.expander("📋 Pre-conditions"):
            for i, p in enumerate(self.preconditions, 1):
                st.markdown(f"{i}. {p}")

        # ── Execution Steps ──────────────────────────────────────────────────
        with st.expander("🔬 Execution Steps", expanded=True):
            for step in self.execution_steps:
                st.markdown(f"> {step}")

        # ── Pass / Fail ──────────────────────────────────────────────────────
        pc_col, fc_col = st.columns(2)
        with pc_col:
            with st.expander("✅ Pass Criteria"):
                for c in self.pass_criteria:
                    st.success(c)
        with fc_col:
            with st.expander("❌ Fail Criteria"):
                for c in self.fail_criteria:
                    st.error(c)

        # ── Evidence & References ────────────────────────────────────────────
        with st.expander("📁 Evidence & References"):
            st.markdown(f"**Evidence Format:** {self.evidence_format}")
            for ref in self.references:
                st.markdown(f"- {ref}")

        # ── Pass/Fail toggle + Mark as Tested ────────────────────────────────
        v_key = self._verdict_key()
        t_key = self._tested_key()
        if v_key not in st.session_state:
            st.session_state[v_key] = "PENDING"
        if t_key not in st.session_state:
            st.session_state[t_key] = False

        action_cols = st.columns([1, 1, 1, 1])
        cur_verdict = st.session_state[v_key]

        with action_cols[0]:
            if st.button("✅ Mark PASS", key=f"pass_btn_{self.test_id}_{uuid.uuid4().hex[:8]}", use_container_width=True):
                st.session_state[v_key] = "PASS"
        with action_cols[1]:
            if st.button("❌ Mark FAIL", key=f"fail_btn_{self.test_id}_{uuid.uuid4().hex[:8]}", use_container_width=True):                st.session_state[v_key] = "FAIL"
        with action_cols[2]:
            st.session_state[t_key] = st.checkbox(
                "Tested", value=st.session_state[t_key], key=f"chk_{self.test_id}_{uuid.uuid4().hex[:8]}"
            )
        with action_cols[3]:
            json_bytes = json.dumps(self.to_dict(), indent=2).encode()
            st.download_button(
                "⬇ JSON",
                data=json_bytes,
                file_name=f"{self.test_id}.json",
                mime="application/json",
            key=f"dl_{self.test_id}_{uuid.uuid4().hex[:8]}",                use_container_width=True,
            )

        verdict_col = STATUS_COLOR.get(cur_verdict, "#6b7280")
        st.markdown(
            f"<div style='margin-top:4px;text-align:right'>"
            f"Current status: {_badge(cur_verdict, verdict_col)}</div>",
            unsafe_allow_html=True,
        )
        st.divider()

    # ── Conversion ───────────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_tstp_entry(test_id: str, entry: Dict[str, Any]) -> "TstpRunner":
        """Build a TstpRunner from a tstp_data.py entry (legacy or new format)."""
        # Normalise old-format string pass/fail criteria to lists
        def _to_list(v):
            if v is None:
                return []
            if isinstance(v, list):
                return v
            return [str(v)]

        return TstpRunner(
            test_id=test_id,
            test_name=entry.get("title") or entry.get("test_name", ""),
            purpose=entry.get("purpose") or entry.get("what", ""),
            what_tested=entry.get("what_tested") or entry.get("where", ""),
            preconditions=_to_list(entry.get("preconditions")),
            execution_steps=_to_list(entry.get("execution_steps") or entry.get("how")),
            where_tested=entry.get("where_tested") or entry.get("where", ""),
            when_to_run=entry.get("when_to_run") or entry.get("when", ""),
            pass_criteria=_to_list(entry.get("pass_criteria")),
            fail_criteria=_to_list(entry.get("fail_criteria")),
            evidence_format=entry.get("evidence_format") or
                            entry.get("evidence", "Wireshark PCAP / System Logs"),
            severity=entry.get("severity") or entry.get("severity_if_fail", "Medium"),
            references=_to_list(entry.get("references") or
                                 [entry.get("standard", "")]),
            cvss=entry.get("cvss"),
            duration=entry.get("duration"),
            environment=entry.get("environment"),
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def render_tstp_card(test: Dict[str, Any], test_id: str) -> None:
    """Convenience wrapper: build TstpRunner from dict and render card."""
    TstpRunner.from_tstp_entry(test_id, test).render_tstp_card()


def render_tstp_table(tests: List[Dict[str, Any]]) -> None:
    """Render a filtered st.dataframe of all test cases."""
    import pandas as pd

    rows = []
    for tid, entry in tests.items():
        verdict = st.session_state.get(f"verdict_{tid}", "PENDING")
        rows.append({
            "Test ID": tid,
            "Name": entry.get("title") or entry.get("test_name", ""),
            "Severity": entry.get("severity") or entry.get("severity_if_fail", ""),
            "Where": (entry.get("where_tested") or entry.get("where", ""))[:50],
            "Status": verdict,
        })
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("No tests to display.")
        return

    col_cfg = {
        "Severity": st.column_config.TextColumn("Severity", width="small"),
        "Status":   st.column_config.TextColumn("Status",   width="small"),
    }
    st.dataframe(df, use_container_width=True, column_config=col_cfg, hide_index=True)


def get_verdict(test_id: str, result: Dict[str, Any], pass_criteria: List[str]) -> str:
    """Return 'PASS' or 'FAIL' by checking result dict against pass_criteria keywords."""
    result_str = json.dumps(result).lower()
    hits = sum(1 for c in pass_criteria if any(
        kw.lower() in result_str for kw in c.split()[:4]
    ))
    return "PASS" if hits >= max(1, len(pass_criteria) // 2) else "FAIL"


def export_tstp_report(tests: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Export full TSTP report dict (for JSON download)."""
    entries = {}
    for tid, entry in tests.items():
        entries[tid] = {
            **entry,
            "verdict": st.session_state.get(f"verdict_{tid}", "PENDING"),
            "tested":  st.session_state.get(f"tested_{tid}", False),
        }
    return {
        "report_type": "TelSec TSTP Audit Report",
        "generated":   __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "total_tests": len(entries),
        "pass_count":  sum(1 for e in entries.values() if e["verdict"] == "PASS"),
        "fail_count":  sum(1 for e in entries.values() if e["verdict"] == "FAIL"),
        "tests":       entries,
    }
