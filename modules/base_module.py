"""
TelSec - Base Module Abstract Class
====================================
All generation modules (2G/3G/4G/5G) inherit from BaseModule.
Provides a uniform interface for running tests, reporting findings,
and checking tool availability.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger("base_module")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TestStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


@dataclass
class FindingResult:
    """Standard result object returned by every test case."""
    test_id: str
    name: str
    generation: str                          # 2G | 3G | 4G | 5G
    status: TestStatus = TestStatus.SKIPPED
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve: str = ""
    gsma_ref: str = ""
    threegpp_ref: str = ""                   # e.g. TS 33.501 clause 6.1.3
    affected_component: str = ""
    finding: str = ""
    impact: str = ""
    recommendation: str = ""
    raw_output: str = ""
    pcap_file: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: float = 0.0
    tool_used: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain dict for JSON/DB storage."""
        return {
            "test_id": self.test_id,
            "name": self.name,
            "generation": self.generation,
            "status": self.status.value,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve": self.cve,
            "gsma_ref": self.gsma_ref,
            "threegpp_ref": self.threegpp_ref,
            "affected_component": self.affected_component,
            "finding": self.finding,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "raw_output": self.raw_output[:4096],  # Truncate for DB
            "pcap_file": self.pcap_file,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "tool_used": self.tool_used,
            "extra": self.extra,
        }

    @property
    def severity_color(self) -> str:
        """Return a hex color for UI display."""
        return {
            Severity.CRITICAL: "#FF0000",
            Severity.HIGH: "#FF6600",
            Severity.MEDIUM: "#FFAA00",
            Severity.LOW: "#0088FF",
            Severity.INFO: "#888888",
        }.get(self.severity, "#888888")


@dataclass
class ToolCheck:
    """Result of checking whether a tool is installed."""
    name: str
    available: bool
    version: str = ""
    path: str = ""
    install_hint: str = ""


class BaseModule(ABC):
    """
    Abstract base class for TelSec audit modules.

    Subclasses MUST implement:
        - module_id (class-level str attribute)
        - generation (class-level str: '2G'|'3G'|'4G'|'5G')
        - run_tests() coroutine → List[FindingResult]
        - check_tools() → List[ToolCheck]
    """

    module_id: str = "BASE"
    generation: str = "UNKNOWN"
    description: str = "Base module"

    def __init__(self, config: Dict[str, Any], authorization_ref: str = ""):
        self.config = config
        self.authorization_ref = authorization_ref
        self.results: List[FindingResult] = []
        self._running = False
        self._paused = False
        self._stop_requested = False
        self.logger = get_logger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def run_tests(
        self,
        selected_tests: Optional[List[str]] = None,
        passive_only: bool = False,
    ) -> List[FindingResult]:
        """
        Execute all (or selected) test cases asynchronously.

        Args:
            selected_tests: List of test IDs to run. None = run all.
            passive_only:   If True, skip any active probe tests.

        Returns:
            List of FindingResult objects.
        """
        ...

    @abstractmethod
    def check_tools(self) -> List[ToolCheck]:
        """Return availability status for all tools this module needs."""
        ...

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    def _make_result(self, test_id: str, name: str, **kwargs) -> FindingResult:
        """Factory for FindingResult with module defaults pre-filled."""
        return FindingResult(
            test_id=test_id,
            name=name,
            generation=self.generation,
            **kwargs,
        )

    def _tool_missing_result(
        self, test_id: str, name: str, tool_name: str
    ) -> FindingResult:
        """Return a NOT_AVAILABLE result when a required tool is absent."""
        return self._make_result(
            test_id=test_id,
            name=name,
            status=TestStatus.NOT_AVAILABLE,
            severity=Severity.INFO,
            finding=f"Required tool '{tool_name}' is not installed.",
            recommendation=f"Install '{tool_name}' and re-run this test.",
            tool_used=tool_name,
        )

    def _check_authorization(self, test_id: str, name: str) -> Optional[FindingResult]:
        """
        Return an ERROR result if active test is attempted without auth.
        Returns None if authorization is valid.
        """
        if not self.authorization_ref:
            return self._make_result(
                test_id=test_id,
                name=name,
                status=TestStatus.ERROR,
                severity=Severity.INFO,
                finding=(
                    "Active test blocked: no authorization reference provided. "
                    "Add a written authorization reference on the Configuration page."
                ),
                recommendation="Obtain written authorization before running active tests.",
            )
        return None

    async def _run_subprocess(
        self,
        cmd: List[str],
        timeout: int = 300,
        input_data: Optional[str] = None,
    ) -> tuple[int, str, str]:
        """
        Run an external command asynchronously.

        Returns:
            (returncode, stdout, stderr)
        """
        self.logger.debug(f"Running: {' '.join(cmd)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
            )
            stdin_data = input_data.encode() if input_data else None
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data), timeout=timeout
            )
            return (
                proc.returncode or 0,
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
            )
        except asyncio.TimeoutError:
            self.logger.warning(f"Command timed out after {timeout}s: {cmd[0]}")
            return -1, "", "TIMEOUT"
        except FileNotFoundError:
            self.logger.warning(f"Command not found: {cmd[0]}")
            return -2, "", f"NOT_FOUND: {cmd[0]}"
        except Exception as exc:
            self.logger.error(f"Subprocess error ({cmd[0]}): {exc}")
            return -3, "", str(exc)

    def _check_single_tool(
        self, name: str, cmd: List[str], install_hint: str = ""
    ) -> ToolCheck:
        """Check if a CLI tool is available by running `--version` or `--help`."""
        import subprocess
        import shutil

        path = shutil.which(cmd[0])
        if not path:
            return ToolCheck(name=name, available=False, install_hint=install_hint)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            version_out = (result.stdout + result.stderr)[:200].strip()
            return ToolCheck(name=name, available=True, version=version_out, path=path)
        except Exception as exc:
            return ToolCheck(name=name, available=True, path=path, version=str(exc))

    def stop(self):
        """Request graceful stop of running tests."""
        self._stop_requested = True

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    async def _wait_if_paused(self):
        """Yield control while paused, checking at 0.5s intervals."""
        while self._paused and not self._stop_requested:
            await asyncio.sleep(0.5)

    async def run(
        self,
        selected_tests: Optional[List[str]] = None,
        passive_only: bool = False,
    ) -> List[FindingResult]:
        """
        Public entry point. Wraps run_tests() with timing and logging.
        """
        self._running = True
        self._stop_requested = False
        start = time.monotonic()
        self.logger.info(
            f"[{self.module_id}] Starting {self.generation} module "
            f"(auth_ref='{self.authorization_ref}', passive={passive_only})"
        )
        try:
            self.results = await self.run_tests(
                selected_tests=selected_tests, passive_only=passive_only
            )
        except Exception as exc:
            self.logger.error(f"[{self.module_id}] Unexpected error: {exc}")
            self.results = [
                self._make_result(
                    test_id=f"{self.module_id}-ERR",
                    name="Module execution error",
                    status=TestStatus.ERROR,
                    severity=Severity.INFO,
                    finding=str(exc),
                )
            ]
        finally:
            elapsed = time.monotonic() - start
            self._running = False
            self.logger.info(
                f"[{self.module_id}] Completed in {elapsed:.1f}s "
                f"({len(self.results)} results)"
            )
        return self.results
