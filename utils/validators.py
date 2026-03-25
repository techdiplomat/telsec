"""
TelSec - Input Validation & Authorization Gate
================================================
All active tests pass through this module before execution.
Key responsibilities:
  - Validate IP addresses are within authorized scope
  - Enforce authorization reference requirement
  - Rate-limit probe frequency
  - Validate MSISDN / IMSI formats
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections import deque
from typing import List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger("validators")

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Token-bucket style rate limiter.
    Default: max 10 operations per second (configurable).
    """

    def __init__(self, max_per_second: int = 10):
        self.max_per_second = max_per_second
        self._timestamps: deque[float] = deque()

    def is_allowed(self) -> bool:
        now = time.monotonic()
        # Remove events older than 1 second
        while self._timestamps and now - self._timestamps[0] > 1.0:
            self._timestamps.popleft()
        if len(self._timestamps) < self.max_per_second:
            self._timestamps.append(now)
            return True
        return False

    def wait_for_slot(self, timeout: float = 5.0) -> bool:
        """Block until a slot is available or timeout expires."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.is_allowed():
                return True
            time.sleep(0.05)
        logger.warning("Rate limit slot timed out — probe skipped")
        return False


# Global rate limiter instance
_global_limiter = RateLimiter(max_per_second=10)


# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------

def validate_authorization(
    auth_ref: str,
    require_ref: bool = True,
) -> Tuple[bool, str]:
    """
    Validate that a written authorization reference is present.

    Args:
        auth_ref:     The authorization reference string from the user.
        require_ref:  If False, passive-only tests bypass this check.

    Returns:
        (is_valid: bool, message: str)
    """
    if not require_ref:
        return True, "Passive mode — authorization not required"

    if not auth_ref or auth_ref.strip() == "":
        msg = (
            "❌ Authorization blocked: no written authorization reference provided. "
            "Obtain explicit written permission from the network operator before "
            "running active tests."
        )
        logger.warning(msg)
        return False, msg

    if len(auth_ref.strip()) < 6:
        msg = "❌ Authorization reference appears too short (min 6 characters)."
        return False, msg

    logger.info(f"Authorization reference accepted: '{auth_ref[:4]}***'")
    return True, f"✅ Authorized (ref: {auth_ref[:4]}...)"


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------

def validate_ip_in_scope(
    ip: str,
    allowed_ranges: List[str],
) -> Tuple[bool, str]:
    """
    Verify that an IP address falls within the configured authorized scope.

    Args:
        ip:             Target IP address string
        allowed_ranges: List of CIDR notation strings from config

    Returns:
        (in_scope: bool, message: str)
    """
    if not allowed_ranges:
        return False, "No IP scope defined in config/targets.yaml — test blocked."

    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP address: '{ip}'"

    for cidr in allowed_ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if target in network:
                return True, f"✅ IP {ip} is within authorized scope {cidr}"
        except ValueError:
            logger.warning(f"Invalid CIDR in scope config: {cidr}")

    return False, (
        f"❌ IP {ip} is NOT within any authorized scope. "
        f"Allowed ranges: {allowed_ranges}"
    )


# ---------------------------------------------------------------------------
# MSISDN / IMSI validators
# ---------------------------------------------------------------------------

_MSISDN_RE = re.compile(r"^\+?[1-9]\d{7,14}$")
_IMSI_RE = re.compile(r"^\d{14,15}$")


def validate_msisdn(msisdn: str) -> Tuple[bool, str]:
    """
    Validate E.164 MSISDN format.

    Returns:
        (valid: bool, message: str)
    """
    clean = msisdn.replace(" ", "").replace("-", "")
    if _MSISDN_RE.match(clean):
        return True, f"Valid MSISDN: {clean}"
    return False, f"Invalid MSISDN format: '{msisdn}' (expected E.164)"


def validate_imsi(imsi: str) -> Tuple[bool, str]:
    """
    Validate IMSI format (14–15 digits).

    Returns:
        (valid: bool, message: str)
    """
    clean = imsi.strip()
    if _IMSI_RE.match(clean):
        return True, f"Valid IMSI: {clean}"
    return False, f"Invalid IMSI format: '{imsi}' (expected 14–15 digits)"


# ---------------------------------------------------------------------------
# Composite pre-flight check
# ---------------------------------------------------------------------------

def preflight_check(
    target_ip: str,
    auth_ref: str,
    allowed_ranges: List[str],
    passive_only: bool = False,
    rate_limit: bool = True,
) -> Tuple[bool, str]:
    """
    Full pre-flight check before running any active test.

    Args:
        target_ip:      IP address of target
        auth_ref:       Authorization reference string
        allowed_ranges: Authorized CIDR ranges
        passive_only:   If True, skip auth and scope checks
        rate_limit:     If True, enforce global rate limiter

    Returns:
        (go: bool, message: str)
    """
    if passive_only:
        return True, "Passive mode — all checks bypassed"

    # 1. Authorization
    ok, msg = validate_authorization(auth_ref)
    if not ok:
        return False, msg

    # 2. Scope
    if target_ip:
        ok, msg = validate_ip_in_scope(target_ip, allowed_ranges)
        if not ok:
            return False, msg

    # 3. Rate limit
    if rate_limit and not _global_limiter.is_allowed():
        return False, "⚠️  Rate limit exceeded — slow down probe frequency."

    return True, "✅ All pre-flight checks passed"
