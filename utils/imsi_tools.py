"""
TelSec - IMSI / SUCI / MSISDN Utilities
==========================================
Decode, encode, and analyze subscriber identifiers across generations.
  - 2G/3G/4G: IMSI (15-digit), TMSI (4-byte), MSISDN (E.164)
  - 5G: SUPI (IMSI form), SUCI (concealed with ECIES)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from utils.logger import get_logger

logger = get_logger("imsi_tools")

# ---------------------------------------------------------------------------
# MCC/MNC database (partial — major operators)
# ---------------------------------------------------------------------------

MCC_MNC_DB: Dict[str, Dict[str, str]] = {
    "001": {"01": "Test Network (ITU-T)", "name": "Test"},
    "310": {
        "010": "AT&T Mobility",
        "026": "T-Mobile US",
        "120": "Sprint (now T-Mobile)",
        "260": "T-Mobile",
        "410": "AT&T",
        "name": "United States",
    },
    "234": {
        "010": "O2",
        "015": "Vodafone GB",
        "020": "Three UK",
        "030": "EE",
        "name": "United Kingdom",
    },
    "404": {
        "010": "Aircel",
        "020": "Vodafone IN",
        "030": "Airtel",
        "045": "Airtel",
        "097": "Aircel",
        "name": "India",
    },
    "405": {
        "840": "Reliance Jio",
        "001": "Airtel",
        "name": "India (more MCCs)",
    },
    "262": {
        "001": "Telekom DE",
        "002": "Vodafone DE",
        "007": "O2 DE",
        "name": "Germany",
    },
    "208": {
        "001": "Orange France",
        "010": "SFR",
        "020": "Bouygues",
        "name": "France",
    },
    "505": {
        "001": "Telstra",
        "002": "Optus",
        "003": "Vodafone AU",
        "name": "Australia",
    },
}


@dataclass
class IMSIInfo:
    """Decoded IMSI components."""
    raw: str
    mcc: str
    mnc: str
    msin: str
    country: str = ""
    operator: str = ""
    valid: bool = True
    error: str = ""


@dataclass
class SUCIInfo:
    """Decoded SUCI (5G Subscription Concealed Identifier)."""
    raw_suci: str
    supi_type: str          # "IMSI" | "NAI" | "GCI" | "GLI"
    home_network_id: str    # MCC+MNC
    routing_indicator: str
    protection_scheme: str  # "0" = null, "1" = Profile A, "2" = Profile B
    home_network_pk_id: str
    scheme_output: str      # Concealed MSIN (if scheme != 0), else raw MSIN
    msin_revealed: Optional[str] = None  # Only when scheme_id == 0 (null)
    warning: str = ""


# ---------------------------------------------------------------------------
# IMSI decoding
# ---------------------------------------------------------------------------

def decode_imsi(imsi: str) -> IMSIInfo:
    """
    Decode an IMSI string into MCC, MNC, MSIN components.

    Args:
        imsi: 14–15 digit IMSI string

    Returns:
        IMSIInfo dataclass
    """
    imsi = imsi.strip().replace(" ", "")
    if not re.match(r"^\d{14,15}$", imsi):
        return IMSIInfo(raw=imsi, mcc="", mnc="", msin="", valid=False,
                        error="IMSI must be 14–15 digits")

    mcc = imsi[:3]
    # Try 3-digit MNC first, then 2-digit
    mnc3 = imsi[3:6]
    mnc2 = imsi[3:5]
    msin = ""
    mnc = mnc2
    country = ""
    operator = ""

    mcc_data = MCC_MNC_DB.get(mcc, {})
    country = mcc_data.get("name", f"MCC={mcc}")

    if mnc3 in mcc_data:
        mnc = mnc3
        msin = imsi[6:]
        operator = mcc_data[mnc3]
    elif mnc2 in mcc_data:
        mnc = mnc2
        msin = imsi[5:]
        operator = mcc_data[mnc2]
    else:
        # Default: 2-digit MNC
        msin = imsi[5:]

    info = IMSIInfo(
        raw=imsi,
        mcc=mcc,
        mnc=mnc,
        msin=msin,
        country=country,
        operator=operator,
        valid=True,
    )
    logger.debug(f"Decoded IMSI {imsi[:6]}... → MCC={mcc} MNC={mnc} MSIN={msin}")
    return info


# ---------------------------------------------------------------------------
# MSISDN utilities
# ---------------------------------------------------------------------------

def parse_msisdn(msisdn: str) -> Dict[str, str]:
    """
    Parse and normalize an MSISDN to E.164 format.

    Returns:
        dict with keys: e164, cc (country code), subscriber_number, valid
    """
    clean = re.sub(r"[\s\-\(\)]", "", msisdn)
    if not clean.startswith("+"):
        clean = "+" + clean.lstrip("0")

    if not re.match(r"^\+[1-9]\d{7,14}$", clean):
        return {"e164": msisdn, "valid": "false", "error": "Invalid E.164 format"}

    # Simple CC detection (1–3 digits)
    cc_map = {
        "+1": "US/CA", "+44": "GB", "+49": "DE", "+33": "FR",
        "+91": "IN", "+61": "AU", "+81": "JP", "+86": "CN",
        "+7": "RU", "+55": "BR", "+39": "IT", "+34": "ES",
    }
    cc, name = "", ""
    for prefix, country in cc_map.items():
        if clean.startswith(prefix):
            cc = prefix[1:]
            name = country
            break

    return {
        "e164": clean,
        "cc": cc,
        "country": name,
        "subscriber_number": clean[1 + len(cc):],
        "valid": "true",
    }


# ---------------------------------------------------------------------------
# TMSI utilities
# ---------------------------------------------------------------------------

def tmsi_to_hex(tmsi_int: int) -> str:
    """Convert integer TMSI to 4-byte hex string."""
    return format(tmsi_int & 0xFFFFFFFF, "08X")


def hex_to_tmsi(hex_str: str) -> int:
    """Convert hex TMSI back to integer."""
    return int(hex_str.replace(" ", ""), 16)


# ---------------------------------------------------------------------------
# 5G SUCI decoder (null-scheme only)
# ---------------------------------------------------------------------------

def decode_suci(suci_str: str) -> SUCIInfo:
    """
    Decode a 5G SUCI (Subscription Concealed Identifier).

    Format (null scheme, NAI representation):
        suci-<supi_type>-<mcc>-<mnc>-<ri>-<scheme_id>-<pk_id>-<scheme_output>

    For protection_scheme = 0 (null), scheme_output IS the MSIN.

    Args:
        suci_str: Raw SUCI string

    Returns:
        SUCIInfo dataclass
    """
    parts = suci_str.strip().split("-")
    if len(parts) < 7 or parts[0] != "suci":
        return SUCIInfo(
            raw_suci=suci_str,
            supi_type="UNKNOWN",
            home_network_id="",
            routing_indicator="",
            protection_scheme="",
            home_network_pk_id="",
            scheme_output="",
            warning="Not a valid SUCI format",
        )

    supi_type_map = {"0": "IMSI", "1": "NAI", "2": "GCI", "3": "GLI"}

    supi_type = supi_type_map.get(parts[1], f"type-{parts[1]}")
    mcc = parts[2]
    mnc = parts[3]
    routing_indicator = parts[4]
    scheme_id = parts[5]
    pk_id = parts[6]
    scheme_output = "-".join(parts[7:]) if len(parts) > 7 else ""

    scheme_names = {"0": "Null (MSIN exposed!)", "1": "ECIES Profile A", "2": "ECIES Profile B"}
    protection_scheme = scheme_names.get(scheme_id, f"Unknown ({scheme_id})")

    msin_revealed = None
    warning = ""
    if scheme_id == "0":
        msin_revealed = scheme_output
        warning = (
            "⚠️  Protection scheme 0 (NULL) detected — SUPI/IMSI is NOT concealed! "
            "This is a CRITICAL privacy vulnerability (NR-002)."
        )
        logger.warning(f"SUCI null scheme detected — MSIN exposed: {msin_revealed}")

    return SUCIInfo(
        raw_suci=suci_str,
        supi_type=supi_type,
        home_network_id=f"{mcc}-{mnc}",
        routing_indicator=routing_indicator,
        protection_scheme=protection_scheme,
        home_network_pk_id=pk_id,
        scheme_output=scheme_output,
        msin_revealed=msin_revealed,
        warning=warning,
    )


def supi_to_suci_null(imsi: str, mcc: str, mnc: str, ri: str = "0") -> str:
    """
    Construct a null-scheme SUCI from a SUPI/IMSI (for lab testing).
    WARNING: null scheme exposes the MSIN — only for lab use.

    Args:
        imsi: Full 15-digit IMSI
        mcc:  Mobile Country Code
        mnc:  Mobile Network Code
        ri:   Routing Indicator (default 0)

    Returns:
        SUCI string in NAI format
    """
    info = decode_imsi(imsi)
    if not info.valid:
        return f"INVALID-IMSI:{imsi}"
    msin = info.msin
    return f"suci-0-{mcc}-{mnc}-{ri}-0-0-{msin}"


# ---------------------------------------------------------------------------
# MCC → country lookup
# ---------------------------------------------------------------------------

def mcc_to_country(mcc: str) -> str:
    """Return country name for a given MCC."""
    entry = MCC_MNC_DB.get(mcc, {})
    return entry.get("name", f"Unknown (MCC={mcc})")


def mcc_mnc_to_operator(mcc: str, mnc: str) -> str:
    """Return operator name for a given MCC+MNC."""
    entry = MCC_MNC_DB.get(mcc, {})
    return entry.get(mnc, f"Unknown (MCC={mcc} MNC={mnc})")
