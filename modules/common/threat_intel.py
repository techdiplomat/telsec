"""
TelSec - CVE & Threat Intelligence Module
==========================================
Fetches telecom-relevant CVEs from NIST NVD API v2.
Maps CVEs to GSMA/3GPP references.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from utils.logger import get_logger

logger = get_logger("threat_intel")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE: Dict[str, Any] = {}
_CACHE_TS: float = 0.0
_CACHE_TTL = 3600  # 1 hour


@dataclass
class CVERecord:
    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str
    published: str
    modified: str
    references: List[str] = field(default_factory=list)
    keywords_matched: List[str] = field(default_factory=list)


TELECOM_KEYWORDS = [
    "SS7", "GTP", "Diameter", "LTE", "5G NR", "NGAP",
    "NAS 5G", "SUPI", "SBI", "OpenAirInterface",
]

GSMA_CVE_MAP = {
    "SS7": "FS.11",
    "Diameter": "FS.19",
    "GTP": "FS.19",
    "5G": "FS.40",
    "LTE": "FS.11",
}


def fetch_telecom_cves(
    keywords: Optional[List[str]] = None,
    api_key: str = "",
    max_results: int = 20,
    use_cache: bool = True,
) -> List[CVERecord]:
    """
    Fetch recent telecom CVEs from NVD API.

    Args:
        keywords:    List of search keywords
        api_key:     NVD API key (optional but increases rate limit)
        max_results: Max CVEs to return
        use_cache:   Return cached results if within TTL

    Returns:
        List of CVERecord objects sorted by CVSS score descending
    """
    global _CACHE, _CACHE_TS

    if keywords is None:
        keywords = TELECOM_KEYWORDS[:5]

    cache_key = "|".join(sorted(keywords))
    if use_cache and cache_key in _CACHE and (time.monotonic() - _CACHE_TS) < _CACHE_TTL:
        logger.debug("Returning cached CVE results")
        return _CACHE[cache_key]

    all_cves: List[CVERecord] = []
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for keyword in keywords[:3]:  # Limit API calls
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 10,
                "noRejected": "",
            }
            resp = requests.get(
                NVD_API_BASE, params=params, headers=headers, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    cve = _parse_nvd_cve(item, keyword)
                    if cve:
                        all_cves.append(cve)
            elif resp.status_code == 403:
                logger.warning("NVD API rate limited — provide an API key")
                break
        except requests.Timeout:
            logger.warning(f"NVD API timeout for keyword: {keyword}")
        except Exception as exc:
            logger.error(f"NVD API error: {exc}")

    # Deduplicate and sort by CVSS
    seen_ids = set()
    unique_cves = []
    for cve in sorted(all_cves, key=lambda c: c.cvss_score, reverse=True):
        if cve.cve_id not in seen_ids:
            seen_ids.add(cve.cve_id)
            unique_cves.append(cve)

    result = unique_cves[:max_results]

    # Cache results
    if result:
        _CACHE[cache_key] = result
        _CACHE_TS = time.monotonic()

    return result


def _parse_nvd_cve(item: Dict, keyword: str) -> Optional[CVERecord]:
    """Parse a single NVD CVE item."""
    try:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Get CVSS v3.1 score
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                first = metrics[version][0]
                cvss_score = float(
                    first.get("cvssData", {}).get("baseScore", 0.0)
                )
                cvss_vector = first.get("cvssData", {}).get("vectorString", "")
                break

        refs = [
            r.get("url", "") for r in cve_data.get("references", [])[:5]
        ]

        published = cve_data.get("published", "")[:10]
        modified = cve_data.get("lastModified", "")[:10]

        return CVERecord(
            cve_id=cve_id,
            description=desc[:500],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published=published,
            modified=modified,
            references=refs,
            keywords_matched=[keyword],
        )
    except Exception:
        return None


def map_cve_to_gsma(cve: CVERecord) -> str:
    """Return GSMA document reference for a CVE based on keywords."""
    for kw, gsma_ref in GSMA_CVE_MAP.items():
        if any(kw.lower() in km.lower() for km in cve.keywords_matched):
            return gsma_ref
    desc_lower = cve.description.lower()
    for kw, gsma_ref in GSMA_CVE_MAP.items():
        if kw.lower() in desc_lower:
            return gsma_ref
    return "N/A"


def get_mock_cves() -> List[CVERecord]:
    """Return static mock CVEs for offline/demo mode."""
    return [
        CVERecord(
            cve_id="CVE-2023-38039",
            description="SS7 MAP sendRoutingInfo allows unauthenticated subscriber location tracking.",
            cvss_score=9.3, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            published="2023-11-14", modified="2024-01-10",
            keywords_matched=["SS7"],
        ),
        CVERecord(
            cve_id="CVE-2023-44487",
            description="HTTP/2 CONTINUATION flood - applicable to 5G SBA services.",
            cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            published="2023-10-10", modified="2024-02-01",
            keywords_matched=["5G"],
        ),
        CVERecord(
            cve_id="CVE-2022-0185",
            description="LTE eNB memory corruption via malformed RRC message.",
            cvss_score=8.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            published="2022-01-18", modified="2023-06-15",
            keywords_matched=["LTE"],
        ),
    ]
