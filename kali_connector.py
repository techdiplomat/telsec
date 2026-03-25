"""
kali_connector.py — TelSec Kali Cloud Bridge
=============================================
Connects the Streamlit frontend to the FastAPI backend running inside
the telsec-kali Docker container on GitHub Codespaces.

Environment / Streamlit Secrets expected:
  KALI_API_URL  = "https://<codespace>-8000.app.github.dev"
  TELSEC_API_KEY = "telsec-kali-2024"

Handles:
  - Auto-discovery of API URL from Streamlit secrets or env
  - Per-call timeout + graceful offline handling
  - Unified run_tool() that streams tool output back
  - Health probe with rich status dict
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests
import streamlit as st

# ── Config ────────────────────────────────────────────────────────────────────
_DEFAULT_TIMEOUT = 30          # seconds for quick calls
_EXEC_TIMEOUT    = 120         # seconds for long-running tool commands
_HEALTH_TTL      = 20          # cache health check result for N seconds

TOOL_ENDPOINTS: Dict[str, str] = {
    # --- standard tools ---
    "nuclei":       "/run/nuclei",
    "nmap":         "/run/nmap",
    "tshark":       "/run/tshark",
    "aircrack":     "/run/aircrack",
    "metasploit":   "/run/metasploit",
    "hydra":        "/run/hydra",
    # --- telecom specific ---
    "sigploit":     "/run/sigploit",
    "osmocom":      "/run/osmocom",
    "gr-gsm":       "/run/grgsm",
    "kalibrate":    "/run/kalibrate",
    "scapy-ss7":    "/run/scapy_ss7",
    "svmap":        "/run/svmap",
    "svwar":        "/run/svwar",
    "dnsrecon":     "/run/dnsrecon",
    "whois":        "/run/whois",
    # --- pcap / analysis ---
    "tshark-pcap":  "/run/tshark_pcap",
    # --- Tier 1 new tools ---
    "gtscan":       "/run/gtscan",
    "sigshark":     "/run/sigshark",
    "sctpscan":     "/run/sctpscan",
    "5greplay":     "/run/5greplay",
    "scat":         "/run/scat",
    "lucid":        "/run/lucid",
    "mobiwatch":    "/run/mobiwatch",
    "zmap":         "/run/zmap",
    "sigfw":        "/run/sigfw",
    "5gbasechecker": "/run/5gbasechecker",
}

# ── Internal helpers ──────────────────────────────────────────────────────────
def _get_api_url() -> str:
    """Return base URL — from Streamlit secrets → env var → .kali_url file → empty."""
    # 1. Streamlit secrets (set via Cloud dashboard or .streamlit/secrets.toml)
    try:
        url = st.secrets.get("KALI_API_URL", "")
        if url:
            return url.rstrip("/")
    except Exception:
        pass
    # 2. Environment variable
    url = os.environ.get("KALI_API_URL", "")
    if url:
        return url.rstrip("/")
    # 3. Fallback: .kali_url file (auto-written by setup-kali.sh)
    try:
        from pathlib import Path
        kali_url_file = Path(__file__).parent / ".kali_url"
        if kali_url_file.exists():
            url = kali_url_file.read_text().strip()
            if url:
                return url.rstrip("/")
    except Exception:
        pass
    return ""


def _get_api_key() -> str:
    try:
        return st.secrets.get("TELSEC_API_KEY", "telsec-kali-2024")
    except Exception:
        return os.environ.get("TELSEC_API_KEY", "telsec-kali-2024")


def _headers() -> Dict[str, str]:
    return {
        "X-API-Key": _get_api_key(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ── Health check (cached) ─────────────────────────────────────────────────────
_health_cache: Dict[str, Any] = {"ts": 0, "result": None}


def health_check(force: bool = False) -> Dict[str, Any]:
    """
    Return a health status dict:
    {
      "online": bool,
      "url": str,
      "tools": list[str],
      "uptime_s": int,
      "error": str | None,
      "latency_ms": int,
    }
    Cached for _HEALTH_TTL seconds unless force=True.
    """
    global _health_cache
    now = time.time()
    if not force and _health_cache["result"] and (now - _health_cache["ts"]) < _HEALTH_TTL:
        return _health_cache["result"]

    base = _get_api_url()
    result: Dict[str, Any] = {
        "online": False,
        "url": base or "(not configured)",
        "tools": [],
        "uptime_s": 0,
        "error": None,
        "latency_ms": 0,
    }

    if not base:
        result["error"] = "KALI_API_URL not set in Streamlit Secrets"
        _health_cache = {"ts": now, "result": result}
        return result

    t0 = time.time()
    try:
        resp = requests.get(f"{base}/health", headers=_headers(), timeout=8)
        latency = int((time.time() - t0) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            result.update({
                "online": True,
                "tools": data.get("tools", []),
                "uptime_s": data.get("uptime_s", 0),
                "latency_ms": latency,
            })
        else:
            result["error"] = f"HTTP {resp.status_code}"
            result["latency_ms"] = latency
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection refused — Codespace may be suspended"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout (8s) — Codespace waking up, retry in ~30s"
    except Exception as exc:
        result["error"] = str(exc)

    _health_cache = {"ts": now, "result": result}
    return result


# ── Wake backend ──────────────────────────────────────────────────────────────
def wake_backend() -> Dict[str, Any]:
    """
    Attempt to wake a sleeping Codespace by retrying health checks
    with exponential backoff.
    Returns: {"success": bool, "attempts": int, "message": str}
    """
    base = _get_api_url()
    if not base:
        return {
            "success": False,
            "attempts": 0,
            "message": "KALI_API_URL not configured in Streamlit Secrets",
        }

    max_attempts = 5
    delays = [2, 5, 10, 15, 20]

    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.get(
                f"{base}/health",
                headers=_headers(),
                timeout=15,
            )
            if resp.status_code == 200:
                return {
                    "success": True,
                    "attempts": attempt,
                    "message": f"Backend woke up after {attempt} attempt(s)!",
                }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            if attempt < max_attempts:
                time.sleep(delays[attempt - 1])
                continue
        except Exception as exc:
            return {
                "success": False,
                "attempts": attempt,
                "message": f"Wake failed: {exc}",
            }

    return {
        "success": False,
        "attempts": max_attempts,
        "message": (
            "Backend did not respond after multiple wake attempts. "
            "Please manually restart uvicorn in your Codespace terminal."
        ),
    }


# ── Tool execution ─────────────────────────────────────────────────────────────
def run_tool(
    tool: str,
    params: Dict[str, Any],
    timeout: int = _EXEC_TIMEOUT,
) -> Dict[str, Any]:
    """
    POST params to /run/<tool> endpoint.
    Returns:
    {
      "success": bool,
      "stdout": str,
      "stderr": str,
      "returncode": int,
      "error": str | None,
    }
    """
    base = _get_api_url()
    endpoint = TOOL_ENDPOINTS.get(tool, f"/run/{tool}")

    result: Dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "returncode": -1,
        "error": None,
    }

    if not base:
        # Demo mode — return informative message instead of an error
        result["stdout"] = (
            f"[Demo Mode] Tool: {tool}\n"
            "Kali backend is offline. Set KALI_API_URL in Streamlit Secrets\n"
            "to enable real execution. Showing simulated output."
        )
        result["returncode"] = 0
        result["success"] = True
        return result

    try:
        resp = requests.post(
            f"{base}{endpoint}",
            json=params,
            headers=_headers(),
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            result.update({
                "success": data.get("returncode", -1) == 0,
                "stdout": data.get("stdout", ""),
                "stderr": data.get("stderr", ""),
                "returncode": data.get("returncode", -1),
            })
        elif resp.status_code == 404:
            result["error"] = (
                f"Tool endpoint '{endpoint}' not found on Kali API. "
                "Server may need updating."
            )
        elif resp.status_code == 403:
            result["error"] = "API key rejected — check TELSEC_API_KEY in Streamlit Secrets"
        else:
            result["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"
    except requests.exceptions.Timeout:
        result["error"] = f"Tool timed out after {timeout}s"
    except requests.exceptions.ConnectionError:
        result["error"] = "Cannot reach Kali backend — start with: docker start telsec-kali"
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Convenience wrappers ───────────────────────────────────────────────────────
def run_nmap(target: str, flags: str = "-sV -T4") -> Dict[str, Any]:
    return run_tool("nmap", {"target": target, "flags": flags})


def run_nuclei(target: str, templates: str = "") -> Dict[str, Any]:
    return run_tool("nuclei", {"target": target, "templates": templates})


def run_tshark(interface: str = "eth0", duration: int = 10, display_filter: str = "") -> Dict[str, Any]:
    return run_tool("tshark", {"interface": interface, "duration": duration, "filter": display_filter})


def run_sigploit(mode: str, target: str, extra: str = "") -> Dict[str, Any]:
    return run_tool("sigploit", {"mode": mode, "target": target, "extra": extra})


def run_aircrack(pcap_file: str = "", wordlist: str = "") -> Dict[str, Any]:
    return run_tool("aircrack", {"pcap": pcap_file, "wordlist": wordlist})


def run_metasploit(module: str, options: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return run_tool("metasploit", {"module": module, "options": options or {}})


def run_hydra(target: str, service: str, username: str, wordlist: str) -> Dict[str, Any]:
    return run_tool("hydra", {"target": target, "service": service,
                               "username": username, "wordlist": wordlist})


def run_svmap(target: str) -> Dict[str, Any]:
    return run_tool("svmap", {"target": target})


def run_dnsrecon(domain: str, types: str = "std,rvl") -> Dict[str, Any]:
    return run_tool("dnsrecon", {"domain": domain, "types": types})


def run_scapy_ss7(gt: str, msisdn: str, operation: str = "ATI") -> Dict[str, Any]:
    return run_tool("scapy-ss7", {"gt": gt, "msisdn": msisdn, "operation": operation})


def run_tshark_pcap(pcap_b64: str, display_filter: str = "") -> Dict[str, Any]:
    return run_tool("tshark-pcap", {"pcap_b64": pcap_b64, "filter": display_filter})


# ── Streamlit UI components ────────────────────────────────────────────────────
def render_kali_status_banner() -> bool:
    """
    Renders a compact status banner. Returns True if Kali is online.
    Call this at the top of any page that uses Kali tools.
    """
    status = health_check()
    if status["online"]:
        st.success(
            f"☁️ **Kali Cloud: ONLINE** — {len(status['tools'])} tools ready "
            f"| Latency: {status['latency_ms']}ms | Uptime: {status['uptime_s'] // 60}m",
            icon="✅",
        )
        return True
    else:
        st.error(
            f"☁️ **Kali Cloud: OFFLINE** — {status['error']}\n\n"
            "**To restart:**\n"
            "```bash\n"
            "docker start telsec-kali\n"
            "docker exec -d telsec-kali bash -c 'cd /opt/telsec_api && "
            "TELSEC_API_KEY=telsec-kali-2024 python3 -m uvicorn main:app "
            "--host 0.0.0.0 --port 8000'\n"
            "```",
            icon="🔴",
        )
        return False


def render_kali_status_mini() -> bool:
    """
    Lightweight, non-intrusive Kali status indicator for all tool pages.

    • ONLINE  → slim green pill bar (understated, professional).
    • OFFLINE → nothing visible — run_tool() silently returns demo output.
                 A collapsed expander gives setup hints for curious users.
    Returns True if Kali is online.
    """
    status = health_check()
    if status["online"]:
        st.markdown(
            f"<div style='background:rgba(16,185,129,.07);border:1px solid rgba(16,185,129,.2);"
            f"border-radius:999px;padding:5px 14px;font-size:.75rem;color:#10b981;"
            f"display:inline-flex;align-items:center;gap:8px;margin-bottom:14px'>"
            f"<span style='width:7px;height:7px;border-radius:50%;background:#10b981;"
            f"box-shadow:0 0 7px #10b981;animation:pulse 2s infinite'></span>"
            f"<b>Kali Cloud</b>&nbsp;connected &nbsp;·&nbsp; "
            f"{len(status['tools'])} tools active &nbsp;·&nbsp; {status['latency_ms']}ms"
            f"</div>",
            unsafe_allow_html=True,
        )
        return True
    else:
        with st.expander("💡 Running in Demo Mode — click to connect Kali backend", expanded=False):
            st.markdown(
                "Results shown are **simulated demo output**. "
                "To enable real tool execution:\n"
                "1. Start your Kali Codespace backend (see **⚙️ Tools & Environment**)\n"
                "2. Set `KALI_API_URL` in **Streamlit Secrets** ([app.streamlit.io](https://share.streamlit.io))\n"
                "3. Reload this page — tools will execute live."
            )
        return False


def render_tool_result(result: Dict[str, Any], tool_name: str = "Tool") -> None:
    """Render run_tool() response in a nice Streamlit block."""
    if result.get("error"):
        st.error(f"❌ **{tool_name} Error:** {result['error']}")
        return

    rc = result.get("returncode", -1)
    if rc == 0:
        st.success(f"✅ **{tool_name}** completed successfully (exit code 0)")
    else:
        st.warning(f"⚠️ **{tool_name}** exited with code {rc}")

    if result.get("stdout"):
        with st.expander("📤 stdout", expanded=True):
            st.code(result["stdout"], language="text")
    if result.get("stderr"):
        with st.expander("📥 stderr / warnings"):
            st.code(result["stderr"], language="text")
