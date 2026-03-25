"""
TelSec - Nmap Scanner Engine
==============================
Wraps Nmap with telecom-specific NSE scripts.
Used by LTE-008 (EPC discovery) and core network recon.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.validators import preflight_check

logger = get_logger("scanner")


class ScanResult:
    """Structured result from a network scan."""

    def __init__(self, target: str, raw: str = "", hosts: Optional[List[Dict]] = None):
        self.target = target
        self.raw = raw
        self.hosts: List[Dict[str, Any]] = hosts or []
        self.open_ports: List[int] = []
        self.services: Dict[int, str] = {}

    def parse_nmap_xml(self, xml_output: str) -> None:
        """Simple XML parser for nmap output (no lxml required)."""
        import re
        port_matches = re.findall(r'portid="(\d+)".*?state="(\w+)"', xml_output, re.DOTALL)
        svc_matches = re.findall(r'portid="(\d+)".*?name="([^"]+)"', xml_output, re.DOTALL)
        for port, state in port_matches:
            if state == "open":
                self.open_ports.append(int(port))
        for port, svc in svc_matches:
            self.services[int(port)] = svc


class NmapScanner:
    """
    Async Nmap wrapper with telecom NSE script support.
    """

    TELECOM_SCRIPTS = [
        "diameter-info",
        "s1ap-info",
        "sip-methods",
        "sip-enum-users",
    ]

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.nmap_path = config.get("tools", {}).get("nmap_path", "nmap")

    async def scan(
        self,
        target: str,
        ports: str = "1-65535",
        scripts: Optional[List[str]] = None,
        args: Optional[str] = None,
        timeout: int = 300,
    ) -> ScanResult:
        """
        Run an nmap scan.

        Args:
            target:  IP or CIDR
            ports:   Port spec, e.g. '80,443,2905,36412'
            scripts: NSE script names (without .nse)
            args:    Additional nmap arguments
            timeout: Max seconds

        Returns:
            ScanResult
        """
        cmd = [self.nmap_path, "-sV", "--open", "-p", ports, "-oX", "-"]

        if scripts:
            cmd += [f"--script={','.join(scripts)}"]

        if args:
            cmd += args.split()

        cmd.append(target)

        logger.info(f"nmap scan: {' '.join(cmd[:6])} ... {target}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            raw = stdout.decode(errors="replace")
            result = ScanResult(target=target, raw=raw)
            result.parse_nmap_xml(raw)
            logger.info(
                f"nmap done: {len(result.open_ports)} open ports on {target}"
            )
            return result
        except FileNotFoundError:
            logger.warning("nmap not found — install with: apt-get install nmap")
            return ScanResult(target=target, raw="NOT_FOUND")
        except asyncio.TimeoutError:
            logger.warning(f"nmap timed out after {timeout}s")
            return ScanResult(target=target, raw="TIMEOUT")
        except Exception as exc:
            logger.error(f"nmap error: {exc}")
            return ScanResult(target=target, raw=str(exc))

    async def telecom_scan(
        self, target: str, generation: str = "4G"
    ) -> ScanResult:
        """
        Preconfigured scan for telecom port ranges.
        """
        port_map = {
            "2G": "7,23,2905",
            "3G": "2905,2906,9900",
            "4G": "36412,36422,3868,2123,2152",
            "5G": "38412,38422,7777,29510,29518,29502",
        }
        ports = port_map.get(generation, "36412,3868,38412")
        return await self.scan(target, ports=ports, scripts=self.TELECOM_SCRIPTS)
