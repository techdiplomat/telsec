"""
TelSec - Packet Sniffer Engine
================================
pyshark/tshark wrapper for live protocol capture and PCAP export.
Supports SS7/M3UA, Diameter, S1AP, NGAP dissection.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger("sniffer")


@dataclass
class CapturedPacket:
    """Parsed packet from capture."""
    number: int
    timestamp: float
    protocol: str
    src: str = ""
    dst: str = ""
    info: str = ""
    length: int = 0
    raw_fields: Dict[str, str] = field(default_factory=dict)


class PacketSniffer:
    """
    Async tshark/pyshark wrapper for telecom protocol capture.
    """

    # Telecom display filters mapped to generation
    FILTERS = {
        "2G": "gsm_a or gsm_sms or gsm_map",
        "3G": "m3ua or sccp or tcap or gsm_map",
        "4G": "diameter or s1ap or nas-eps or gtpv2",
        "5G": "ngap or nas-5gs or pfcp or http2",
        "ALL": "m3ua or diameter or s1ap or ngap or nas-5gs",
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tshark = config.get("tools", {}).get("tshark_path", "tshark")
        self._packets: List[CapturedPacket] = []
        self._capture_process: Optional[asyncio.subprocess.Process] = None

    async def capture_live(
        self,
        interface: str,
        duration: int = 60,
        display_filter: Optional[str] = None,
        generation: str = "ALL",
        packet_callback: Optional[Callable[[CapturedPacket], None]] = None,
        output_pcap: Optional[str] = None,
    ) -> List[CapturedPacket]:
        """
        Live packet capture via tshark.

        Args:
            interface:       Network interface (e.g., eth0, lo)
            duration:        Capture duration in seconds
            display_filter:  Wireshark display filter
            generation:      Protocol generation for auto-filter
            packet_callback: Called for each decoded packet
            output_pcap:     If provided, save PCAP to this path

        Returns:
            List of CapturedPacket objects
        """
        if display_filter is None:
            display_filter = self.FILTERS.get(generation, self.FILTERS["ALL"])

        cmd = [
            self.tshark,
            "-i", interface,
            "-a", f"duration:{duration}",
            "-Y", display_filter,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "_ws.col.Protocol",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Info",
            "-e", "frame.len",
            "-E", "separator=|",
            "-E", "occurrence=f",
        ]

        if output_pcap:
            cmd += ["-w", output_pcap]

        logger.info(f"Starting capture on {interface} ({duration}s, filter={display_filter})")
        self._packets = []

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._capture_process = proc

            start = time.monotonic()
            while time.monotonic() - start < duration + 5:
                if proc.stdout is None:
                    break
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=2.0)
                except asyncio.TimeoutError:
                    if proc.returncode is not None:
                        break
                    continue
                if not line:
                    break
                decoded = line.decode(errors="replace").strip()
                pkt = self._parse_tshark_line(decoded)
                if pkt:
                    self._packets.append(pkt)
                    if packet_callback:
                        packet_callback(pkt)

            await proc.wait()
        except FileNotFoundError:
            logger.warning("tshark not found — install with: apt-get install tshark")
        except Exception as exc:
            logger.error(f"Capture error: {exc}")

        logger.info(f"Capture complete: {len(self._packets)} packets")
        return self._packets

    async def capture_from_pcap(
        self, pcap_file: str, display_filter: Optional[str] = None
    ) -> List[CapturedPacket]:
        """Read and parse an existing PCAP file."""
        cmd = [
            self.tshark, "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.number", "-e", "frame.time_epoch",
            "-e", "_ws.col.Protocol", "-e", "ip.src", "-e", "ip.dst",
            "-e", "_ws.col.Info", "-e", "frame.len",
            "-E", "separator=|", "-E", "occurrence=f",
        ]
        if display_filter:
            cmd += ["-Y", display_filter]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            packets = []
            for line in stdout.decode(errors="replace").splitlines():
                pkt = self._parse_tshark_line(line.strip())
                if pkt:
                    packets.append(pkt)
            return packets
        except Exception as exc:
            logger.error(f"PCAP read error: {exc}")
            return []

    def stop(self) -> None:
        """Stop active capture."""
        if self._capture_process:
            try:
                self._capture_process.terminate()
            except Exception:
                pass

    def _parse_tshark_line(self, line: str) -> Optional[CapturedPacket]:
        """Parse a tshark -T fields -E separator=| output line."""
        parts = line.split("|")
        if len(parts) < 6:
            return None
        try:
            return CapturedPacket(
                number=int(parts[0]) if parts[0] else 0,
                timestamp=float(parts[1]) if parts[1] else 0.0,
                protocol=parts[2] or "UNKNOWN",
                src=parts[3],
                dst=parts[4],
                info=parts[5],
                length=int(parts[6]) if len(parts) > 6 and parts[6] else 0,
            )
        except (ValueError, IndexError):
            return None

    async def export_pcap_annotated(
        self,
        input_pcap: str,
        output_json: str,
        generation: str = "ALL",
    ) -> str:
        """Export a PCAP with protocol annotation to JSON."""
        packets = await self.capture_from_pcap(
            input_pcap, display_filter=self.FILTERS.get(generation)
        )
        import json
        data = [
            {
                "number": p.number,
                "timestamp": p.timestamp,
                "protocol": p.protocol,
                "src": p.src,
                "dst": p.dst,
                "info": p.info,
                "length": p.length,
            }
            for p in packets
        ]
        with open(output_json, "w") as f:
            json.dump(data, f, indent=2)
        return output_json
