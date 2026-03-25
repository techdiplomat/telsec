"""
TelSec - Protocol Fuzzer Engine
=================================
Scapy-based generational fuzzer for SS7/Diameter/NAS protocols.
Strategies: bit-flip, boundary values, type confusion.
"""

from __future__ import annotations

import asyncio
import random
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger("fuzzer")


@dataclass
class FuzzPayload:
    """A single generated test payload."""
    strategy: str
    original_bytes: bytes
    fuzzed_bytes: bytes
    mutation_description: str


@dataclass
class FuzzResult:
    """Outcome of sending a fuzz payload."""
    payload: FuzzPayload
    response: bytes = b""
    response_time_ms: float = 0.0
    anomaly_detected: bool = False
    anomaly_reason: str = ""
    exception: str = ""


class ProtocolFuzzer:
    """
    Generational protocol fuzzer using Scapy for packet crafting.
    Supports SS7 MAP, Diameter AVPs, and NAS messages.
    """

    STRATEGIES = ["bit_flip", "boundary_value", "type_confusion",
                  "repetition", "truncation", "random_bytes"]

    def __init__(self, config: Dict[str, Any], seed: int = 42):
        self.config = config
        random.seed(seed)

    # ------------------------------------------------------------------
    # Mutation strategies
    # ------------------------------------------------------------------

    def _bit_flip(self, data: bytes, num_bits: int = 1) -> bytes:
        """Flip N random bits in the payload."""
        if not data:
            return data
        arr = bytearray(data)
        for _ in range(num_bits):
            byte_idx = random.randint(0, len(arr) - 1)
            bit_idx = random.randint(0, 7)
            arr[byte_idx] ^= (1 << bit_idx)
        return bytes(arr)

    def _boundary_value(self, data: bytes) -> bytes:
        """Replace random bytes with boundary values (0x00, 0xFF, 0x80)."""
        arr = bytearray(data)
        boundaries = [0x00, 0xFF, 0x80, 0x7F, 0x01]
        for i in random.sample(range(len(arr)), k=min(3, len(arr))):
            arr[i] = random.choice(boundaries)
        return bytes(arr)

    def _type_confusion(self, data: bytes) -> bytes:
        """Inject type-mismatched values into structured fields."""
        if len(data) < 4:
            return data + b"\xFF\xFF"
        arr = bytearray(data)
        # Replace first 4 bytes with max int (type confusion for length fields)
        arr[0:4] = b"\xFF\xFF\xFF\xFF"
        return bytes(arr)

    def _repetition(self, data: bytes) -> bytes:
        """Repeat the payload to simulate buffer overflow conditions."""
        factor = random.randint(2, 5)
        return data * factor

    def _truncation(self, data: bytes) -> bytes:
        """Truncate to random length — tests incomplete message handling."""
        if len(data) < 2:
            return b""
        trunc_len = random.randint(1, len(data) - 1)
        return data[:trunc_len]

    def _random_bytes(self, data: bytes) -> bytes:
        """Generate completely random bytes of same length."""
        return bytes(random.randint(0, 255) for _ in range(len(data)))

    def mutate(self, data: bytes, strategy: Optional[str] = None) -> FuzzPayload:
        """
        Apply a mutation strategy to produce a fuzz payload.

        Args:
            data:     Original protocol message bytes
            strategy: Mutation strategy name; random if None

        Returns:
            FuzzPayload
        """
        if strategy is None:
            strategy = random.choice(self.STRATEGIES)

        mutators: Dict[str, Callable[[bytes], bytes]] = {
            "bit_flip": self._bit_flip,
            "boundary_value": self._boundary_value,
            "type_confusion": self._type_confusion,
            "repetition": self._repetition,
            "truncation": self._truncation,
            "random_bytes": self._random_bytes,
        }
        mutator = mutators.get(strategy, self._bit_flip)
        fuzzed = mutator(data)
        return FuzzPayload(
            strategy=strategy,
            original_bytes=data,
            fuzzed_bytes=fuzzed,
            mutation_description=f"{strategy}: {len(data)}B → {len(fuzzed)}B",
        )

    def generate_campaign(
        self, seed_payload: bytes, iterations: int = 50
    ) -> List[FuzzPayload]:
        """
        Generate a fuzzing campaign from a seed payload.

        Args:
            seed_payload: Starting protocol message bytes
            iterations:   Number of mutations to generate

        Returns:
            List of FuzzPayload objects
        """
        payloads = []
        current = seed_payload
        for i in range(iterations):
            strategy = self.STRATEGIES[i % len(self.STRATEGIES)]
            payload = self.mutate(current, strategy=strategy)
            payloads.append(payload)
            # Use fuzzed output as next seed (coverage-guided style)
            if len(payload.fuzzed_bytes) > 0:
                current = payload.fuzzed_bytes
            else:
                current = seed_payload  # Reset on empty
        return payloads

    # ------------------------------------------------------------------
    # Response anomaly detection
    # ------------------------------------------------------------------

    def detect_anomaly(
        self,
        response: bytes,
        baseline_length: Optional[int] = None,
        expected_prefix: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """
        Heuristically detect anomalous responses.

        Args:
            response:         Raw response bytes
            baseline_length:  Expected response length (±20%)
            expected_prefix:  Bytes the response should start with

        Returns:
            (anomaly_detected: bool, reason: str)
        """
        if not response:
            return True, "Empty response — potential crash or connection reset"

        if len(response) > 65535:
            return True, f"Oversized response ({len(response)} bytes) — possible memory issue"

        if baseline_length:
            ratio = len(response) / baseline_length
            if ratio < 0.5 or ratio > 3.0:
                return True, (
                    f"Response length deviation: {len(response)} vs baseline {baseline_length}"
                )

        if expected_prefix and not response.startswith(expected_prefix):
            return True, (
                f"Unexpected response prefix: {response[:4].hex()} "
                f"(expected {expected_prefix.hex()})"
            )

        # Check for crash indicators in ASCII responses
        crash_indicators = [b"segfault", b"core dump", b"exception", b"fatal error"]
        resp_lower = response.lower()
        for indicator in crash_indicators:
            if indicator in resp_lower:
                return True, f"Crash indicator in response: {indicator.decode()}"

        return False, "No anomaly detected"

    # ------------------------------------------------------------------
    # Scapy-based protocol-specific helpers
    # ------------------------------------------------------------------

    def build_diameter_avp(
        self, avp_code: int, value: bytes, vendor_id: int = 0, flags: int = 0x40
    ) -> bytes:
        """
        Build a raw Diameter AVP.
        Format: Code(4) + Flags(1) + Length(3) + [VendorId(4)] + Value
        """
        if vendor_id:
            flags |= 0x80
            avp_len = 8 + 4 + len(value)
            header = struct.pack(">IBxH", avp_code, flags, avp_len >> 8 & 0xFF) + \
                     struct.pack(">I", vendor_id)
        else:
            avp_len = 8 + len(value)
            header = struct.pack(">I", avp_code) + \
                     bytes([flags]) + \
                     struct.pack(">I", avp_len)[1:]
        return header + value

    def build_ss7_map_probe(self, imsi: str = "001010000000001") -> bytes:
        """
        Build a minimal SS7 MAP/SRI probe payload for fuzzing.
        (Simplified — real MAP uses TCAP wrapping)
        """
        imsi_bytes = bytes.fromhex(
            "".join(
                b + a for a, b in zip(imsi[::2], imsi[1::2])
            ) + ("F" + imsi[-1] if len(imsi) % 2 else "")
        )
        return b"\x04\x00\x61" + bytes([len(imsi_bytes)]) + imsi_bytes
