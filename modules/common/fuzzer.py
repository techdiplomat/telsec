"""
Protocol Fuzzer.
Scapy based mutational fuzzer for NAS, Diameter and MAP.
"""
import random
import string

class ProtocolFuzzer:
    def __init__(self, rounds: int = 100):
        self.rounds = rounds
        
    def generate_random_bytes(self, length: int) -> bytes:
        return bytearray(random.getrandbits(8) for _ in range(length))
        
    def fuzz_sba_payload(self) -> dict:
        """Generates malformed JSON payloads for 5G REST APIs."""
        junk_string = ''.join(random.choices(string.ascii_letters + string.digits, k=1024))
        return {
            "supi": f"imsi-{junk_string}",
            "servingNetworkName": "5G:mnc000.mcc000.3gppnetwork.org",
            "malformed_field": "\x00\x01\x02" * 50
        }
