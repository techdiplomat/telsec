"""
Packet Capture Engine.
Wrapper around pyshark and tshark for live protocol extraction without blocking.
"""
import asyncio
import os

class Sniffer:
    def __init__(self, interface: str = "eth0", out_dir: str = "outputs/pcaps"):
        self.interface = interface
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)

    async def start_capture(self, duration: int, file_prefix: str, bpf_filter: str = "") -> str:
        """Starts a background tshark capture for a set duration"""
        out_file = os.path.join(self.out_dir, f"{file_prefix}.pcap")
        
        cmd = ["tshark", "-i", self.interface, "-a", f"duration:{duration}", "-w", out_file]
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])
            
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=duration+5)
            return out_file
        except Exception as e:
            return f"Capture failed: {e}"
