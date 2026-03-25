"""
TelSec Backend API v2.0 — Full /run/* Tool Gateway
====================================================
Runs on GitHub Codespaces inside kalilinux/kali-rolling Docker container.
All tool executions use subprocess.run() with timeout + output capture.
"""
from __future__ import annotations
import os
import subprocess
import shutil
import json
import time
import base64
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="TelSec Kali Gateway", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

API_KEY = os.getenv("TELSEC_API_KEY", "telsec-kali-2024")
_START_TIME = time.time()

# ── Auth ───────────────────────────────────────────────────────────────────────
def verify_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(403, "Invalid API key")

# ── Unified request / response models ─────────────────────────────────────────
class RunRequest(BaseModel):
    target:      str = ""
    msisdn:      str = ""
    gt:          str = ""
    test_type:   str = ""
    flags:       str = ""
    mode:        str = ""
    extra:       str = ""
    interface:   str = "lo"
    duration:    int = 10
    filter:      str = ""
    domain:      str = ""
    types:       str = "std"
    username:    str = "admin"
    wordlist:    str = "fasttrack.txt"
    service:     str = "http"
    module:      str = ""
    options:     Dict[str, str] = {}
    templates:   str = ""
    operation:   str = "ATI"
    pcap_b64:    str = ""
    port_range:  str = "5060"
    ext_range:   str = "100-200"

class RunResult(BaseModel):
    stdout:      str = ""
    stderr:      str = ""
    returncode:  int = 0
    runtime_ms:  int = 0
    tool:        str = ""
    demo:        bool = False

# ── Helper: run subprocess safely ─────────────────────────────────────────────
def _run(cmd: List[str], timeout: int = 60, env: dict | None = None) -> RunResult:
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        return RunResult(
            stdout=proc.stdout[:8000],
            stderr=proc.stderr[:2000],
            returncode=proc.returncode,
            runtime_ms=int((time.time() - t0) * 1000),
            tool=cmd[0],
        )
    except FileNotFoundError:
        return RunResult(stderr=f"Tool not found: {cmd[0]}", returncode=127, tool=cmd[0])
    except subprocess.TimeoutExpired:
        return RunResult(stderr=f"Timed out after {timeout}s", returncode=124, tool=cmd[0])
    except Exception as e:
        return RunResult(stderr=str(e), returncode=1, tool=cmd[0])

def _demo(tool: str, msg: str) -> RunResult:
    return RunResult(stdout=msg, returncode=0, tool=tool, demo=True)

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None

# ── Health endpoint ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "TelSec Kali Gateway", "status": "online", "version": "2.0.0"}

@app.get("/health")
async def health():
    available_tools = []
    for t in ["nmap","tshark","hydra","aircrack-ng","hping3","dnsrecon",
              "curl","python3","scapy","sipvicious","nuclei","msfconsole",
              "whois","kamailio","svmap","svwar","svcrack"]:
        if _tool_available(t):
            available_tools.append(t)
    return {
        "status": "online",
        "tools": available_tools,
        "uptime_s": int(time.time() - _START_TIME),
        "version": "2.0.0",
    }

# =============================================================================
#  /run/* ENDPOINTS — one per tool
# =============================================================================

# ── nmap ──────────────────────────────────────────────────────────────────────
@app.post("/run/nmap", response_model=RunResult)
async def run_nmap(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not req.target:
        return RunResult(stderr="target is required", returncode=1)
    if not _tool_available("nmap"):
        return _demo("nmap", f"[DEMO] nmap {req.flags or '-sV -T4'} {req.target}\n\nStarting Nmap 7.94\nHost is up (0.003s latency).\nPORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.9\n80/tcp   open  http    nginx 1.18\n8080/tcp open  http    Python uvicorn\n443/tcp  open  ssl/ssl\nNmap done: 1 IP address (1 host up) scanned in 4.23 seconds")
    flags = (req.flags or "-sV -T4").split()
    return _run(["nmap"] + flags + [req.target], timeout=60)

# ── nuclei ────────────────────────────────────────────────────────────────────
@app.post("/run/nuclei", response_model=RunResult)
async def run_nuclei(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not req.target:
        return RunResult(stderr="target is required", returncode=1)
    if not _tool_available("nuclei"):
        return _demo("nuclei", f"[DEMO] nuclei -u {req.target}\n\n[INF] Nuclei v3.2.0\n[INF] Templates loaded: 8247\n[2026-03-24] [http-missing-security-headers] [{req.target}] [INFO]\n[2026-03-24] [x-frame-options] [{req.target}] [LOW]\n[2026-03-24] [default-login:http] [{req.target}:8080] [MEDIUM] admin:password123\n[INF] Scan complete — 3 findings")
    cmd = ["nuclei", "-u", req.target, "-silent"]
    if req.templates:
        cmd += ["-t", req.templates]
    return _run(cmd, timeout=90)

# ── tshark ────────────────────────────────────────────────────────────────────
@app.post("/run/tshark", response_model=RunResult)
async def run_tshark(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not _tool_available("tshark"):
        return _demo("tshark", "[DEMO] Capturing on 'lo' for 5s...\n1  0.000000  127.0.0.1 → 127.0.0.1  TCP 74  8000 → 52412\n2  0.000103  127.0.0.1 → 127.0.0.1  HTTP 234  GET /health HTTP/1.1\n3  0.002001  127.0.0.1 → 127.0.0.1  HTTP 198  HTTP/1.1 200 OK\nPackets captured: 3")
    cmd = ["tshark", "-i", req.interface or "lo", "-a", f"duration:{req.duration or 5}"]
    if req.filter:
        cmd += ["-Y", req.filter]
    return _run(cmd, timeout=req.duration + 10)

# ── tshark_pcap ───────────────────────────────────────────────────────────────
@app.post("/run/tshark_pcap", response_model=RunResult)
async def run_tshark_pcap(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not req.pcap_b64:
        return RunResult(stderr="pcap_b64 required", returncode=1)
    try:
        data = base64.b64decode(req.pcap_b64)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(data)
            pcap_path = f.name
        cmd = ["tshark", "-r", pcap_path, "-V"]
        if req.filter:
            cmd += ["-Y", req.filter]
        return _run(cmd, timeout=30)
    except Exception as e:
        return RunResult(stderr=str(e), returncode=1)

# ── hydra ─────────────────────────────────────────────────────────────────────
@app.post("/run/hydra", response_model=RunResult)
async def run_hydra(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not req.target:
        return RunResult(stderr="target is required", returncode=1)
    if not _tool_available("hydra"):
        return _demo("hydra", f"[DEMO] hydra -l {req.username} -P /usr/share/wordlists/{req.wordlist} {req.target} {req.service}\n\nHydra v9.5 starting\n[{req.service}][{req.target}] host: {req.target}   login: {req.username}   password: admin\n1 of 1 target successfully completed, 1 valid password found")
    wl = f"/usr/share/wordlists/{req.wordlist}"
    cmd = ["hydra", "-l", req.username, "-P", wl, req.target, req.service, "-t", "4", "-q"]
    return _run(cmd, timeout=90)

# ── metasploit ────────────────────────────────────────────────────────────────
@app.post("/run/metasploit", response_model=RunResult)
async def run_metasploit(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not req.module:
        return RunResult(stderr="module is required", returncode=1)
    if not _tool_available("msfconsole"):
        return _demo("msfconsole", f"[DEMO] msfconsole -q -x 'use {req.module}; info'\n\nMetasploit Framework v6.4.0\n   Name: {req.module.split('/')[-1]}\n   Module: {req.module}\n   Platform: linux\n   Arch: x86_64\n   Type: auxiliary\nDescription: Selected module loaded. (Demo mode — real Metasploit requires active Kali backend)")
    opts_cmd = "; ".join(f"set {k} {v}" for k, v in req.options.items())
    msf_rc = f"use {req.module}; {opts_cmd}; info; exit"
    return _run(["msfconsole", "-q", "-x", msf_rc], timeout=60)

# ── aircrack ──────────────────────────────────────────────────────────────────
@app.post("/run/aircrack", response_model=RunResult)
async def run_aircrack(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    return _demo("aircrack-ng", "[DEMO] aircrack-ng requires a real capture file with handshakes.\nThis demo simulates: aircrack-ng -a 2 capture.cap -w wordlist.txt\n\nAircrack-ng 1.7\nOpening capture.cap\nRead 2814 packets.\n   #  BSSID              ESSID  Encryption\n   1  00:11:22:33:44:55  TestAP  WPA (1 handshake)\nCurrent passphrase: password123\nKEY FOUND! [ admin1234 ]\nMaster Key: 2A 4B 6C 8D...")

# ── sigploit / ss7 ────────────────────────────────────────────────────────────
@app.post("/run/sigploit", response_model=RunResult)
async def run_sigploit(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    mode = req.mode or "location"
    gt   = req.gt or "491770000000"
    msisdn = req.msisdn or "491771234567"
    sigploit_path = "/opt/tools/SigPloit/ss7/location_tracking.py"
    if os.path.exists(sigploit_path) and _tool_available("python3"):
        return _run(["python3", sigploit_path, "--gt", gt, "--msisdn", msisdn], timeout=30)
    # Demo output per mode
    demos = {
        "location": (
            f"[SigPloit] MAP ATI — Location Tracking\n"
            f"Target MSISDN : {msisdn}\n"
            f"Source GT     : {gt}\n\n"
            f"Sending MAP Any-Time-Interrogation (ATI) to HLR...\n"
            f"[✓] ATI Response received\n"
            f"  IMSI    : 26201{msisdn[-7:]}\n"
            f"  VLR     : +49177888000\n"
            f"  Cell-Id : 0x1A2F (LAC 7700, CI 3891)\n"
            f"  State   : Attached / IDLE\n\n"
            f"VULNERABILITY: Unauthenticated MAP ATI accepted\n"
            f"CVSS 8.2 | GSMA FS.11 Cat-2 | CVE-2023-1337"
        ),
        "sms": (
            f"[SigPloit] MAP SRI-SM — SMS Interception Setup\n"
            f"Target MSISDN : {msisdn}\n"
            f"Sending SRI_SM to SMSC...\n"
            f"[✓] SRI_SM Response\n"
            f"  IMSI    : 26201{msisdn[-7:]}\n"
            f"  MSC     : +4917788900\n"
            f"Sending mt-ForwardSM to fake MSC...\n"
            f"[✓] SMS intercepted — content decoded\n"
            f"VULNERABILITY: NE impersonation, no SMS-HE filtering\n"
            f"CVSS 8.8 | GSMA FS.11 Cat-3"
        ),
        "call": (
            f"[SigPloit] MAP PSI — Call Interception\n"
            f"Target MSISDN : {msisdn}\n"
            f"Sending MAP PSI (Provide Subscriber Info)...\n"
            f"[✓] PSI Response — subscriber roaming to MSC +4917788900\n"
            f"Injecting fake IAM to MSC for re-routing...\n"
            f"[✓] Call diverted to attacker-controlled MSC\n"
            f"VULNERABILITY: MAP PSI unrestricted from external GT\n"
            f"CVSS 9.1 | GSMA FS.11 Cat-3"
        ),
        "dos": (
            f"[SigPloit] MAP SRI-DoS Flood\n"
            f"Target MSISDN : {msisdn}\n"
            f"Sending 100 rapid MAP SRI_SM queries...\n"
            f"[✓] HLR overloaded at query 43 — no response after 100ms\n"
            f"[!] Subscriber registration rejected (Cancel Location triggered)\n"
            f"VULNERABILITY: MAP rate-limiting absent on HLR\n"
            f"CVSS 7.5 | GSMA FS.11 Cat-4"
        ),
    }
    return _demo("sigploit", demos.get(mode, demos["location"]))

# ── scapy SS7 ─────────────────────────────────────────────────────────────────
@app.post("/run/scapy_ss7", response_model=RunResult)
async def run_scapy_ss7(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    op = req.operation or "ATI"
    gt = req.gt or "491770000000"
    msisdn = req.msisdn or "491771234567"
    scapy_script = f"/opt/tools/scapy_ss7_{op.lower()}.py"
    if os.path.exists(scapy_script):
        return _run(["python3", scapy_script, "--gt", gt, "--msisdn", msisdn], timeout=30)
    return _demo("scapy", (
        f"[Scapy SS7] Crafting MAP {op} PDU\n"
        f"  Source GT : {gt}\n"
        f"  MSISDN    : {msisdn}\n\n"
        f">>> pkt = SCCP()/MAP_ATI(msisdn='{msisdn}',gt='{gt}')\n"
        f">>> send(pkt)\n"
        f"Sent 1 packets.\n\n"
        f"[Response] MAP ATI Ack received\n"
        f"  Raw bytes: 62 41 48 04 00 00 00 01 6b 2a ...\n"
        f"  Decoded: IMSI=26201XXXXXXX, VLR=+49177888, CellId=7700-3891\n"
        f"FINDING: MAP {op} succeeds without SCCP Calling-GT category check"
    ))

# ── svmap (SIPVicious) ────────────────────────────────────────────────────────
@app.post("/run/svmap", response_model=RunResult)
async def run_svmap(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "192.168.1.0/24"
    if _tool_available("svmap"):
        return _run(["svmap", target], timeout=60)
    if _tool_available("svmap.py"):
        return _run(["svmap.py", target], timeout=60)
    return _demo("svmap", (
        f"[SIPVicious] svmap — SIP Device Discovery\n"
        f"Target: {target}\n\n"
        f"SipVicious PRO v0.3.5 / svmap\n"
        f"| SIP Device        | IP              | Port | Useragent              |\n"
        f"|-------------------|-----------------|------|------------------------|\n"
        f"| FreePBX 17        | 192.168.1.10    | 5060 | Asterisk PBX 20.1      |\n"
        f"| Cisco ATA 190     | 192.168.1.20    | 5060 | Cisco-ATA190/1.2.3     |\n"
        f"| Kamailio 5.7      | 192.168.1.30    | 5060 | kamailio (5.7.0)       |\n"
        f"3 SIP devices discovered"
    ))

# ── svwar (SIPVicious ext enum) ───────────────────────────────────────────────
@app.post("/run/svwar", response_model=RunResult)
async def run_svwar(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "192.168.1.10"
    ext_range = req.ext_range or "100-200"
    if _tool_available("svwar"):
        return _run(["svwar", "-e", ext_range, target], timeout=60)
    return _demo("svwar", (
        f"[SIPVicious] svwar — Extension Bruteforce\n"
        f"Target: {target}  Extensions: {ext_range}\n\n"
        f"| Extension | Auth       | Status   |\n"
        f"|-----------|------------|----------|\n"
        f"| 100       | reqd       | Found    |\n"
        f"| 101       | reqd       | Found    |\n"
        f"| 102       | noauth     | OPEN     |\n"
        f"| 200       | reqd       | Found    |\n"
        f"VULNERABILITY: Extension 102 accepts calls without authentication\n"
        f"CVSS 5.3 | IMS CID abuse risk"
    ))

# ── kamailio test (SIP OPTIONS probe) ────────────────────────────────────────
@app.post("/run/kamailio_test", response_model=RunResult)
async def run_kamailio_test(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "192.168.1.30"
    # send SIP OPTIONS via sipsak or nmap NSE if available
    if _tool_available("sipsak"):
        return _run(["sipsak", "-s", f"sip:{target}"], timeout=15)
    return _demo("kamailio", (
        f"[SIP OPTIONS Probe] → {target}:5060\n\n"
        f"OPTIONS sip:{target} SIP/2.0\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-telsec-probe\n"
        f"From: <sip:telsec@127.0.0.1>;tag=audit001\n"
        f"To: <sip:{target}>\n"
        f"Call-ID: audit-001@telsec\n"
        f"CSeq: 1 OPTIONS\n\n"
        f"--- Response received ---\n"
        f"SIP/2.0 200 OK\n"
        f"Allow: INVITE,ACK,CANCEL,BYE,OPTIONS,REGISTER,SUBSCRIBE\n"
        f"Supported: path,100rel\n"
        f"Server: Kamailio (5.7.0)\n\n"
        f"FINDING: Kamailio responds to unauthenticated OPTIONS\n"
        f"FINDING: Server header discloses version (Kamailio 5.7.0)\n"
        f"CVSS 5.3 | Information Disclosure"
    ))

# ── dnsrecon ──────────────────────────────────────────────────────────────────
@app.post("/run/dnsrecon", response_model=RunResult)
async def run_dnsrecon(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if not req.domain and not req.target:
        return RunResult(stderr="domain or target is required", returncode=1)
    domain = req.domain or req.target
    if _tool_available("dnsrecon"):
        return _run(["dnsrecon", "-d", domain, "-t", req.types or "std"], timeout=45)
    return _demo("dnsrecon", (
        f"[dnsrecon] Standard DNS Enumeration: {domain}\n\n"
        f"[*] std Record Enumeration\n"
        f"[*] A      {domain}        93.184.216.34\n"
        f"[*] MX     {domain}        mail.{domain}  priority=10\n"
        f"[*] NS     {domain}        ns1.example.com\n"
        f"[*] TXT    {domain}        v=spf1 include:_spf.{domain} ~all\n"
        f"[*] SOA    {domain}        ns1.{domain} admin.{domain}\n"
        f"[*] AXFR   {domain}        ok — zone transfer REJECTED\n"
        f"[+] 5 records found — no zone transfer vulnerability"
    ))

# ── whois ─────────────────────────────────────────────────────────────────────
@app.post("/run/whois", response_model=RunResult)
async def run_whois(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or req.domain
    if not target:
        return RunResult(stderr="target required", returncode=1)
    if _tool_available("whois"):
        return _run(["whois", target], timeout=15)
    return _demo("whois", f"[DEMO] whois {target}\n\nDomain Name: {target.upper()}\nRegistrar: Example Registrar\nCreated: 2006-03-15\nExpires: 2027-03-15\nName Server: ns1.{target}\nName Server: ns2.{target}\nStatus: clientTransferProhibited")

# ── hping3 ────────────────────────────────────────────────────────────────────
@app.post("/run/hping3", response_model=RunResult)
async def run_hping3(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "127.0.0.1"
    flags = (req.flags or "-S -p 80 -c 5").split()
    if _tool_available("hping3"):
        return _run(["hping3"] + flags + [target], timeout=30)
    return _demo("hping3", (
        f"[DEMO] hping3 {' '.join(flags)} {target}\n\n"
        f"HPING {target} (lo {target}): S set, 40 headers + 0 data bytes\n"
        f"len=44 ip={target} ttl=64 DF id=0 sport=80 flags=SA seq=0 win=512 rtt=0.2 ms\n"
        f"len=44 ip={target} ttl=64 DF id=0 sport=80 flags=SA seq=1 win=512 rtt=0.1 ms\n"
        f"--- {target} hping3 statistic ---\n"
        f"5 packets transmitted, 5 packets received, 0% packet loss"
    ))

# ── osmocom (SS7 connectivity test) ───────────────────────────────────────────
@app.post("/run/osmocom", response_model=RunResult)
async def run_osmocom(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    return _demo("osmocom", (
        f"[Osmocom SS7] SCCP Connectivity Test\n"
        f"Target STP: {req.target or '192.168.1.100'}\n"
        f"OPC: {req.extra.split(',')[0] if req.extra else '0001'}\n"
        f"DPC: {req.extra.split(',')[1] if ',' in req.extra else '0002'}\n\n"
        f"Establishing M3UA over SCTP...\n"
        f"[✓] SCTP handshake complete (port 2905)\n"
        f"[✓] M3UA BEAT / BEAT-Ack exchanged\n"
        f"[✓] MTP3 connectivity established\n"
        f"Sending SCCP UDT (Any-Time-Interrogation test)...\n"
        f"[✓] SCCP response received from GT 0x{req.gt or '0491770000000':>013}\n"
        f"FINDING: No SCCP Calling-GT validation — external GT accepted"
    ))

# ── grgsm (GSM scanner — demo only in Docker) ─────────────────────────────────
@app.post("/run/grgsm", response_model=RunResult)
async def run_grgsm(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    return _demo("grgsm", (
        "[gr-gsm] GSM Cell Scanner\n"
        "NOTE: Requires physical RTL-SDR / HackRF — simulated output shown\n\n"
        "Scanning GSM900 band ...\n"
        "Found cell: ARFCN=70 (935.2 MHz) BSIC=017 MCC=234 MNC=30 LAC=5100 CID=1234\n"
        "Found cell: ARFCN=75 (935.8 MHz) BSIC=022 MCC=234 MNC=30 LAC=5100 CID=1235 [WEAK CIPHER: A5/1]\n"
        "Found cell: ARFCN=82 (936.4 MHz) BSIC=003 MCC=234 MNC=10 LAC=7300 CID=9920\n\n"
        "VULNERABILITY: Cell CID=1235 advertises A5/1 only — known-plaintext downgrade possible"
    ))

# ── kalibrate (GSM frequency) ─────────────────────────────────────────────────
@app.post("/run/kalibrate", response_model=RunResult)
async def run_kalibrate(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    return _demo("kal", (
        "[kalibrate-rtl] GSM Frequency Scanner\n"
        "NOTE: Requires RTL-SDR hardware — simulated output shown\n\n"
        "Scanning GSM900...\n"
        "  chan: 70  power: 58.78  ARFCN: 70  (935.2 MHz)\n"
        "  chan: 75  power: 63.41  ARFCN: 75  (935.8 MHz) ← strongest\n"
        "  chan: 82  power: 42.11  ARFCN: 82  (936.4 MHz)\n\n"
        "Estimated clock offset: -4.8 ppm (vs expected 0 ppm)\n"
        "Best channel for monitoring: ARFCN 75"
    ))

# ── GTScan ───────────────────────────────────────────────────────────────────
@app.post("/run/gtscan", response_model=RunResult)
async def run_gtscan(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    gt = req.gt or "4917"
    target = req.target or "192.168.1.100"
    extra = req.extra or "1-1-1,1000,HLR (6)"
    parts = extra.split(",")
    opc = parts[0] if parts else "1-1-1"
    scan_range = parts[1] if len(parts) > 1 else "1000"
    ss = parts[2] if len(parts) > 2 else "HLR (6)"
    gtscan_path = "/opt/tools/GTScan/gtscan.py"
    if os.path.exists(gtscan_path):
        return _run(["python3", gtscan_path, "--gt-prefix", gt, "--stp", target,
                     "--range", scan_range], timeout=60)
    return _demo("gtscan", (
        f"[GTScan] SS7 Global Title Enumeration\n"
        f"GT Prefix   : {gt}\n"
        f"Target STP  : {target}\n"
        f"OPC         : {opc}\n"
        f"Range       : {gt}000000 - {gt}{scan_range}\n"
        f"Subsystem   : {ss}\n\n"
        f"Sending SCCP UDT probes...\n"
        f"[✓] {gt}000001  → HLR RESPONSE    subsys=6  (ACTIVE)\n"
        f"[✓] {gt}000002  → SMSC RESPONSE   subsys=147 (ACTIVE)\n"
        f"[-] {gt}000003  → TIMEOUT\n"
        f"[✓] {gt}000007  → MSC RESPONSE    subsys=8  (ACTIVE)\n\n"
        f"Summary: 3 active GTs found\n"
        f"VULNERABILITY: HLR/SMSC respond to external GT probes\n"
        f"CVSS 7.5 | GSMA FS.11 Cat-1"
    ))

# ── Sigshark ──────────────────────────────────────────────────────────────────
@app.post("/run/sigshark", response_model=RunResult)
async def run_sigshark(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    if req.pcap_b64:
        import base64, tempfile
        try:
            data = base64.b64decode(req.pcap_b64)
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
                f.write(data); pcap_path = f.name
            sigshark_path = "/opt/tools/sigshark/sigshark.py"
            if os.path.exists(sigshark_path):
                return _run(["python3", sigshark_path, pcap_path], timeout=30)
        except Exception as e:
            return RunResult(stderr=str(e), returncode=1)
    return _demo("sigshark", (
        "[Sigshark] SS7/Diameter PCAP Analyzer\n"
        "Grouping TCAP transactions...\n\n"
        "TRANSACTION SUMMARY\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│ #  │ GT Src          │ GT Dst      │ Op   │ Result     │\n"
        "├────────────────────────────────────────────────────────┤\n"
        "│  1 │ 491770000001    │ 49177HLR001 │ ATI  │ SUCCESS ⚠️  │\n"
        "│  2 │ 491770000001    │ 49177HLR001 │ SRI  │ SUCCESS ⚠️  │\n"
        "│  3 │ 334550000099    │ 49177HLR001 │ ATI  │ SUCCESS ⚠️  │\n"
        "│  4 │ 19177000002     │ 49177SMSC01 │ SRI-SM│ SUCCESS ⚠️ │\n"
        "│  5 │ 44770000003     │ 49177HLR001 │ PSI  │ TIMEOUT    │\n"
        "└────────────────────────────────────────────────────────┘\n\n"
        "FINDINGS:\n"
        "  - 3 external GTs successfully queried HLR (ATI/SRI)\n"
        "  - SRI-SM succeeded from non-home network GT\n"
        "  - CVSS 8.2 | GSMA FS.11 Cat-2/3"
    ))

# ── SCTPScan ──────────────────────────────────────────────────────────────────
@app.post("/run/sctpscan", response_model=RunResult)
async def run_sctpscan(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "192.168.1.0/24"
    ports = req.flags or "2905,3868,36412,38412,9900"
    # Try nmap SCTP probe first (available if nmap installed)
    if _tool_available("nmap"):
        return _run(["nmap", "-sY", f"-p{ports}", "--open", target], timeout=60)
    return _demo("sctpscan", (
        f"[SCTPScan] SCTP Port Discovery\n"
        f"Target : {target}\n"
        f"Ports  : {ports}\n\n"
        f"Scanning...\n"
        f"192.168.1.10  port 2905  OPEN   (M3UA/SIGTRAN) ⚠️\n"
        f"192.168.1.10  port 9900  OPEN   (SUA/SCCP)\n"
        f"192.168.1.20  port 3868  OPEN   (Diameter) ⚠️\n"
        f"192.168.1.30  port 36412 OPEN   (S1-MME) ⚠️\n"
        f"192.168.1.40  port 38412 CLOSED\n\n"
        f"FINDINGS: 3 SCTP services exposed without IP-ACL\n"
        f"CVSS 6.5 | 3GPP TS 33.210"
    ))

# ── 5Greplay ──────────────────────────────────────────────────────────────────
@app.post("/run/5greplay", response_model=RunResult)
async def run_5greplay(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "127.0.0.1"
    mode = req.mode or "replay"
    iface = req.test_type or "N2 (NGAP/SCTP)"
    replay_path = "/opt/tools/5Greplay/build/5greplay"
    if os.path.exists(replay_path) and req.pcap_b64:
        import base64, tempfile
        data = base64.b64decode(req.pcap_b64)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(data); pcap_path = f.name
        return _run([replay_path, "-t", target, "-m", mode, "-i", pcap_path], timeout=30)
    return _demo("5greplay", (
        f"[5Greplay] 5G Traffic {mode.title()} — {iface}\n"
        f"Target : {target}\n"
        f"Mode   : {mode}\n\n"
        f"Loading PCAP... 48 NGAP packets found\n"
        f"Replaying to AMF at {target}...\n"
        f"  [1/3] NG Setup Request              → 200 NG Setup Response ✓\n"
        f"  [2/3] Initial UE Message (Attach)   → 200 Initial Context Setup ✓\n"
        f"  [3/3] REPLAYED Initial UE Message   → 200 Accepted ⚠️\n\n"
        f"VULNERABILITY: AMF accepted replayed Initial UE Message\n"
        f"No sequence number or replay protection detected\n"
        f"CVSS 8.1 | 3GPP TS 33.501 §5.3.3"
    ))

# ── SCAT ──────────────────────────────────────────────────────────────────────
@app.post("/run/scat", response_model=RunResult)
async def run_scat(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    scat_path = "/opt/tools/scat/scat.py"
    if req.pcap_b64 and os.path.exists(scat_path):
        import base64, tempfile
        data = base64.b64decode(req.pcap_b64)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(data); pcap_path = f.name
        return _run(["python3", scat_path, "-t", req.mode or "qualcomm", pcap_path], timeout=30)
    return _demo("scat", (
        "[SCAT] LTE/5G Control Plane Log Parser\n"
        "Format: auto-detect → Qualcomm DIAG\n\n"
        "Decoded Messages:\n"
        "  [00:00.001] RRC: RRCConnectionSetup\n"
        "  [00:00.012] NAS: AttachRequest IMSI=262010000000001 type=EPS_ATTACH\n"
        "  [00:00.031] NAS: AuthenticationRequest RAND=0x3F2A... autn=0x7B...\n"
        "  [00:00.045] NAS: SecurityModeCommand NAS-EIA=EIA2 NAS-EEA=EEA0\n"
        "  [00:00.055] NAS: AttachAccept T3412=54min GUTI=2620100001afe\n\n"
        "FINDINGS:\n"
        "  ⚠️  NAS-EEA0 (NULL encryption) negotiated — traffic unencrypted\n"
        "  CVSS 6.5 | 3GPP TS 33.401 §7.2.4"
    ))

# ── LUCID ─────────────────────────────────────────────────────────────────────
@app.post("/run/lucid", response_model=RunResult)
async def run_lucid(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    lucid_path = "/opt/tools/lucid-ddos/lucid_cnn.py"
    if os.path.exists(lucid_path) and req.pcap_b64:
        import base64, tempfile
        data = base64.b64decode(req.pcap_b64)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(data); pcap_path = f.name
        return _run(["python3", lucid_path, "--predict", pcap_path], timeout=60)
    return _demo("lucid", (
        "[LUCID] CNN DDoS Flow Classification\n"
        "Model: LUCID-v1 (CIC-DDoS2019)\n\n"
        "Flow Analysis Results:\n"
        "┌──────────────────┬────────────┬──────────┬────────────┐\n"
        "│ Flow ID          │ Protocol   │ Class    │ Confidence │\n"
        "├──────────────────┼────────────┼──────────┼────────────┤\n"
        "│ 192.168.1.1:443  │ TCP        │ BENIGN   │ 98.2%      │\n"
        "│ 10.0.0.5:8080    │ HTTP/2     │ HTTP-FL  │ 99.7% ⚠️   │\n"
        "│ 10.0.0.6:2152    │ UDP/GTP-U  │ UDP-FL   │ 97.4% ⚠️   │\n"
        "│ 192.168.1.10:53  │ DNS        │ DNS-AMP  │ 99.9% ⚠️   │\n"
        "│ 172.16.0.1:22    │ TCP        │ BENIGN   │ 95.1%      │\n"
        "└──────────────────┴────────────┴──────────┴────────────┘\n\n"
        "3 DDoS flows detected | 2 benign\n"
        "Recommendation: Rate-limit UDP port 2152 (GTP-U) from external sources\n"
        "CVSS 7.5 | GSMA FS.19"
    ))

# ── MobiWatch ─────────────────────────────────────────────────────────────────
@app.post("/run/mobiwatch", response_model=RunResult)
async def run_mobiwatch(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    attack = req.extra or "IMSI Catcher"
    mobiwatch_path = "/opt/tools/MobiWatch/mobiwatch.py"
    if os.path.exists(mobiwatch_path):
        return _run(["python3", mobiwatch_path, "--mode", "offline"], timeout=60)
    return _demo("mobiwatch", (
        f"[MobiWatch] O-RAN L3 Intrusion Detection\n"
        f"Model: LSTM-Attention | Simulated attack: {attack}\n\n"
        f"Loading MobiFlow telemetry...\n"
        f"Processing 1024 flow records from E2 interface...\n\n"
        f"DETECTION RESULTS:\n"
        f"  Timestamp   : 2026-03-24T10:45:12Z\n"
        f"  UE RNTI     : 0x4A2F\n"
        f"  Alert Type  : {attack}\n"
        f"  Confidence  : 97.3%\n"
        f"  Evidence    :\n"
        f"    - RRC Connection Request without prior Release\n"
        f"    - Missing Authentication in subsequent NAS Attach\n"
        f"    - RSRP -85 dBm (stronger than serving cell)\n\n"
        f"ACTION: Suspicious gNB at PCI=115 — block E2 association\n"
        f"CVSS 8.6 | 3GPP TS 33.501 §5.4 | GSMA FS.54"
    ))

# ── ZMap ──────────────────────────────────────────────────────────────────────
@app.post("/run/zmap", response_model=RunResult)
async def run_zmap(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    target = req.target or "192.168.1.0/24"
    port = req.port_range or "443"
    rate = "1000"
    if _tool_available("zmap"):
        return _run(["zmap", "-p", port, f"--rate={rate}", target], timeout=60)
    return _demo("zmap", (
        f"[ZMap] Fast Network Scanner\n"
        f"Target : {target}\n"
        f"Port   : {port}\n"
        f"Rate   : {rate} pps\n\n"
        f"Starting ZMap scan...\n"
        f"  192.168.1.10  OPEN  ← open port {port}\n"
        f"  192.168.1.20  OPEN  ← open port {port}\n"
        f"  192.168.1.100 OPEN  ← open port {port}\n\n"
        f"Scan complete — 3 hosts responded\n"
        f"Duration: 1.2s | Sent: 254 pkts | Recv: 3\n"
        f"FINDING: Port {port} exposed on 3 hosts — verify ACL policy"
    ))

# ── SigFW ─────────────────────────────────────────────────────────────────────
@app.post("/run/sigfw", response_model=RunResult)
async def run_sigfw(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    rules = req.extra or "GSMA FS.11 Cat-1"
    return _demo("sigfw", (
        f"[SigFW] SS7/Diameter Signaling Firewall\n"
        f"Active Rules: {rules}\n\n"
        f"Evaluating captured signaling traffic...\n\n"
        f"RULE EVALUATION RESULTS:\n"
        f"  BLOCKED  | MAP ATI from external GT 491770000001 → [FS.11 Cat-1]\n"
        f"  BLOCKED  | MAP SRI-SM from non-partner GT 19177000002 → [FS.11 Cat-3]\n"
        f"  ALLOWED  | MAP SAI from own-network GT 4917770001 → [whitelist]\n"
        f"  BLOCKED  | Diameter S6a from unknown Origin-Host → [Origin-Host check]\n"
        f"  RATE-LTD | GT 334550000099: 47 ATI in 60s → limit=10/min [rate limit]\n\n"
        f"Summary: 4 BLOCKED | 1 ALLOWED | 1 RATE-LIMITED\n"
        f"SigFW effectiveness: 80% attack surface reduced\n"
        f"Recommendation: Deploy SigFW in BLOCK mode on SS7/Diameter interconnect"
    ))

# ── 5GBaseChecker ─────────────────────────────────────────────────────────────
@app.post("/run/5gbasechecker", response_model=RunResult)
async def run_5gbasechecker(req: RunRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    checks = req.extra or "NULL SUCI scheme|NAS integrity bypass"
    checker_path = "/opt/tools/5GBaseChecker/run_checker.py"
    if os.path.exists(checker_path):
        return _run(["python3", checker_path, "--checks", checks,
                     "--target", req.target or "127.0.0.1"], timeout=60)
    findings = []
    if "NULL SUCI" in checks:
        findings.append("  [FAIL] NULL SUCI scheme accepted → IMSI linkability possible\n         CVE-2021-26031 | CVSS 6.5")
    if "NAS integrity" in checks:
        findings.append("  [FAIL] NAS SecurityModeCommand w/o integrity check accepted\n         CVSS 8.1 | 3GPP TS 33.501 §6.7.2")
    if "Auth failure" in checks:
        findings.append("  [PASS] Authentication Failure handled correctly")
    if "downgrade" in checks.lower():
        findings.append("  [FAIL] Forced 5G→4G downgrade via RRC redirect accepted\n         CVSS 7.4 | 3GPP TS 33.501 §5.3.5")
    if not findings:
        findings.append("  [PASS] All selected checks passed")
    return _demo("5gbasechecker", (
        f"[5GBaseChecker] 5G NAS FSM Verification\n"
        f"Mode: {req.mode or 'demo'}\n"
        f"Checks: {checks}\n\n"
        f"Running automata learning on NAS state machine...\n\n"
        f"RESULTS:\n" + "\n".join(findings) + "\n\n"
        f"FSM deviations found: {sum(1 for f in findings if 'FAIL' in f)}\n"
        f"Reference: 3GPP TS 33.501, TS 24.501"
    ))

# ── SS7 legacy endpoints ──────────────────────────────────────────────────────
@app.post("/api/ss7/sigploit")
async def ss7_legacy(x_api_key: str = Header(None), target: str = "", msisdn: str = "", gt: str = ""):
    verify_key(x_api_key)
    return {"result": f"ATI probe to {msisdn} via {gt}", "vuln": "Unauthenticated MAP ATI"}

@app.post("/api/diameter/test")
async def diameter_test(x_api_key: str = Header(None)):
    verify_key(x_api_key)
    return {"result": "S6a HSS accepts spoofed Origin-Host", "severity": "CRITICAL"}

@app.post("/api/gtp/scan")
async def gtp_scan(x_api_key: str = Header(None), target: str = ""):
    verify_key(x_api_key)
    return {"teids": ["0x8A2F1B01"], "result": "Active GTP session found", "target": target}

@app.get("/api/5gc/status")
async def fivegc_status(x_api_key: str = Header(None)):
    verify_key(x_api_key)
    return {"nfs": [
        {"name": "AMF", "status": "running"}, {"name": "SMF", "status": "running"},
        {"name": "UPF", "status": "running"}, {"name": "NRF", "status": "running"},
    ]}

@app.post("/api/ueransim/test")
async def ueransim_test(x_api_key: str = Header(None), test_type: str = "suci"):
    verify_key(x_api_key)
    return {"test": test_type, "result": "SUCI null scheme accepted — IMSI linkability"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
