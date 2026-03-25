"""GTP-C/GTP-U Protocol Simulator - Core network tunneling with IMSI hijacking tests"""
import random
from datetime import datetime

class GTPSimulator:
    
    @staticmethod
    def simulate_create_session_hijack(imsi, target_apn, attacker_pgw):
        """Simulate GTP-C Create Session Request with PGW hijacking"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        teid = random.randint(100000000, 999999999)
        seq = random.randint(1000, 9999)
        
        log = f"""[{timestamp}] [GTP-C] Initiating S11 tunnel hijacking test
[{timestamp}] [UDP] Connected to SGW on port 2123

--- CREATE SESSION REQUEST (Type: 32) ---
Message Length: 245 bytes
TEID: 0x00000000 (Initial request)
Sequence: {seq}

=== Information Elements ===

IMSI: {imsi}
 RAT Type: 6 (EUTRAN)

Servicing Network: MCC=405, MNC=01 (India)

MME-FQ-CSID:
 Node-ID: 192.168.1.50 (MME)
 CSID: 1

APN: {target_apn}
 Selection Mode: MS or network provided APN

PDN Type: IPv4

PDN Address Allocation: 0.0.0.0 (Dynamic)

Maximum APN Restriction: Public-1

APN-AMBR:
 UL: 50 Mbps
 DL: 100 Mbps

Bearer Context (to be created):
 EPS Bearer ID: 5
 Bearer Level QoS:
   QCI: 9 (Non-GBR, Best effort)
   ARP: Priority=8
 SGW S5/S8 Address (Control): 10.0.1.1
 SGW S5/S8 TEID (Control): 0x{teid:08X}

Recovery: 42

S11-SGW-F-TEID:
 IPv4: 10.0.1.1
 TEID: 0x{teid:08X}

HEX DUMP:
48 20 00 F5 00 00 00 00 00 00 {seq:04X} 00
01 00 08 00 {imsi[-15:]} (IMSI IE)
63 00 01 00 06 (RAT Type = EUTRAN)

[{timestamp}] [GTP-C] Request sent via S11 interface (245 bytes)
[{timestamp}] [GTP-C] Waiting for Create Session Response...

[{timestamp}] ⚠️ [ATTACK] Injecting fake Create Session Response
[{timestamp}] [SPOOF] Crafting response with attacker PGW

--- CREATE SESSION RESPONSE (Type: 33) [SPOOFED] ---
Message Length: 198 bytes
TEID: 0x{teid:08X}
Sequence: {seq}

Cause: Request accepted (16)

PDN Address Allocation:
 IPv4: 100.64.1.{random.randint(10,250)} [ASSIGNED]

Bearer Context (created):
 EPS Bearer ID: 5
 Cause: Request accepted
 PGW S5/S8 Address: {attacker_pgw} [!!! ATTACKER CONTROLLED !!!]
 PGW S5/S8 TEID (Control): 0xDEADBEEF
 PGW S5/S8 TEID (User): 0xCAFEBABE
 Bearer QoS: QCI=9

PGW-FQ-CSID:
 Node-ID: {attacker_pgw} [MALICIOUS PGW]

[{timestamp}] [GTP-C] Session established - TEID: 0x{teid:08X}
[{timestamp}] [GTP-U] User plane tunnel active
[{timestamp}] [DATA] All user traffic routing through {attacker_pgw}

=== GTP-U DATA PLANE ===
[{timestamp}] [CAPTURE] Intercepting user packets:

Packet #1:
 GTP Header: Version=1, PT=1, TEID=0xCAFEBABE
 Payload: HTTP GET /api/banking/balance
 Source IP: 100.64.1.{random.randint(10,250)}
 Dest IP: 203.123.45.67
 [SENSITIVE] Banking API request captured

Packet #2:
 GTP Header: TEID=0xCAFEBABE
 Payload: DNS Query for paytm.com
 [INFO] Payment service access detected

Packet #3:
 GTP Header: TEID=0xCAFEBABE
 Payload: HTTPS to www.uidai.gov.in
 [SENSITIVE] Aadhaar portal access

[ANALYSIS] 🔴 CRITICAL VULNERABILITY DETECTED

Finding: GTP-C Session Hijacking via Response Spoofing
 - CVE: CVE-2019-25101 (GTP Path Management Bypass)
 - GSMA: FS.07 Section 3.2 (GTP Message Authentication)
 - 3GPP: TS 29.274 (GTPv2-C Protocol)

What Happened:
 1. Legitimate SGW initiated Create Session Request
 2. Attacker injected spoofed Create Session Response
 3. Response contained attacker-controlled PGW address
 4. All user data now routes through malicious PGW
 5. No message authentication (no HMAC/digital signature)

Impact:
 - Man-in-the-Middle: All user traffic intercepted
 - Data exfiltration: Banking, payment, Aadhaar data captured
 - Session persistence: Hijack remains until detach
 - Mass surveillance: Scale to thousands of subscribers
 - India Critical: Violates TRAI privacy regulations

Exposed Data:
 - Banking credentials and transaction details
 - Payment app usage (Paytm, PhonePe, Google Pay)
 - Government portal access (Aadhaar, mAadhaar)
 - Social media credentials
 - Location data via IP geolocation

Recommended Fixes:
 1. Deploy GTP firewall at SGW/PGW (GSMA FS.07)
 2. Enable GTP message authentication (3GPP TS 33.401)
 3. Implement PLMN-level GTP filtering
 4. Use IPsec tunnels for inter-PLMN GTP
 5. DoT/TRAI: Mandate GTP security for all TSPs

Compliance Impact:
 - NESAS Phase-2: FAIL (GTP authentication missing)
 - DoT Security Audit: Non-compliant
 - TRAI Data Protection: Violation of privacy norms

Risk Score: 9.5/10 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L)
"""
        
        return {
            "success": True,
            "log": log,
            "vuln": "GTP-C response spoofing enables PGW hijacking",
            "cvss": 9.5,
            "cve": "CVE-2019-25101",
            "gsma_ref": "FS.07",
            "nesas_status": "FAIL",
            "intercepted_data": [
                "Banking API requests",
                "Payment service queries",
                "Aadhaar portal access"
            ]
        }
    
    @staticmethod
    def simulate_gtp_reflection_attack(target_sgsn_ip):
        """Simulate GTP-U reflection/amplification DDoS attack"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        spoofed_teid = random.randint(1000000, 9999999)
        
        log = f"""[{timestamp}] [GTP-U] Initiating reflection attack test
[{timestamp}] [UDP] Sending crafted packets to port 2152

--- GTP-U ECHO REQUEST (Type: 1) ---
Version: 1
Protocol Type: GTP (1)
Message Type: Echo Request
Length: 4
TEID: 0x00000000
Sequence: {random.randint(1,65535)}

Source IP: {target_sgsn_ip} [SPOOFED - Victim IP]
Dest IP: 203.x.x.x (Target SGSN)

[{timestamp}] Sent 100 Echo Requests with spoofed source
[{timestamp}] [AMPLIFICATION] SGSN responding to victim IP

--- GTP-U ECHO RESPONSE (Type: 2) ---
All 100 responses sent to {target_sgsn_ip}
Amplification Factor: 1.2x
Total bandwidth consumed: 48 Kbps

[{timestamp}] [DDoS] Reflection attack successful
[{timestamp}] [IMPACT] Victim experiencing packet flood

[ANALYSIS] 🟡 MODERATE VULNERABILITY

Finding: GTP-U Reflection/Amplification DDoS
 - CVE: CVE-2018-21265 (GTP Source Validation)
 - GSMA: FS.07 Section 2.4

What Happened:
 1. Attacker sent GTP Echo Requests with spoofed source IP
 2. SGSN replied to victim IP without validation
 3. Can be scaled for DDoS amplification

Impact:
 - Service disruption for victim infrastructure
 - Network congestion on SGi/S1-U interfaces
 - DoT/TRAI: Affects TSP SLA compliance

Recommended Fixes:
 1. Implement source IP validation (BCP 38)
 2. Rate-limit GTP Echo messages
 3. Deploy anti-DDoS at GTP gateway

Risk Score: 6.5/10 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
"""
        
        return {
            "success": True,
            "log": log,
            "vuln": "GTP-U reflection DDoS attack",
            "cvss": 6.5,
            "cve": "CVE-2018-21265",
            "gsma_ref": "FS.07"
        }

if __name__ == "__main__":
    result = GTPSimulator.simulate_create_session_hijack(
        "405010123456789",
        "internet",
        "192.168.99.1"
    )
    print(result["log"])
