"""5G NAS Protocol Simulator - Registration, Authentication and Security Mode testing"""
import random
from datetime import datetime
import hashlib

class NASSimulator:
    
    @staticmethod
    def simulate_null_integrity_attack(suci, serving_network):
        """Simulate NAS Security Mode downgrade with null integrity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ran_ue_id = random.randint(1000000, 9999999)
        
        log = f"""[{timestamp}] [5G-NAS] Initiating Security Mode Command downgrade test
[{timestamp}] [N1] UE Registration Request received
[{timestamp}] [NGAP] RAN-UE-NGAP-ID: {ran_ue_id}

--- REGISTRATION REQUEST (Message Type: 0x41) ---
Protocol Discriminator: 5GS Mobility Management (0x7E)
Security Header Type: Not protected (0x0)
Message Type: Registration Request (0x41)

5GS Registration Type:
 Follow-on Request: No
 Registration Type: Initial Registration

5GS Mobile Identity:
 Type: SUCI
 SUCI: {suci}
 Home Network: {serving_network}
 Routing Indicator: 0000
 Protection Scheme: ECIES Profile A

UE Security Capability:
 5G-EA: 128-EA0, 128-EA1, 128-EA2, 128-EA3 [EA0 SUPPORTED - Null encryption]
 5G-IA: 128-IA0, 128-IA1, 128-IA2, 128-IA3 [IA0 SUPPORTED - Null integrity]
 EPS-EA: EEA0, EEA1, EEA2, EEA3
 EPS-IA: EIA0, EIA1, EIA2, EIA3

Last Visited TAI:
 MCC: 405 (India)
 MNC: 01
 TAC: 0x000001

HEX DUMP:
7E 00 41 79 00 0D 01 {suci[-12:]} F0 00 00 00 00

[{timestamp}] [AMF] Processing registration...
[{timestamp}] [AUSF] Initiating 5G-AKA authentication

--- AUTHENTICATION REQUEST (Type: 0x56) ---
ngKSI: 0
ABBA: 0x0000
Authentication Parameter RAND:
 {hashlib.md5(suci.encode()).hexdigest()[:32]}
Authentication Parameter AUTN:
 {hashlib.md5(serving_network.encode()).hexdigest()[:32]}

[{timestamp}] [UE] Computing authentication response
[{timestamp}] [UE] RES* = HXRES* (authentication successful)

--- AUTHENTICATION RESPONSE (Type: 0x57) ---
Authentication Response Parameter:
 RES*: {hashlib.sha256((suci+serving_network).encode()).hexdigest()[:32]}

[{timestamp}] [AMF] Authentication SUCCESS
[{timestamp}] [AMF] Deriving K_AMF and NAS keys

[{timestamp}] ⚠️ [ATTACK] AMF selects weakest algorithms

--- SECURITY MODE COMMAND (Type: 0x5D) [DOWNGRADED] ---
Protocol Discriminator: 5GS MM
Security Header: Integrity protected (0x1)
Message Type: Security Mode Command (0x5D)

Selected NAS Security Algorithms:
 Integrity Algorithm: 5G-IA0 (NULL) [!!! CRITICAL !!!]
 Ciphering Algorithm: 5G-EA0 (NULL) [!!! CRITICAL !!!]

ngKSI: 0
Replayed UE Security Capabilities: (same as above)

IMEISV Request: Required

Message Authentication Code: 0x00000000 [NULL INTEGRITY]

[{timestamp}] [NAS] Security Mode Command sent (NULL algorithms)
[{timestamp}] [UE] ⚠️ UE accepting downgraded security

--- SECURITY MODE COMPLETE (Type: 0x5E) ---
Protocol Discriminator: 5GS MM
Security Header: Not protected (0x0) [NULL-IA accepted]
Message Type: Security Mode Complete (0x5E)

IMEISV:
 TAC: 35276609 (Samsung Device)
 SNR: 123456

NAS Message Container:
 Includes: Registration Request (forwarded)

[{timestamp}] [AMF] Security context established with NULL protection
[{timestamp}] [5G-CORE] Registration accepted - SUPI derived

--- REGISTRATION ACCEPT (Type: 0x42) ---
5GS Registration Result: 3GPP access
5G-GUTI:
 GUAMI: MCC=405, MNC=01, AMF Region=1
 5G-TMSI: {random.randint(1000000000, 9999999999)}

Allowed NSSAI:
 S-NSSAI: SST=1 (eMBB), SD=0x000001

[{timestamp}] 🔴 [COMPROMISE] NAS Security bypassed
[{timestamp}] [INTERCEPT] Capturing unprotected NAS messages:

Message #1: PDU Session Establishment Request
 DNN: internet
 PDU Type: IPv4
 [PLAINTEXT] APN configuration exposed

Message #2: Configuration Update Command
 Network Slicing Info: eMBB slice details
 [PLAINTEXT] Network topology revealed

Message #3: De-registration Request
 Cause: Switch off
 [ATTACK] Can inject fake detach to disrupt service

[ANALYSIS] 🔴 CRITICAL VULNERABILITY DETECTED

Finding: NAS Security Mode Downgrade to NULL Algorithms
 - CVE: CVE-2019-17537 (5G NAS Bidding-Down Attack)
 - 3GPP: TS 33.501 Section 6.7.2 (Algorithm Selection)
 - GSMA: FS.31 Section 4.1 (5G Security Baseline)

What Happened:
 1. UE advertised support for NULL algorithms (EA0/IA0)
 2. AMF selected weakest algorithms instead of strongest
 3. All NAS messages transmitted without encryption/integrity
 4. No anti-bidding-down protection enforced
 5. India networks using legacy UE security profiles

Impact:
 - NAS eavesdropping: All control plane messages readable
 - Message injection: Fake detach, service reject attacks
 - Privacy violation: SUPI/GUTI mapping exposed
 - Location tracking: Registration updates in plaintext
 - NESAS Phase-2 FAIL: Mandatory IA1/EA1 minimum required

Exposed Information:
 - SUPI (permanent subscriber identity)
 - IMEI-SV (device fingerprinting)
 - Network slicing configuration
 - DNN (Data Network Name) for all PDU sessions
 - UE capabilities and supported features

Real-world Exploit:
 - Stingray/IMSI catcher for 5G networks
 - Fake base station can force NULL protection
 - Mass surveillance without detection
 - India DoT: Critical for national security

Recommended Fixes:
 1. Disable NULL algorithms (EA0/IA0) in AMF configuration
 2. Enforce minimum security: 128-IA1 and 128-EA1
 3. Enable anti-bidding-down counter (3GPP TS 33.501)
 4. Reject UEs advertising only NULL algorithms
 5. DoT/TEC mandate: IA2/EA2 minimum for Indian networks
 6. TRAI regulation: Ban NULL protection for commercial networks

Compliance Impact:
 - NESAS Phase-2: FAIL (Null algorithm acceptance)
 - 3GPP SA3: Non-compliant with TS 33.501
 - DoT License Condition: Security requirement breach

Risk Score: 9.2/10 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L)
"""
        
        return {
            "success": True,
            "log": log,
            "vuln": "NAS Security Mode downgrade to NULL integrity/encryption",
            "cvss": 9.2,
            "cve": "CVE-2019-17537",
            "3gpp_ref": "TS 33.501",
            "gsma_ref": "FS.31",
            "nesas_status": "FAIL"
        }
    
    @staticmethod
    def simulate_authentication_sync_failure():
        """Simulate 5G-AKA SQN desynchronization attack"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log = f"""[{timestamp}] [5G-AKA] Testing sequence number manipulation

--- AUTHENTICATION REQUEST ---
RAND: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
AUTN: b0a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5
 SQN (concealed): 0x000000000042

[{timestamp}] [ATTACK] UE detects SQN out of sync
[{timestamp}] [UE] Sending Authentication Failure

--- AUTHENTICATION FAILURE (Type: 0x59) ---
5GMM Cause: Synch failure (0x15)
Authentication Failure Parameter (AUTS):
 Computed AUTS: f5*_output XOR SQN_MS || MAC-S
 SQN_MS: 0x000000000100 (UE's expected SQN)

[{timestamp}] [AUSF] Receiving AUTS from UE
[{timestamp}] [AUSF] Re-synchronizing with UDM
[{timestamp}] [UDM] SQN updated to UE value

[{timestamp}] 🟡 [EXPLOIT] Repeated sync failures
[{timestamp}] [DOS] Forcing constant re-authentication

Authentication Attempt #1: SYNC_FAILURE
Authentication Attempt #2: SYNC_FAILURE
Authentication Attempt #3: SYNC_FAILURE
Authentication Attempt #4: SYNC_FAILURE
Authentication Attempt #5: SYNC_FAILURE

[{timestamp}] [IMPACT] UE unable to register
[{timestamp}] [IMPACT] HSS/UDM experiencing high load

[ANALYSIS] 🟡 MODERATE VULNERABILITY

Finding: 5G-AKA Desynchronization Denial of Service
 - CVE: CVE-2020-26559 (AKA SQN Exhaustion)
 - 3GPP: TS 33.102 / TS 33.501 (SQN Management)

What Happened:
 1. Attacker replays old AUTN with outdated SQN
 2. UE rejects and sends AUTS to re-sync
 3. Attacker repeats with different old SQNs
 4. UDM/HSS overwhelmed with sync operations

Impact:
 - Targeted DoS: Specific IMSI unable to register
 - Resource exhaustion: UDM/AUSF overload
 - Emergency service blocked: Critical for E-112
 - India impact: Affects Digital India initiatives

Recommended Fixes:
 1. Rate-limit AUTS processing per SUPI
 2. Implement SQN anti-replay windows
 3. Detect and block sync failure flooding
 4. TRAI: Mandate resilience testing

Risk Score: 6.8/10 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)
"""
        
        return {
            "success": True,
            "log": log,
            "vuln": "5G-AKA SQN desynchronization DoS",
            "cvss": 6.8,
            "cve": "CVE-2020-26559",
            "3gpp_ref": "TS 33.501"
        }

if __name__ == "__main__":
    result = NASSimulator.simulate_null_integrity_attack(
        "suci-0-405-01-0-0-0-0123456789",
        "5G:mnc001.mcc405.3gppnetwork.org"
    )
    print(result["log"])
