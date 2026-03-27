"""
pages/21_tools_catalog.py — Comprehensive Tools Catalog & Usage Guide
======================================================================
A user-friendly reference showing all 28+ telecom security tools:
- What each tool does
- Required inputs and parameters
- Expected outputs
- Use cases and examples
- Protocol/generation coverage
"""
import streamlit as st
from kali_connector import TOOL_ENDPOINTS, health_check

st.set_page_config(page_title="TelSec — Tools Catalog", page_icon="📚", layout="wide")

# ─────────────────────────────────────────────────────────────────────────────
# CSS Styling
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

body, .stApp { 
    font-family: 'Inter', sans-serif !important; 
    background: #0a0f1e; 
}

/* Page Hero */
.page-hero {
    display: flex; align-items: center; gap: 16px;
    background: linear-gradient(135deg, rgba(59,130,246,.08), rgba(139,92,246,.04));
    border: 1px solid rgba(255,255,255,.06); border-radius: 14px;
    padding: 24px 28px; margin-bottom: 28px;
}
.page-hero-icon { font-size: 2.4rem; }
.page-hero-title { font-size: 1.5rem; font-weight: 700; color: #f8fafc; }
.page-hero-sub { font-size: 0.9rem; color: #94a3b8; margin-top: 6px; line-height: 1.5; }

/* Search Box */
.search-container {
    background: rgba(15,23,42,.6); border: 1px solid rgba(59,130,246,.2);
    border-radius: 12px; padding: 20px 24px; margin-bottom: 24px;
}
.search-input input {
    background: rgba(30,41,59,.8) !important;
    border: 1px solid rgba(59,130,246,.3) !important;
    color: #f8fafc !important; font-size: 0.95rem !important;
    border-radius: 8px !important; padding: 12px 16px !important;
}

/* Category Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: rgba(15,23,42,.5); border-radius: 12px;
    padding: 4px; gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #94a3b8 !important;
    border-radius: 8px !important;
    padding: 10px 18px !important;
    font-weight: 600 !important; font-size: 0.88rem !important;
}
.stTabs [aria-selected="true"] {
    background: rgba(59,130,246,.15) !important;
    color: #60a5fa !important;
    border: 1px solid rgba(59,130,246,.3) !important;
}

/* Tool Cards */
.tool-card {
    background: rgba(15,23,42,.7);
    border: 1px solid rgba(255,255,255,.08);
    border-left: 4px solid #3b82f6;
    border-radius: 12px;
    padding: 20px 22px;
    margin-bottom: 16px;
    transition: all 0.2s ease;
}
.tool-card:hover {
    border-color: rgba(59,130,246,.4);
    box-shadow: 0 4px 20px rgba(0,0,0,.3), 0 0 0 1px rgba(59,130,246,.1);
}
.tool-card.critical { border-left-color: #ef4444; }
.tool-card.high { border-left-color: #f97316; }
.tool-card.medium { border-left-color: #f59e0b; }
.tool-card.low { border-left-color: #10b981; }

.tool-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 12px; flex-wrap: wrap; gap: 12px;
}
.tool-name {
    font-size: 1.1rem; font-weight: 700; color: #f8fafc;
    display: flex; align-items: center; gap: 10px;
}
.tool-badge {
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
    padding: 3px 8px; border-radius: 6px; letter-spacing: 0.05em;
}
.badge-recon { background: rgba(59,130,246,.15); color: #60a5fa; border: 1px solid rgba(59,130,246,.3); }
.badge-exploit { background: rgba(239,68,68,.15); color: #f87171; border: 1px solid rgba(239,68,68,.3); }
.badge-wireless { background: rgba(245,158,11,.15); color: #fbbf24; border: 1px solid rgba(245,158,11,.3); }
.badge-telecom { background: rgba(139,92,246,.15); color: #a78bfa; border: 1px solid rgba(139,92,246,.3); }
.badge-analysis { background: rgba(16,185,129,.15); color: #34d399; border: 1px solid rgba(16,185,129,.3); }
.badge-voip { background: rgba(236,72,153,.15); color: #f472b6; border: 1px solid rgba(236,72,153,.3); }
.badge-5g { background: rgba(167,139,250,.15); color: #c4b5fd; border: 1px solid rgba(167,139,250,.3); }

.tool-desc {
    font-size: 0.88rem; color: #cbd5e1; margin-bottom: 14px; line-height: 1.6;
}

/* Input/Output Sections */
.io-section {
    background: rgba(30,41,59,.4); border: 1px solid rgba(255,255,255,.06);
    border-radius: 8px; padding: 14px 16px; margin-bottom: 12px;
}
.io-title {
    font-size: 0.75rem; font-weight: 700; color: #64748b;
    text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px;
    display: flex; align-items: center; gap: 6px;
}
.param-row {
    display: flex; align-items: baseline; gap: 8px;
    margin-bottom: 6px; font-size: 0.82rem;
}
.param-name {
    font-family: 'JetBrains Mono', monospace; font-weight: 600;
    color: #60a5fa; background: rgba(59,130,246,.1);
    padding: 2px 6px; border-radius: 4px; min-width: 140px;
}
.param-type {
    font-size: 0.75rem; color: #94a3b8; font-style: italic;
}
.param-desc { color: #cbd5e1; }
.param-required {
    color: #ef4444; font-size: 0.7rem; font-weight: 700; margin-left: 4px;
}

/* Example Box */
.example-box {
    background: rgba(15,23,42,.8); border: 1px solid rgba(148,163,184,.15);
    border-radius: 8px; padding: 12px 16px; margin-top: 12px;
}
.example-title {
    font-size: 0.75rem; font-weight: 700; color: #94a3b8;
    text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px;
}
.example-code {
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    color: #e2e8f0; line-height: 1.7;
}

/* Status Indicator */
.status-pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: 600;
}
.status-online {
    background: rgba(16,185,129,.15); color: #10b981;
    border: 1px solid rgba(16,185,129,.3);
}
.status-offline {
    background: rgba(148,163,184,.15); color: #94a3b8;
    border: 1px solid rgba(148,163,184,.3);
}

/* Coverage Tags */
.coverage-tags {
    display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px;
}
.cov-tag {
    font-size: 0.7rem; padding: 3px 8px; border-radius: 4px;
    background: rgba(255,255,255,.05); color: #94a3b8;
    border: 1px solid rgba(255,255,255,.08);
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Page Hero
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">📚</div>
  <div>
    <div class="page-hero-title">Tools Catalog & Usage Guide</div>
    <div class="page-hero-sub">
      Complete reference for 28+ telecom security tools · Input requirements · Expected outputs · Use cases
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Health check
health = health_check()
status_class = "status-online" if health["online"] else "status-offline"
status_text = f"✅ {len(health.get('tools', []))} tools online" if health["online"] else "⚫ Demo mode active"
st.markdown(f"""
<div style="margin-bottom:20px;">
  <span class="status-pill {status_class}">
    <span style="width:7px;height:7px;border-radius:50%;background:{'#10b981' if health['online'] else '#94a3b8'}"></span>
    Backend: {status_text}
  </span>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Search & Filter
# ─────────────────────────────────────────────────────────────────────────────
col_search, col_filter = st.columns([3, 1])
with col_search:
    search_query = st.text_input(
        "🔍 Search tools",
        placeholder="Search by name, protocol, or capability (e.g., 'SS7', 'nmap', '5G')...",
        label_visibility="collapsed",
        key="tool_search"
    )
with col_filter:
    sort_option = st.selectbox(
        "Sort by",
        ["Category", "Name (A-Z)", "Name (Z-A)"],
        label_visibility="collapsed",
        key="tool_sort"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Complete Tool Catalog with Detailed Metadata
# ─────────────────────────────────────────────────────────────────────────────
TOOL_CATALOG = {
    # ═══════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE & DISCOVERY
    # ═══════════════════════════════════════════════════════════════════════
    "nmap": {
        "name": "Nmap",
        "category": "Reconnaissance",
        "badge": "recon",
        "icon": "🌐",
        "description": "Network mapper for port scanning, service detection, and OS fingerprinting. Essential for initial network reconnaissance.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "Target IP, hostname, or CIDR range (e.g., '192.168.1.0/24')"},
            {"name": "flags", "type": "string", "required": False, "desc": "Nmap flags (default: '-sV -T4'). Examples: '-sS -O' for stealth + OS detection"},
        ],
        "outputs": "List of open ports, service versions, OS guesses, and script results",
        "example": "nmap -sV -T4 192.168.1.10\n# Discovers running services and versions",
        "coverage": ["2G", "3G", "4G", "5G", "IP"],
        "use_cases": [
            "Discover exposed signaling interfaces (M3UA, Diameter, GTP-C)",
            "Identify vulnerable service versions on core network elements",
            "Map network topology before deeper testing"
        ],
        "docs_url": "https://nmap.org/docs.html"
    },
    
    "zmap": {
        "name": "ZMap",
        "category": "Reconnaissance",
        "badge": "recon",
        "icon": "🔭",
        "description": "Internet-scale network scanner capable of scanning the entire IPv4 space in minutes. Used for large-scale exposure assessment.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "CIDR range or IP list (optimized for /8 or larger)"},
            {"name": "port", "type": "integer", "required": True, "desc": "Single port to scan (ZMap scans one port at a time)"},
            {"name": "output_format", "type": "string", "required": False, "desc": "Output format: 'csv', 'json', 'txt' (default: 'csv')"},
        ],
        "outputs": "List of responsive IPs with metadata (timestamp, banner if applicable)",
        "example": "zmap -p 2905 10.0.0.0/8 -o results.csv\n# Scans entire 10.x.x.x range for SCTP/M3UA",
        "coverage": ["2G", "3G", "4G", "5G", "IP"],
        "use_cases": [
            "Find all exposed M3UA (2905) or Diameter (3868) endpoints globally",
            "Large-scale exposure assessment of telecom infrastructure",
            "Identify misconfigured firewalls allowing signaling traffic"
        ],
        "docs_url": "https://github.com/zmap/zmap"
    },
    
    "dnsrecon": {
        "name": "DNSRecon",
        "category": "Reconnaissance",
        "badge": "recon",
        "icon": "🔎",
        "description": "DNS enumeration tool for discovering subdomains, zone transfers, and DNS records. Critical for mapping operator infrastructure.",
        "inputs": [
            {"name": "domain", "type": "string", "required": True, "desc": "Target domain (e.g., 'operator.com')"},
            {"name": "types", "type": "string", "required": False, "desc": "Record types: 'std,rvl,brt' (standard, reverse, brute-force)"},
        ],
        "outputs": "DNS records (A, AAAA, MX, NS, TXT), subdomains, zone transfer results",
        "example": "dnsrecon -d operator.com -t std,axfr\n# Standard enumeration + zone transfer attempt",
        "coverage": ["IP", "Infrastructure"],
        "use_cases": [
            "Discover roaming partner domains and interconnect points",
            "Find exposed management interfaces via subdomain enumeration",
            "Map DNS infrastructure for social engineering campaigns"
        ],
        "docs_url": "https://github.com/darkoperator/dnsrecon"
    },
    
    "whois": {
        "name": "WHOIS",
        "category": "Reconnaissance",
        "badge": "recon",
        "icon": "📋",
        "description": "Query WHOIS databases for domain registration, IP allocation, and network ownership information.",
        "inputs": [
            {"name": "query", "type": "string", "required": True, "desc": "Domain name, IP address, or ASN to lookup"},
        ],
        "outputs": "Registration details, admin contacts, nameservers, creation/expiry dates",
        "example": "whois 91.108.0.0/16\n# Returns ASN owner (e.g., Telegram), country, abuse contacts",
        "coverage": ["IP", "Infrastructure"],
        "use_cases": [
            "Identify network owners for targeted SS7/Diameter attacks",
            "Gather intelligence on roaming partners",
            "Find abuse contacts for responsible disclosure"
        ],
        "docs_url": "https://www.icann.org/resources/pages/whois-2018-01-17-en"
    },
    
    "svmap": {
        "name": "SVMap",
        "category": "Reconnaissance",
        "badge": "voip",
        "icon": "☎️",
        "description": "SIP network scanner for discovering VoIP endpoints, PBX systems, and SIP servers across networks.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "IP, range, or domain to scan for SIP devices"},
        ],
        "outputs": "List of SIP endpoints with user agents, supported methods, extensions",
        "example": "svmap 192.168.1.0/24\n# Discovers all SIP phones and PBX in subnet",
        "coverage": ["VoLTE", "VoIP", "IMS"],
        "use_cases": [
            "Discover VoLTE endpoints in IMS networks",
            "Identify misconfigured SIP servers accepting anonymous calls",
            "Map VoIP infrastructure before authentication attacks"
        ],
        "docs_url": "https://www.sipvicious.org/"
    },
    
    "svwar": {
        "name": "SVWar",
        "category": "Reconnaissance",
        "badge": "voip",
        "icon": "📞",
        "description": "SIP extension enumerator that identifies valid phone extensions on PBX/VoIP systems without authentication.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "SIP server IP or hostname"},
            {"name": "extension_range", "type": "string", "required": False, "desc": "Range to test (e.g., '1000-9999' or '100,101,102')"},
        ],
        "outputs": "List of valid extensions with registration status",
        "example": "svwar -D -m INVITE -s 192.168.1.10\n# Detects extensions via INVITE method",
        "coverage": ["VoLTE", "VoIP", "IMS"],
        "use_cases": [
            "Enumerate valid extensions for toll fraud attacks",
            "Identify targets for vishing or SIM swapping",
            "Test SIP server authentication policies"
        ],
        "docs_url": "https://www.sipvicious.org/svwar.html"
    },
    
    # ═══════════════════════════════════════════════════════════════════════
    # TELECOM-SPECIFIC TOOLS (SS7 / Diameter / GTP)
    # ═══════════════════════════════════════════════════════════════════════
    "sigploit": {
        "name": "SigPloit",
        "category": "Telecom Exploitation",
        "badge": "telecom",
        "icon": "🎯",
        "description": "Comprehensive SS7, Diameter, and GTP exploitation framework. Implements GSMA FS.11 attack scenarios for authorized testing.",
        "inputs": [
            {"name": "mode", "type": "string", "required": True, "desc": "Protocol mode: 'ss7', 'diameter', 'gtp', 'http2' (5G SBA)"},
            {"name": "target", "type": "string", "required": True, "desc": "Target GT, Origin-Host, or GTP-C endpoint"},
            {"name": "attack_type", "type": "string", "required": False, "desc": "Specific attack: 'ATI', 'SRI', 'CLR', 'IDR', 'CreateSession'"},
            {"name": "msisdn", "type": "string", "required": False, "desc": "Target subscriber number (for subscriber-specific attacks)"},
        ],
        "outputs": "Attack results: location data, IMSI, intercepted SMS, session hijack confirmation",
        "example": "sigploit --mode ss7 --attack ATI --gt 919000000006 --msisdn +919999999999\n# Sends MAP Any-Time-Interrogation",
        "coverage": ["2G", "3G", "4G", "5G"],
        "use_cases": [
            "Test HLR/HSS susceptibility to unauthorized location queries",
            "Validate Diameter firewall rules for CLR/IDR attacks",
            "Demonstrate GTP-C session hijacking on roaming interfaces",
            "Assess 5G SBA API authentication (Nausf, Nudm)"
        ],
        "docs_url": "https://github.com/jekil/SigPloit"
    },
    
    "scapy-ss7": {
        "name": "Scapy-SS7",
        "category": "Telecom Exploitation",
        "badge": "telecom",
        "icon": "🧪",
        "description": "Craft and send custom SS7/MAP packets using Scapy. Enables precise control over TCAP, SCCP, and MAP layer parameters.",
        "inputs": [
            {"name": "gt", "type": "string", "required": True, "desc": "Destination Global Title (e.g., HLR GT)"},
            {"name": "src_gt", "type": "string", "required": False, "desc": "Source GT (spoofed roaming partner)"},
            {"name": "msisdn", "type": "string", "required": True, "desc": "Target subscriber MSISDN"},
            {"name": "operation", "type": "string", "required": True, "desc": "MAP operation: 'ATI', 'PSI', 'SRI', 'SRI-SM', 'UDL'"},
            {"name": "custom_tcap", "type": "string", "required": False, "desc": "Custom TCAP payload (hex) for advanced fuzzing"},
        ],
        "outputs": "Raw MAP response, decoded subscriber data, error codes",
        "example": "# Craft custom MAP PSI with modified SCCP calling party\nsend(MAP_PSI(msisdn='+919999999999')/SCCP(calling_gt='441234567890'))",
        "coverage": ["2G", "3G"],
        "use_cases": [
            "Test non-standard MAP operations not covered by SigPloit",
            "Fuzz TCAP transaction IDs for DoS testing",
            "Bypass simple GT-based filtering with spoofed addressing"
        ],
        "docs_url": "https://scapy.readthedocs.io/"
    },
    
    "gtscan": {
        "name": "GTScan",
        "category": "Telecom Reconnaissance",
        "badge": "telecom",
        "icon": "🗺️",
        "description": "Global Title enumerator that discovers valid HLR/MSC/VLR addresses by probing SS7 networks. Identifies reachable signaling endpoints.",
        "inputs": [
            {"name": "prefix", "type": "string", "required": True, "desc": "GT prefix to enumerate (e.g., '9190' for India mobile numbers)"},
            {"name": "ssn", "type": "integer", "required": False, "desc": "SubSystem Number: 6=HLR, 7=VLR, 8=MSP, 14=GMLC (default: 6)"},
            {"name": "timeout", "type": "integer", "required": False, "desc": "Response timeout in seconds (default: 3)"},
        ],
        "outputs": "List of responding GTs with role (HLR/MSC/VLR) and capabilities",
        "example": "gtscan --prefix 9190 --ssn 6\n# Scans 919000000006 through 919099999996 for HLRs",
        "coverage": ["2G", "3G"],
        "use_cases": [
            "Map SS7 network topology of target operator",
            "Identify HLR ranges for subsequent MAP attacks",
            "Discover misconfigured GTs accepting any SCCP-UDE"
        ],
        "docs_url": "https://github.com/P1sec/GTScan"
    },
    
    "sctpscan": {
        "name": "SCTPScan",
        "category": "Telecom Reconnaissance",
        "badge": "telecom",
        "icon": "🔌",
        "description": "Discovers SCTP endpoints running M3UA, SUA, or other SIGTRAN protocols. Essential for finding SS7-over-IP interfaces.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "IP range to scan (e.g., '10.0.0.0/24')"},
            {"name": "ports", "type": "string", "required": False, "desc": "Ports to scan (default: '2905,9900,4861')"},
        ],
        "outputs": "Open SCTP ports with protocol identification (M3UA/SUA/M2PA)",
        "example": "sctpscan 192.168.1.0/24 -p 2905,9900\n# Finds M3UA and SUA endpoints",
        "coverage": ["3G", "4G", "5G"],
        "use_cases": [
            "Locate STP/DRA SIGTRAN interfaces",
            "Identify unprotected M3UA associations",
            "Map backhaul SCTP links between RNC and core"
        ],
        "docs_url": "https://github.com/medbenali/sctpscan"
    },
    
    "sigshark": {
        "name": "SigShark",
        "category": "Traffic Analysis",
        "badge": "analysis",
        "icon": "📊",
        "description": "Wireshark plugin for deep SS7/Diameter/GTP packet analysis. Automatically detects GSMA FS.11 violations in PCAP files.",
        "inputs": [
            {"name": "pcap_file", "type": "file", "required": True, "desc": "PCAP file containing signaling traffic"},
            {"name": "protocol", "type": "string", "required": False, "desc": "Filter by protocol: 'ss7', 'diameter', 'gtp', 'nas'"},
            {"name": "filter", "type": "string", "required": False, "desc": "Wireshark display filter (e.g., 'map.operationCode == 5')"},
        ],
        "outputs": "Decoded MAP/Diameter operations, violation reports, statistics",
        "example": "sigshark capture.pcap --protocol diameter --filter \"dr.command-flag == 1\"\n# Finds unauthenticated Diameter commands",
        "coverage": ["2G", "3G", "4G", "5G"],
        "use_cases": [
            "Audit captured traffic for Cat-1/Cat-2 violations",
            "Extract IMSI/MSISDN from PCAP for breach assessment",
            "Generate compliance reports for GSMA FS.11 audits"
        ],
        "docs_url": "https://github.com/mti-software/SigShark"
    },
    
    "sigfw": {
        "name": "SigFW",
        "category": "Firewall Testing",
        "badge": "telecom",
        "icon": "🛡️",
        "description": "Open-source SS7/Diameter signaling firewall for testing and research. Can be deployed as a honeypot or protective proxy.",
        "inputs": [
            {"name": "mode", "type": "string", "required": True, "desc": "Operation mode: 'firewall', 'honeypot', 'proxy'"},
            {"name": "config", "type": "string", "required": False, "desc": "Path to firewall rules YAML configuration"},
            {"name": "log_file", "type": "string", "required": False, "desc": "Output log file for blocked attempts"},
        ],
        "outputs": "Firewall logs, blocked attack attempts, statistics dashboard",
        "example": "sigfw --mode firewall --config rules.yaml\n# Deploys firewall with custom rule set",
        "coverage": ["2G", "3G", "4G"],
        "use_cases": [
            "Test existing firewall effectiveness by replaying attacks",
            "Deploy honeypot to attract and log real-world attackers",
            "Prototype custom filtering rules before production deployment"
        ],
        "docs_url": "https://github.com/Signaling-Grace-Solutions/SigFW"
    },
    
    # ═══════════════════════════════════════════════════════════════════════
    # 5G-SPECIFIC TOOLS
    # ═══════════════════════════════════════════════════════════════════════
    "5gbasechecker": {
        "name": "5GBaseChecker",
        "category": "5G Security",
        "badge": "5g",
        "icon": "🚀",
        "description": "Automated 5G NAS security baseline auditor. Checks for null encryption, SUCI exposure, and compliance with 3GPP TS 33.501.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "gNB IP or AMF endpoint"},
            {"name": "ue_config", "type": "string", "required": False, "desc": "UE configuration profile (YAML) with SUPI/keys"},
            {"name": "tests", "type": "string", "required": False, "desc": "Comma-separated test IDs (default: 'all')"},
        ],
        "outputs": "Security baseline report with pass/fail per test, CVSS scores",
        "example": "5gbasechecker --target 192.168.1.100 --tests NR-001,NR-003,NR-007\n# Runs specific 5G NAS security tests",
        "coverage": ["5G"],
        "use_cases": [
            "Verify 5G-EA0 null cipher is rejected by UE/network",
            "Test SUCI null-scheme detection and prevention",
            "Audit GUTI reallocation frequency for tracking risks"
        ],
        "docs_url": "https://github.com/Orange-Cyberdefense/5GBaseChecker"
    },
    
    "5greplay": {
        "name": "5GReplay",
        "category": "5G Testing",
        "badge": "5g",
        "icon": "🔁",
        "description": "GTP/NGAP PCAP replay engine for 5G core testing. Replays captured N2/N3 interface traffic against target 5GC.",
        "inputs": [
            {"name": "pcap_file", "type": "file", "required": True, "desc": "PCAP with NGAP or GTP-U packets"},
            {"name": "target_amf", "type": "string", "required": True, "desc": "Target AMF IP for NGAP replay"},
            {"name": "target_upf", "type": "string", "required": False, "desc": "Target UPF IP for GTP-U replay"},
            {"name": "modify_teid", "type": "boolean", "required": False, "desc": "Auto-modify TEIDs to match target session"},
        ],
        "outputs": "Replay success rate, response packets, error messages",
        "example": "5greplay --pcap ngap_capture.pcap --target-amf 10.0.0.5 --modify-teid\n# Replays NGAP with adjusted TEIDs",
        "coverage": ["5G"],
        "use_cases": [
            "Replay legitimate registration to test duplicate detection",
            "Inject modified PDU session requests for authorization bypass",
            "Test UPF GTP-U validation with crafted tunnel packets"
        ],
        "docs_url": "https://github.com/Alteru/5GReplay"
    },
    
    "scat": {
        "name": "SCAT",
        "category": "5G Analysis",
        "badge": "5g",
        "icon": "📱",
        "description": "5G NAS diagnostic log analyzer for Qualcomm-based devices. Extracts NAS messages, security context, and mobility events from device logs.",
        "inputs": [
            {"name": "log_file", "type": "file", "required": True, "desc": "Qualcomm diag log (QXDM/ELT format) or PCAP"},
            {"name": "filter", "type": "string", "required": False, "desc": "Filter by message type (e.g., 'Registration', 'Service Request')"},
        ],
        "outputs": "Decoded NAS messages, security parameters, state machine transitions",
        "example": "scat --input qmdl_log.qmdl --filter \"5GMM-REGISTER\"\n# Extracts all 5G registration messages",
        "coverage": ["5G"],
        "use_cases": [
            "Debug UE registration failures in lab environments",
            "Extract SUCI/SUPI for privacy analysis",
            "Analyze handover sequences for security context handling"
        ],
        "docs_url": "https://github.com/fgsect/scat"
    },
    
    "mobiwatch": {
        "name": "MobiWatch",
        "category": "5G Analysis",
        "badge": "5g",
        "icon": "⌚",
        "description": "Real-time 5G NAS protocol analyzer with anomaly detection. Monitors N1/N2 interfaces for suspicious patterns.",
        "inputs": [
            {"name": "interface", "type": "string", "required": True, "desc": "Network interface to monitor (e.g., 'eth0')"},
            {"name": "rules", "type": "string", "required": False, "desc": "Path to anomaly detection rules (YAML)"},
        ],
        "outputs": "Live NAS message stream, alerts for anomalies, statistics",
        "example": "mobiwatch --interface eth0 --rules nas_anomalies.yaml\n# Monitors for registration floods, identity mismatches",
        "coverage": ["5G"],
        "use_cases": [
            "Detect IMSI catchers via abnormal NAS behavior",
            "Monitor for registration DoS attacks",
            "Track mobility patterns for location privacy auditing"
        ],
        "docs_url": "https://github.com/mobiwatch"
    },
    
    # ═══════════════════════════════════════════════════════════════════════
    # WIRELESS & SDR TOOLS
    # ═══════════════════════════════════════════════════════════════════════
    "gr-gsm": {
        "name": "GR-GSM",
        "category": "Wireless/SDR",
        "badge": "wireless",
        "icon": "📻",
        "description": "GNU Radio toolkit for GSM air interface capture and decoding. Works with RTL-SDR, HackRF, BladeRF, and USRP.",
        "inputs": [
            {"name": "device", "type": "string", "required": True, "desc": "SDR device: 'rtl', 'hackrf', 'bladerf', 'usrp'"},
            {"name": "arfcn", "type": "integer", "required": False, "desc": "GSM ARFCN to monitor (auto-scan if omitted)"},
            {"name": "band", "type": "string", "required": False, "desc": "GSM band: 'GSM900', 'DCS1800', 'PCS1900'"},
        ],
        "outputs": "Decoded BCCH, CCCH, SDCCH frames; system info; ciphering mode",
        "example": "grgsm_livemon --device hackrf --arfcn 1\n# Captures GSM900 ARFCN 1 (935.2 MHz downlink)",
        "coverage": ["2G"],
        "use_cases": [
            "Capture broadcast channel for cell tower fingerprinting",
            "Monitor ciphering mode commands to detect A5/0 usage",
            "Decode IMSI catchers broadcasting fake BCCH"
        ],
        "docs_url": "https://github.com/ptrkrysik/gr-gsm"
    },
    
    "kalibrate": {
        "name": "Kalibrate-RTL",
        "category": "Wireless/SDR",
        "badge": "wireless",
        "icon": "📡",
        "description": "GSM channel scanner and frequency correction tool. Quickly identifies active GSM carriers and measures frequency offset.",
        "inputs": [
            {"name": "band", "type": "string", "required": True, "desc": "Band to scan: 'gsm850', 'gsm900', 'dcs1800', 'pcs1900'"},
            {"name": "gain", "type": "integer", "required": False, "desc": "LNA gain (0-50, default: auto)"},
        ],
        "outputs": "List of detected ARFCNs with signal strength and frequency offset",
        "example": "kal -b gsm900 -g 40\n# Scans GSM900 band with gain 40",
        "coverage": ["2G"],
        "use_cases": [
            "Quick survey of local GSM spectrum",
            "Identify strongest cells for targeted monitoring",
            "Calibrate SDR frequency accuracy"
        ],
        "docs_url": "https://github.com/steve-m/kalibrate-rtl"
    },
    
    "osmocom": {
        "name": "OsmocomBB",
        "category": "Wireless/SDR",
        "badge": "wireless",
        "icon": "📱",
        "description": "Free baseband firmware for GSM phones. Turns compatible handsets into programmable MS for active testing.",
        "inputs": [
            {"name": "phone_model", "type": "string", "required": True, "desc": "Supported phone: 'calypso', 'compalo', 'kirin'"},
            {"name": "arfcn", "type": "integer", "required": True, "desc": "Target ARFCN to camp on"},
            {"name": "action", "type": "string", "required": True, "desc": "Action: 'scan', 'camp', 'sms_send', 'call'"},
        ],
        "outputs": "Layer 1/2/3 logs, SMS delivery confirmation, call status",
        "example": "layer23 --arfcn 1 --sms-send +919999999999\n# Sends SMS from modified phone firmware",
        "coverage": ["2G"],
        "use_cases": [
            "Active IMSI catching with modified handset",
            "Send/receive SMS without SIM for testing",
            "Research GSM protocol stack implementation bugs"
        ],
        "docs_url": "https://bb.osmocom.org/"
    },
    
    "aircrack": {
        "name": "Aircrack-ng",
        "category": "Wireless/SDR",
        "badge": "wireless",
        "icon": "🔑",
        "description": "WiFi security auditing suite. Included for completeness when testing WiFi calling, VoWiFi, or converged networks.",
        "inputs": [
            {"name": "pcap_file", "type": "file", "required": True, "desc": "PCAP containing WPA handshake"},
            {"name": "wordlist", "type": "file", "required": True, "desc": "Password wordlist (e.g., rockyou.txt)"},
            {"name": "essid", "type": "string", "required": False, "desc": "Target network ESSID (if multiple in PCAP)"},
        ],
        "outputs": "Recovered WPA key or failure message with attempts count",
        "example": "aircrack-ng -w rockyou.txt -e \"WiFi Calling\" capture.pcap\n# Cracks WiFi calling hotspot",
        "coverage": ["WiFi", "VoWiFi"],
        "use_cases": [
            "Test WiFi calling security in converged networks",
            "Audit enterprise WiFi protecting IMS access",
            "Demonstrate weak PSK risks for IoT devices"
        ],
        "docs_url": "https://www.aircrack-ng.org/"
    },
    
    # ═══════════════════════════════════════════════════════════════════════
    # TRAFFIC CAPTURE & ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════
    "tshark": {
        "name": "TShark",
        "category": "Traffic Capture",
        "badge": "analysis",
        "icon": "🎣",
        "description": "Command-line Wireshark for live packet capture. Supports all telecom protocols with proper dissectors.",
        "inputs": [
            {"name": "interface", "type": "string", "required": True, "desc": "Network interface (e.g., 'eth0', 'any')"},
            {"name": "duration", "type": "integer", "required": False, "desc": "Capture duration in seconds (default: 10)"},
            {"name": "filter", "type": "string", "required": False, "desc": "BPF capture filter (e.g., 'port 3868' for Diameter)"},
            {"name": "display_filter", "type": "string", "required": False, "desc": "Wireshark display filter for post-processing"},
        ],
        "outputs": "PCAP data or decoded packet summary in CLI",
        "example": "tshark -i eth0 -f 'port 2905' -Y 'm3ua' -c 100\n# Captures 100 M3UA packets",
        "coverage": ["2G", "3G", "4G", "5G", "IP"],
        "use_cases": [
            "Capture live SS7-over-IP for offline analysis",
            "Monitor Diameter S6a interface during testing",
            "Record GTP-C signaling for replay attacks"
        ],
        "docs_url": "https://www.wireshark.org/docs/man-pages/tshark.html"
    },
    
    "tshark-pcap": {
        "name": "TShark (PCAP Analysis)",
        "category": "Traffic Analysis",
        "badge": "analysis",
        "icon": "📂",
        "description": "Offline PCAP analysis mode. Upload PCAP files for deep protocol dissection without live capture.",
        "inputs": [
            {"name": "pcap_b64", "type": "file", "required": True, "desc": "PCAP file (base64 encoded for upload)"},
            {"name": "filter", "type": "string", "required": False, "desc": "Display filter (e.g., 'map', 'diameter', 'gtp')"},
            {"name": "export_format", "type": "string", "required": False, "desc": "Output: 'text', 'json', 'pcap_filtered'"},
        ],
        "outputs": "Filtered PCAP, JSON export of protocol fields, or text summary",
        "example": "tshark -r capture.pcap -Y 'diameter.cmd.code == 318'\n# Filters for Diameter IDR messages",
        "coverage": ["2G", "3G", "4G", "5G"],
        "use_cases": [
            "Analyze captured roaming traffic for violations",
            "Extract specific MAP operations from large PCAPs",
            "Convert legacy PCAP formats for modern tools"
        ],
        "docs_url": "https://www.wireshark.org/"
    },
    
    # ═══════════════════════════════════════════════════════════════════════
    # EXPLOITATION & BRUTE FORCE
    # ═══════════════════════════════════════════════════════════════════════
    "metasploit": {
        "name": "Metasploit Framework",
        "category": "Exploitation",
        "badge": "exploit",
        "icon": "💥",
        "description": "Modular penetration testing framework with telecom modules. Includes auxiliary scanners for SIP, SS7 gateways, and Diameter.",
        "inputs": [
            {"name": "module", "type": "string", "required": True, "desc": "Module path (e.g., 'auxiliary/scanner/voip/sip_enum')"},
            {"name": "options", "type": "object", "required": True, "desc": "Module options dict: {'RHOSTS': '192.168.1.0/24', ...}"},
        ],
        "outputs": "Exploit success, shells gained, credentials found, scan results",
        "example": "use auxiliary/scanner/voip/sip_enum\nset RHOSTS 192.168.1.0/24\nrun",
        "coverage": ["VoIP", "SIP", "General IT"],
        "use_cases": [
            "Enumerate SIP extensions on IMS CSCF",
            "Scan for exposed management interfaces on EPC",
            "Exploit known CVEs in telecom infrastructure"
        ],
        "docs_url": "https://www.metasploitunleashed.com/"
    },
    
    "hydra": {
        "name": "Hydra",
        "category": "Brute Force",
        "badge": "exploit",
        "icon": "🔨",
        "description": "Fast online brute-force cracker supporting 50+ protocols including SSH, HTTP, SIP, and FTP.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "Target IP or hostname"},
            {"name": "service", "type": "string", "required": True, "desc": "Protocol: 'ssh', 'http-get', 'sip', 'ftp', etc."},
            {"name": "username", "type": "string", "required": False, "desc": "Single username or file with '-L'"},
            {"name": "wordlist", "type": "file", "required": True, "desc": "Password wordlist path"},
        ],
        "outputs": "Valid credential pairs or exhaustion message",
        "example": "hydra -l admin -P rockyou.txt ssh://192.168.1.10\n# Brute-forces SSH admin account",
        "coverage": ["IP", "SIP", "Management"],
        "use_cases": [
            "Test SSH credentials on eNodeB/gNB management ports",
            "Brute-force SIP registrar for toll fraud",
            "Audit HTTP basic auth on OSS interfaces"
        ],
        "docs_url": "https://github.com/vanhauser-thc/thc-hydra"
    },
    
    "nuclei": {
        "name": "Nuclei",
        "category": "Vulnerability Scanning",
        "badge": "recon",
        "icon": "☢️",
        "description": "Template-based vulnerability scanner with community templates for CVEs, misconfigurations, and telecom-specific checks.",
        "inputs": [
            {"name": "target", "type": "string", "required": True, "desc": "URL, IP, or CIDR to scan"},
            {"name": "templates", "type": "string", "required": False, "desc": "Template filter (e.g., 'cves/2023', 'telecom', 'exposures')"},
            {"name": "severity", "type": "string", "required": False, "desc": "Minimum severity: 'critical', 'high', 'medium', 'low'"},
        ],
        "outputs": "Matched vulnerabilities with CVSS scores and remediation",
        "example": "nuclei -u https://operator.com -t cves/2023 -s critical\n# Scans for 2023 critical CVEs",
        "coverage": ["HTTP", "API", "Infrastructure"],
        "use_cases": [
            "Scan OSS/BSS web portals for known CVEs",
            "Detect exposed OpenAPI specs on 5G SBA APIs",
            "Find misconfigured CORS or authentication bypasses"
        ],
        "docs_url": "https://nuclei.projectdiscovery.io/"
    },
    
    # ═══════════════════════════════════════════════════════════════════════
    # AI & ANOMALY DETECTION
    # ═══════════════════════════════════════════════════════════════════════
    "lucid": {
        "name": "LUCID",
        "category": "AI Detection",
        "badge": "analysis",
        "icon": "🤖",
        "description": "CNN-based DDoS and anomaly classifier for telecom networks. Trained on signaling traffic patterns to detect attacks in real-time.",
        "inputs": [
            {"name": "traffic_file", "type": "file", "required": True, "desc": "PCAP or CSV flow data for analysis"},
            {"name": "model", "type": "string", "required": False, "desc": "Model variant: 'ddos', 'anomaly', 'intrusion' (default: 'ddos')"},
        ],
        "outputs": "Classification results with confidence scores, attack type identification",
        "example": "lucid --input signaling_flows.csv --model ddos\n# Classifies DDoS vs normal traffic",
        "coverage": ["4G", "5G", "IP"],
        "use_cases": [
            "Detect signaling storms indicative of DDoS",
            "Identify anomalous MAP/Diameter patterns",
            "Train custom models on operator-specific traffic"
        ],
        "docs_url": "https://github.com/minerva-labs/LUCID"
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Filter & Sort Logic
# ─────────────────────────────────────────────────────────────────────────────
filtered_tools = {}
for tool_id, tool_data in TOOL_CATALOG.items():
    # Search filter
    if search_query:
        query_lower = search_query.lower()
        searchable = (
            f"{tool_data['name']} {tool_data['category']} "
            f"{' '.join(tool_data['coverage'])} {tool_data['description']}"
        ).lower()
        if query_lower not in searchable:
            continue
    filtered_tools[tool_id] = tool_data

# Sort
if sort_option == "Name (A-Z)":
    filtered_tools = dict(sorted(filtered_tools.items(), key=lambda x: x[1]['name']))
elif sort_option == "Name (Z-A)":
    filtered_tools = dict(sorted(filtered_tools.items(), key=lambda x: x[1]['name'], reverse=True))
# Default: Category order (as defined)

# ─────────────────────────────────────────────────────────────────────────────
# Group by Category
# ─────────────────────────────────────────────────────────────────────────────
categories = {}
for tool_id, tool_data in filtered_tools.items():
    cat = tool_data['category']
    if cat not in categories:
        categories[cat] = []
    categories[cat].append((tool_id, tool_data))

# ─────────────────────────────────────────────────────────────────────────────
# Render Tabs by Category
# ─────────────────────────────────────────────────────────────────────────────
if not categories:
    st.warning(f"No tools found matching '{search_query}'. Try a different search term.")
else:
    category_names = sorted(categories.keys())
    tabs = st.tabs(category_names)
    
    for tab, category_name in zip(tabs, category_names):
        with tab:
            tools_in_cat = categories[category_name]
            
            # Category description
            cat_descriptions = {
                "Reconnaissance": "Network discovery, port scanning, DNS enumeration, and infrastructure mapping tools.",
                "Telecom Exploitation": "SS7, Diameter, and GTP attack tools implementing GSMA FS.11 scenarios.",
                "Telecom Reconnaissance": "Specialized tools for mapping SS7/Diameter networks and enumerating signaling endpoints.",
                "5G Security": "5G NAS testing, SUCI/SUPI analysis, and 3GPP TS 33.501 compliance auditors.",
                "5G Testing": "NGAP/GTP replay, UERANSIM integration, and 5G core interface testing.",
                "5G Analysis": "NAS message analyzers, device log parsers, and real-time monitoring tools.",
                "Wireless/SDR": "GSM air interface capture, SDR tools, and baseband manipulation frameworks.",
                "Traffic Capture": "Live packet capture and protocol dissection tools.",
                "Traffic Analysis": "Offline PCAP analysis, violation detection, and compliance reporting.",
                "Exploitation": "General-purpose exploitation frameworks with telecom modules.",
                "Brute Force": "Credential cracking and authentication testing tools.",
                "Vulnerability Scanning": "Template-based CVE scanners and misconfiguration detectors.",
                "Firewall Testing": "Signaling firewall evaluation and honeypot deployment tools.",
                "AI Detection": "Machine learning-based anomaly and DDoS detection systems.",
                "VoIP/SIP": "SIP enumeration, extension discovery, and VoLTE testing tools.",
            }
            
            st.markdown(f"*{cat_descriptions.get(category_name, 'Tools for ' + category_name)}*")
            st.markdown("---")
            
            for tool_id, tool_data in tools_in_cat:
                badge_class = f"badge-{tool_data['badge']}"
                
                st.markdown(f"""
                <div class="tool-card">
                  <div class="tool-header">
                    <div class="tool-name">
                      {tool_data['icon']} {tool_data['name']}
                      <span class="tool-badge {badge_class}">{tool_data['category']}</span>
                    </div>
                  </div>
                  <div class="tool-desc">{tool_data['description']}</div>
                  
                  <div class="io-section">
                    <div class="io-title">📥 Required Inputs</div>
                """, unsafe_allow_html=True)
                
                for param in tool_data['inputs']:
                    req_badge = '<span class="param-required">*</span>' if param['required'] else ''
                    st.markdown(f"""
                    <div class="param-row">
                      <span class="param-name">{param['name']}</span>
                      <span class="param-type">({param['type']})</span>
                      {req_badge}
                      <span class="param-desc">— {param['desc']}</span>
                    </div>
                    """)
                
                st.markdown(f"""
                  </div>
                  
                  <div class="io-section">
                    <div class="io-title">📤 Expected Output</div>
                    <div style="font-size:0.82rem;color:#cbd5e1;line-height:1.6;">
                      {tool_data['outputs']}
                    </div>
                  </div>
                  
                  <div class="example-box">
                    <div class="example-title">💡 Example Usage</div>
                    <div class="example-code">{tool_data['example']}</div>
                  </div>
                  
                  <div class="coverage-tags">
                """, unsafe_allow_html=True)
                
                for cov in tool_data['coverage']:
                    st.markdown(f'<span class="cov-tag">{cov}</span>', unsafe_allow_html=True)
                
                st.markdown("</div></div>", unsafe_allow_html=True)
                
                # Use cases expander
                with st.expander(f"🎯 Typical Use Cases for {tool_data['name']}", expanded=False):
                    for i, use_case in enumerate(tool_data['use_cases'], 1):
                        st.markdown(f"{i}. {use_case}")
                    
                    if tool_data.get('docs_url'):
                        st.markdown(f"\n📖 **Documentation:** [{tool_data['docs_url']}]({tool_data['docs_url']})")
                
                st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Footer Summary
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("---")
c1, c2, c3 = st.columns(3)
with c1:
    st.metric("Total Tools Documented", len(TOOL_CATALOG))
with c2:
    st.metric("Categories Covered", len(categories))
with c3:
    protocols = set()
    for t in TOOL_CATALOG.values():
        protocols.update(t['coverage'])
    st.metric("Protocols/Generations", len(protocols))

st.markdown("""
<div style="text-align:center;padding:20px;font-size:0.82rem;color:#64748b;">
  <strong>💡 Tip:</strong> Use the search box to quickly find tools by protocol (e.g., "SS7", "Diameter"), 
  capability (e.g., "scanner", "fuzzer"), or generation (e.g., "5G", "LTE").
</div>
""", unsafe_allow_html=True)
