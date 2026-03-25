"""
TelSec — Offensive Security Toolkit (Page 15)
==============================================
Covers: Nuclei scanner, nmap, Hydra auth brute-force,
        Metasploit module runner, DNS Recon, hping3
"""
import streamlit as st

st.markdown("""
<div class="page-hero">
  <div class="page-hero-icon">⚔️</div>
  <div>
    <div class="page-hero-title">Offensive Security Toolkit</div>
    <div class="page-hero-sub">Nuclei · nmap · Hydra · Metasploit · DNS Recon · hping3 — all via Kali Cloud backend</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Kali connector ────────────────────────────────────────────────────────────
from kali_connector import run_tool, render_tool_result
try:
    from kali_connector import render_kali_status_mini
except ImportError:
    def render_kali_status_mini():
        import streamlit as _st
        with _st.expander("💡 Running in Demo Mode", expanded=False):
            _st.info("Set KALI_API_URL in Streamlit Secrets to enable live tools.")
        return False

render_kali_status_mini()
kali_online = True  # run_tool() handles offline gracefully



try:
    from kali_connector import render_kali_status_banner, run_tool, render_tool_result
    render_kali_status_mini()
except Exception:
    kali_online = False
    st.info("ℹ️ Kali backend not connected — Demo Mode active")

tabs = st.tabs([
    "🔬 Nuclei Scanner",
    "🗂️ nmap",
    "🔑 Hydra Bruteforce",
    "🦠 Metasploit",
    "🌐 DNS Recon",
    "📶 hping3",
])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: NUCLEI
# ─────────────────────────────────────────────────────────────────────────────
with tabs[0]:
    with st.expander("📘 About Nuclei", expanded=False):
        st.markdown("""
**Nuclei** is a fast, template-based vulnerability scanner. It runs thousands of community-maintained
templates against targets to find misconfigurations, CVEs, default credentials, and more.

**Telecom relevance:**
- Scan 5G Core HTTP/2 SBI APIs for default configs and known CVEs
- Check Open5GS WebUI (CVE-2026-0622 hardcoded JWT secret)
- Test NRF/AMF REST endpoints for unauthenticated access

**Template categories:** `cves`, `misconfigs`, `default-logins`, `exposures`, `network`
""")

    st.markdown("### 🔬 Nuclei Vulnerability Scanner")
    col1, col2, col3 = st.columns([3, 2, 1])
    with col1:
        nuclei_target = st.text_input("Target URL / IP", value="http://localhost:9999", key="nuclei_t",
                                       help="Full URL or IP")
    with col2:
        nuclei_tpl = st.selectbox("Template Set", [
            "(all)", "cves", "misconfigs", "default-logins",
            "exposures", "network", "http/default-logins"
        ], key="nuclei_tpl")
    with col3:
        if st.button("▶ Scan", use_container_width=True, key="nuclei_run"):
            with st.spinner("Running Nuclei scan..."):
                tpl = "" if nuclei_tpl == "(all)" else nuclei_tpl
                result = run_tool("nuclei", {"target": nuclei_target, "templates": tpl})
                render_tool_result(result, "Nuclei")

    st.caption("⚠️ Only scan systems you have explicit written authorization to test.")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: NMAP
# ─────────────────────────────────────────────────────────────────────────────
with tabs[1]:
    with st.expander("📘 About nmap", expanded=False):
        st.markdown("""
**nmap** (Network Mapper) is the industry-standard port scanner and service fingerprinter.

**Telecom use cases:**
- Discover open MM7, S1-MME, Gx, Gy, Gz, SBI ports on core nodes
- Detect misconfigured management interfaces (SSH, HTTP) on EPC/5GC
- OS fingerprinting of MSC, HLR, MME, AMF nodes for risk assessment

**Useful flags:**
| Flag | Purpose |
|---|---|
| `-sV` | Version detection |
| `-sU` | UDP scan (find open SCTP-like UDP services) |
| `-p 2905,5060,36412,7777` | Specific telecom ports |
| `-O` | OS detection |
| `--script vuln` | Run NSE vuln scripts |
""")

    st.markdown("### 🗂️ nmap Port Scan")
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        nmap_target = st.text_input("Target IP/Range", value="192.168.1.1", key="nmap_t")
    with col2:
        nmap_flags = st.text_input("Flags", value="-sV -T4 -p 22,80,443,2905,5060,8080,9999",
                                    key="nmap_flags")
    with col3:
        if st.button("▶ Scan", use_container_width=True, key="nmap_run"):
            with st.spinner("Running nmap..."):
                result = run_tool("nmap", {"target": nmap_target, "flags": nmap_flags})
                render_tool_result(result, "nmap")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: HYDRA
# ─────────────────────────────────────────────────────────────────────────────
with tabs[2]:
    with st.expander("📘 About Hydra", expanded=False):
        st.markdown("""
**Hydra** is a fast network authentication brute-forcer supporting 50+ protocols.

**Telecom use cases:**
- Test default credentials on OAM/EMS portals (HTTP, SSH)
- Audit Open5GS WebUI for weak admin passwords
- Test SIP REGISTER auth (use with caution — rate limited)
- Probe Diameter/GTP management interfaces

**Supported services:** ssh, http-get, http-post-form, ftp, smtp, pop3, imap, ldap, sip, rdp
""")

    st.markdown("### 🔑 Hydra Auth Bruteforce")
    col1, col2 = st.columns(2)
    with col1:
        hydra_target = st.text_input("Target IP", value="192.168.1.1", key="hydra_t")
        hydra_user   = st.text_input("Username", value="admin", key="hydra_u")
        hydra_svc    = st.selectbox("Service", ["ssh", "http-get", "ftp", "smtp", "sip", "rdp"], key="hydra_svc")
    with col2:
        hydra_wl = st.selectbox("Wordlist", [
            "fasttrack.txt", "rockyou.txt", "unix_passwords.txt", "password.lst"
        ], key="hydra_wl")
        st.markdown("<div style='height:52px'></div>", unsafe_allow_html=True)
        if st.button("▶ Run Hydra", use_container_width=True, key="hydra_run"):
            with st.spinner("Running Hydra..."):
                result = run_tool("hydra", {
                    "target": hydra_target, "username": hydra_user,
                    "service": hydra_svc, "wordlist": hydra_wl
                })
                render_tool_result(result, "Hydra")

    st.caption("⚠️ Use only against systems you are authorized to test. Account lockout risk.")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4: METASPLOIT
# ─────────────────────────────────────────────────────────────────────────────
with tabs[3]:
    with st.expander("📘 About Metasploit", expanded=False):
        st.markdown("""
**Metasploit** is the world's most widely used penetration testing framework with 2,000+ modules.

**Relevant modules for telecom:**
| Module | Description |
|---|---|
| `auxiliary/scanner/sip/options` | SIP server enumeration |
| `auxiliary/scanner/http/open5gs_scan` | Open5GS endpoint scan |
| `auxiliary/dos/tcp/synflood` | TCP SYN flood (with written auth) |
| `auxiliary/fuzzers/http/http_form_field` | Web form fuzzer |
| `exploit/linux/http/open5gs_webui` | Open5GS WebUI exploit research |

Note: modules run in **info mode only** without a verified RHOST target.
""")

    st.markdown("### 🦠 Metasploit Module")
    col1, col2 = st.columns([3, 1])
    with col1:
        msf_module = st.text_input("Module Path", value="auxiliary/scanner/sip/options", key="msf_mod")
        msf_opts   = st.text_area("Options (KEY=VALUE per line)", value="RHOSTS=192.168.1.0/24\nTHREADS=10",
                                    height=80, key="msf_opts")
    with col2:
        st.markdown("<div style='height:52px'></div>", unsafe_allow_html=True)
        if st.button("▶ Run Module", use_container_width=True, key="msf_run"):
            with st.spinner("Loading Metasploit module..."):
                opts = dict(line.split("=", 1) for line in msf_opts.strip().split("\n") if "=" in line)
                result = run_tool("metasploit", {"module": msf_module, "options": opts})
                render_tool_result(result, "Metasploit")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 5: DNS RECON
# ─────────────────────────────────────────────────────────────────────────────
with tabs[4]:
    with st.expander("📘 About dnsrecon", expanded=False):
        st.markdown("""
**dnsrecon** performs comprehensive DNS reconnaissance including:
- Standard record enumeration (A, MX, NS, TXT, SOA)
- Zone transfer attempts (AXFR)
- Reverse DNS lookup
- Google and Bing dorking for subdomains
- SRV record enumeration (critical for SIP/IMS — finds `_sip._udp`, `_sips._tcp`)

**Telecom DNS of interest:**
- `_sip._udp.mno.com` → IMS SIP entry point
- `_diameter._sctp.mno.com` → Diameter realm
- `_3gpp-gba-bsf._tcp.mno.com` → BSF/GBA end point
- NAPTR/SRV records for roaming hub resolution
""")

    st.markdown("### 🌐 DNS Reconnaissance")
    col1, col2, col3 = st.columns([3, 2, 1])
    with col1:
        dns_domain = st.text_input("Domain", value="example.com", key="dns_d")
    with col2:
        dns_type = st.multiselect("Record Types", ["std", "axfr", "rvl", "srv", "google"],
                                   default=["std", "srv"], key="dns_t")
    with col3:
        if st.button("▶ Recon", use_container_width=True, key="dns_run"):
            with st.spinner("Running dnsrecon..."):
                result = run_tool("dnsrecon", {"domain": dns_domain, "types": ",".join(dns_type)})
                render_tool_result(result, "dnsrecon")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 6: hping3
# ─────────────────────────────────────────────────────────────────────────────
with tabs[5]:
    with st.expander("📘 About hping3", expanded=False):
        st.markdown("""
**hping3** is an advanced TCP/IP packet assembler and analyser. Beyond ping, it can:
- Send custom TCP/UDP/ICMP/RAW packets
- Perform TCP port scanning and OS fingerprinting
- Measure network path latency with timestamp options
- Test firewall rules and packet filtering
- **Telecom use:** verify SS7/GTP firewall behavior by probing SCTP ports (hping3 has SCTP support)
""")

    st.markdown("### 📶 hping3 Custom Packet")
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        hp_target = st.text_input("Target IP", value="192.168.1.1", key="hp_t")
    with col2:
        hp_flags  = st.text_input("hping3 Flags", value="-S -p 80 -c 5", key="hp_f",
                                   help="-S=SYN -U=UDP -p=port -c=count --flood etc.")
    with col3:
        if st.button("▶ Run", use_container_width=True, key="hp_run"):
            with st.spinner("Running hping3..."):
                result = run_tool("hping3", {"target": hp_target, "flags": hp_flags})
                render_tool_result(result, "hping3")

    st.caption("⚠️ hping3 with --flood may impact target availability. Use only on authorized lab targets.")
