"""Unified Telecom Security Log Analyzer - Parse, correlate and score vulnerabilities across all protocols"""
import re
from datetime import datetime
from collections import defaultdict

class TelecomLogAnalyzer:
    
    # CVE severity weights
    CVE_DB = {
        "CVE-2014-7973": {"cvss": 9.8, "protocol": "SS7", "vuln": "SS7 Location Tracking", "cwe": "CWE-306"},
        "CVE-2016-9693": {"cvss": 8.1, "protocol": "SS7", "vuln": "SMS Interception via SS7", "cwe": "CWE-287"},
        "CVE-2022-24613": {"cvss": 9.8, "protocol": "Diameter", "vuln": "Diameter S6a Origin-Host Spoofing", "cwe": "CWE-290"},
        "CVE-2019-25101": {"cvss": 9.5, "protocol": "GTP", "vuln": "GTP-C Session Hijacking", "cwe": "CWE-345"},
        "CVE-2018-21265": {"cvss": 6.5, "protocol": "GTP", "vuln": "GTP Reflection DDoS", "cwe": "CWE-400"},
        "CVE-2019-17537": {"cvss": 9.2, "protocol": "5G-NAS", "vuln": "NAS Security Mode Downgrade", "cwe": "CWE-757"},
        "CVE-2020-26559": {"cvss": 6.8, "protocol": "5G-NAS", "vuln": "5G-AKA SQN Exhaustion", "cwe": "CWE-400"},
        "CVE-2021-45080": {"cvss": 7.5, "protocol": "Open5GS", "vuln": "AMF NGAP Handler DoS", "cwe": "CWE-476"},
    }
    
    # Attack pattern signatures
    SIGNATURES = [
        {"pattern": r"SPOOFED|SPOOF", "severity": "CRITICAL", "type": "Identity Spoofing"},
        {"pattern": r"VULNERABLE|VULN", "severity": "CRITICAL", "type": "Confirmed Vulnerability"},
        {"pattern": r"\[ATTACK\]", "severity": "HIGH", "type": "Active Attack"},
        {"pattern": r"HIJACK|hijack", "severity": "CRITICAL", "type": "Session Hijacking"},
        {"pattern": r"NULL INTEGRITY|IA0", "severity": "CRITICAL", "type": "Integrity Bypass"},
        {"pattern": r"NULL.*ENCR|EA0", "severity": "CRITICAL", "type": "Encryption Disabled"},
        {"pattern": r"INTERCEPT|intercept", "severity": "HIGH", "type": "Traffic Interception"},
        {"pattern": r"DDoS|REFLECTION", "severity": "MEDIUM", "type": "Denial of Service"},
        {"pattern": r"SYNC_FAILURE", "severity": "MEDIUM", "type": "Authentication DoS"},
        {"pattern": r"SENSITIVE.*captur|captur.*SENSITIVE", "severity": "HIGH", "type": "Data Exfiltration"},
        {"pattern": r"NESAS.*FAIL|FAIL.*NESAS", "severity": "HIGH", "type": "Compliance Violation"},
        {"pattern": r"Result-Code: 2001", "severity": "INFO", "type": "Successful Auth (Expected)"},
        {"pattern": r"CVE-\d{4}-\d+", "severity": "HIGH", "type": "Known CVE Detected"},
        {"pattern": r"TRAI|DoT.*FAIL", "severity": "HIGH", "type": "India Regulatory Non-compliance"},
        {"pattern": r"Aadhaar|UIDAI", "severity": "CRITICAL", "type": "Critical National Data Exposure"},
        {"pattern": r"Paytm|PhonePe|UPI", "severity": "HIGH", "type": "Financial Data Exposure"},
    ]
    
    @classmethod
    def analyze_log(cls, log_text, protocol=None):
        """Comprehensive analysis of simulation log output"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = log_text.split('\n')
        
        findings = []
        cves_found = []
        severity_counts = defaultdict(int)
        compliance_issues = []
        timeline = []
        
        # Extract timestamp events for timeline
        ts_pattern = re.compile(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (.*)')
        
        for line in lines:
            # Build timeline
            ts_match = ts_pattern.match(line)
            if ts_match:
                timeline.append({
                    "time": ts_match.group(1),
                    "event": ts_match.group(2)[:80]
                })
            
            # Check signatures
            for sig in cls.SIGNATURES:
                if re.search(sig["pattern"], line, re.IGNORECASE):
                    findings.append({
                        "line": line.strip()[:100],
                        "type": sig["type"],
                        "severity": sig["severity"]
                    })
                    severity_counts[sig["severity"]] += 1
            
            # Extract CVEs
            cve_matches = re.findall(r'CVE-\d{4}-\d+', line)
            cves_found.extend(cve_matches)
            
            # Compliance checks
            if re.search(r'NESAS.*FAIL', line):
                compliance_issues.append("NESAS Phase-2: FAIL")
            if re.search(r'DoT.*Non-compliant|Non-compliant.*DoT', line, re.IGNORECASE):
                compliance_issues.append("DoT Security Audit: Non-compliant")
            if re.search(r'TRAI.*Violation|Violation.*TRAI', line, re.IGNORECASE):
                compliance_issues.append("TRAI Regulation: Violation")
        
        # Deduplicate
        cves_found = list(set(cves_found))
        compliance_issues = list(set(compliance_issues))
        
        # Calculate overall risk score
        max_cvss = 0
        for cve in cves_found:
            if cve in cls.CVE_DB:
                max_cvss = max(max_cvss, cls.CVE_DB[cve]["cvss"])
        
        if max_cvss == 0:
            max_cvss = 5.0 if severity_counts["HIGH"] > 0 else 3.0
        
        # Risk level mapping
        if max_cvss >= 9.0:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif max_cvss >= 7.0:
            risk_level = "HIGH"
            risk_color = "orange"
        elif max_cvss >= 4.0:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        else:
            risk_level = "LOW"
            risk_color = "green"
        
        # Build detailed CVE report
        cve_details = []
        for cve in cves_found:
            if cve in cls.CVE_DB:
                cve_details.append(cls.CVE_DB[cve])
        
        # Generate analysis report
        report = {
            "analysis_timestamp": timestamp,
            "protocol": protocol or "Auto-detected",
            "total_lines": len(lines),
            "timeline_events": len(timeline),
            "findings_count": len(findings),
            "severity_breakdown": dict(severity_counts),
            "risk_score": max_cvss,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "cves_detected": cves_found,
            "cve_details": cve_details,
            "compliance_issues": compliance_issues,
            "top_findings": findings[:10],
            "timeline_sample": timeline[:20],
            "summary": cls._generate_summary(
                max_cvss, risk_level, cves_found,
                severity_counts, compliance_issues, protocol
            )
        }
        
        return report
    
    @classmethod
    def _generate_summary(cls, cvss, risk, cves, severity_counts, compliance, protocol):
        """Generate human-readable executive summary"""
        summary_lines = [
            f"=== TELECOM SECURITY ANALYSIS REPORT ===",
            f"Protocol: {protocol or 'Multi-protocol'}",
            f"Overall Risk: {risk} (CVSS: {cvss})",
            "",
            "=== KEY FINDINGS ===",
        ]
        
        if severity_counts.get("CRITICAL", 0) > 0:
            summary_lines.append(f"[CRITICAL] {severity_counts['CRITICAL']} critical security issues detected")
        if severity_counts.get("HIGH", 0) > 0:
            summary_lines.append(f"[HIGH] {severity_counts['HIGH']} high severity findings")
        if severity_counts.get("MEDIUM", 0) > 0:
            summary_lines.append(f"[MEDIUM] {severity_counts['MEDIUM']} medium risk items")
        
        if cves:
            summary_lines.append("")
            summary_lines.append("=== CVEs IDENTIFIED ===")
            for cve in cves:
                if cve in cls.CVE_DB:
                    db = cls.CVE_DB[cve]
                    summary_lines.append(
                        f" {cve}: {db['vuln']} (CVSS: {db['cvss']})"
                    )
        
        if compliance:
            summary_lines.append("")
            summary_lines.append("=== REGULATORY COMPLIANCE ===")
            for issue in compliance:
                summary_lines.append(f" NON-COMPLIANT: {issue}")
        
        summary_lines.extend([
            "",
            "=== INDIA-SPECIFIC RISK ===",
            " Assessment applies to Indian TSPs under DoT/TRAI jurisdiction",
            " NESAS Phase-2 certification may be impacted",
            " Consider reporting to CERT-In as per IT Act Section 70B",
            "",
            "=== DISCLAIMER ===",
            " This is a controlled simulation for authorized security testing",
            " Results are for DoT/TRAI compliance audit purposes only"
        ])
        
        return "\n".join(summary_lines)
    
    @staticmethod
    def correlate_multi_protocol(results_list):
        """Correlate findings from multiple protocol simulators"""
        all_cves = []
        max_cvss = 0
        protocols_affected = []
        total_criticals = 0
        
        for result in results_list:
            if "cvss" in result:
                max_cvss = max(max_cvss, result["cvss"])
            if "cve" in result:
                all_cves.append(result["cve"])
            if "protocol" in result:
                protocols_affected.append(result["protocol"])
            
        # Attack chain analysis
        attack_chains = []
        if "CVE-2014-7973" in all_cves and "CVE-2022-24613" in all_cves:
            attack_chains.append(
                "SS7+Diameter combo: Location tracking + subscriber hijacking"
            )
        if "CVE-2019-25101" in all_cves and "CVE-2019-17537" in all_cves:
            attack_chains.append(
                "GTP+NAS combo: Full MITM from radio to core"
            )
        
        return {
            "correlation_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "protocols_tested": protocols_affected,
            "unique_cves": list(set(all_cves)),
            "max_combined_cvss": max_cvss,
            "attack_chains_detected": attack_chains,
            "total_results_correlated": len(results_list)
        }

if __name__ == "__main__":
    # Test with a sample log
    sample_log = """[2024-01-01 12:00:00] [SS7] Initiating MAP test
    [2024-01-01 12:00:01] [ATTACK] Sending malformed message
    CVE-2014-7973 detected
    NESAS Phase-2: FAIL
    TRAI Violation found
    Result-Code: 2001 (VULNERABLE)
    """
    
    analyzer = TelecomLogAnalyzer()
    report = analyzer.analyze_log(sample_log, "SS7")
    print(report["summary"])
