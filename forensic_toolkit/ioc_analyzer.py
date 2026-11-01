"""
Indicators of Compromise (IOC) & Threat Intelligence Analyzer
Automates forensic IOC extraction, threat scoring, and MITRE ATT&CK matrix alignment.
"""

import re
import json
from pathlib import Path
from datetime import datetime
from forensic_toolkit.utils import log, PROJECT_ROOT
from forensic_toolkit.live_forensics import is_private_ip

# Regex patterns for IOC discovery
IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Threat Intelligence Database for the Case
KNOWN_THREAT_INTEL = {
    "198.51.100.20": {
        "type": "IPv4",
        "threat_level": "MALICIOUS",
        "role": "External C2 & Exfiltration Destination",
        "description": "Receives stolen corporate database archive (archive.zip 45.2 MB) via HTTPS curl upload.",
        "mitre_technique": "T1048.002 - Exfiltration Over Alternative Protocol"
    },
    "203.45.18.101": {
        "type": "IPv4",
        "threat_level": "MALICIOUS",
        "role": "Attacker Source / VPN Brute Force",
        "description": "Origin of 5 consecutive failed logins followed by compromised VPN session for user 'j.smith'.",
        "mitre_technique": "T1110.001 - Brute Force: Password Spraying"
    },
    "45.33.18.7": {
        "type": "IPv4",
        "threat_level": "SUSPICIOUS",
        "role": "Secondary C2 / Lateral Movement Target",
        "description": "Target of denied outbound SSH connection attempt from SRV-FIN-01.",
        "mitre_technique": "T1021.004 - Remote Services: SSH"
    },
    "198.51.100.5": {
        "type": "IPv4",
        "threat_level": "SUSPICIOUS",
        "role": "Password Spraying Probe",
        "description": "Reconnaissance login attempts for admin, administrator, root.",
        "mitre_technique": "T1110.001 - Brute Force"
    },
    "10.10.15.25": {
        "type": "IPv4",
        "threat_level": "COMPROMISED_HOST",
        "role": "Finance Server (SRV-FIN-01)",
        "description": "Internal server compromised via SSH session; database dumped and exfiltrated.",
        "mitre_technique": "T1078 - Valid Accounts"
    },
    "10.10.1.5": {
        "type": "IPv4",
        "threat_level": "COMPROMISED_TUNNEL",
        "role": "VPN Assigned Tunnel IP",
        "description": "Internal VPN tunnel address assigned to attacker masquerading as j.smith.",
        "mitre_technique": "T1133 - External Remote Services"
    }
}

# MITRE ATT&CK Matrix Mapping for this Incident
MITRE_ATTACK_MAPPING = [
    {
        "tactic": "Initial Access",
        "technique_id": "T1078.002",
        "technique_name": "Valid Accounts: Domain Accounts",
        "description": "Attacker gained entry using authenticated credentials for user 'j.smith' across the corporate VPN.",
        "confidence": "High",
        "evidence_source": "vpn.log & incident_report.txt"
    },
    {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Spraying",
        "description": "Five failed authentication attempts recorded from IP 203.45.18.101 within 2 minutes preceding successful login.",
        "confidence": "High",
        "evidence_source": "vpn.log"
    },
    {
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "description": "Attacker traversed from VPN gateway (10.10.1.5) to Finance Server SRV-FIN-01 (10.10.15.25) over SSH.",
        "confidence": "High",
        "evidence_source": "system.log & firewall.log"
    },
    {
        "tactic": "Execution",
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "description": "Execution of finance_export.sh via bash session to query PostgreSQL database.",
        "confidence": "High",
        "evidence_source": "system.log"
    },
    {
        "tactic": "Collection",
        "technique_id": "T1560.001",
        "technique_name": "Archive Collected Data: Archive via Utility",
        "description": "Compression of billing details and transactions into archive.zip (45.2 MB) using zip utility.",
        "confidence": "High",
        "evidence_source": "system.log"
    },
    {
        "tactic": "Exfiltration",
        "technique_id": "T1048.002",
        "technique_name": "Exfiltration Over Alternative Protocol: Symmetric Encrypted Non-C2 Protocol",
        "description": "Stolen database archive transmitted to external IP 198.51.100.20 via HTTPS curl upload.",
        "confidence": "High",
        "evidence_source": "system.log & firewall.log"
    },
    {
        "tactic": "Command and Control",
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port / Outbound C2",
        "description": "Attempted outbound connection to 45.33.18.7:22 blocked by network firewall.",
        "confidence": "Medium",
        "evidence_source": "firewall.log & system.log"
    }
]


def extract_iocs_from_text(text: str) -> dict:
    """Extract and correlate all Indicators of Compromise from raw text."""
    raw_ips = set(IPV4_REGEX.findall(text))
    raw_domains = set(DOMAIN_REGEX.findall(text))
    raw_urls = set(URL_REGEX.findall(text))
    raw_emails = set(EMAIL_REGEX.findall(text))
    raw_sha256 = set(SHA256_REGEX.findall(text))
    raw_md5 = set(MD5_REGEX.findall(text))
    raw_cves = set(CVE_REGEX.findall(text))

    # Filter out noisy or false positive domains/extensions
    filtered_domains = set()
    ignored_suffixes = (".txt", ".log", ".sh", ".zip", ".py", ".md", ".json", ".csv", ".local", ".png", ".jpg")
    for d in raw_domains:
        d_lower = d.lower()
        if not any(d_lower.endswith(sfx) for sfx in ignored_suffixes) and not IPV4_REGEX.match(d):
            filtered_domains.add(d)

    # Classify IP Addresses
    ip_records = []
    for ip in sorted(raw_ips):
        intel = KNOWN_THREAT_INTEL.get(ip, None)
        is_priv = is_private_ip(ip)

        if intel:
            threat = intel["threat_level"]
            role = intel["role"]
            desc = intel["description"]
        elif is_priv:
            threat = "INTERNAL"
            role = "Internal LAN / Private Network"
            desc = "RFC1918 Private Address"
        else:
            threat = "EXTERNAL_UNVERIFIED"
            role = "External Public IP"
            desc = "Routable Internet Address"

        ip_records.append({
            "ip": ip,
            "threat_level": threat,
            "is_private": is_priv,
            "role": role,
            "description": desc
        })

    # Sort IPs: Malicious first, then suspicious, then others
    threat_order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "COMPROMISED_HOST": 2, "COMPROMISED_TUNNEL": 3, "EXTERNAL_UNVERIFIED": 4, "INTERNAL": 5}
    ip_records.sort(key=lambda x: threat_order.get(x["threat_level"], 99))

    return {
        "ip_addresses": ip_records,
        "domains": sorted(list(filtered_domains)),
        "urls": sorted(list(raw_urls)),
        "email_addresses": sorted(list(raw_emails)),
        "sha256_hashes": sorted(list(raw_sha256)),
        "md5_hashes": sorted(list(raw_md5)),
        "cves": sorted(list(raw_cves))
    }


def scan_evidence_directory(evidence_dir: Path = None) -> dict:
    """Scan all files in Evidence/ and aggregate comprehensive threat intelligence."""
    if evidence_dir is None:
        evidence_dir = PROJECT_ROOT / "Evidence"

    aggregated_text = ""
    file_summaries = []

    for fpath in sorted(evidence_dir.glob("*")):
        if fpath.is_file():
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                aggregated_text += f"\n--- {fpath.name} ---\n" + content
                file_summaries.append({
                    "filename": fpath.name,
                    "size_bytes": fpath.stat().st_size
                })
            except Exception:
                pass

    iocs = extract_iocs_from_text(aggregated_text)

    # Count high-priority indicators
    malicious_ips = [i for i in iocs["ip_addresses"] if i["threat_level"] in ("MALICIOUS", "SUSPICIOUS")]

    return {
        "scanned_files_count": len(file_summaries),
        "total_unique_ips": len(iocs["ip_addresses"]),
        "malicious_ip_count": len(malicious_ips),
        "iocs": iocs,
        "mitre_attack": MITRE_ATTACK_MAPPING
    }

