"""
Digital Forensics Chain of Custody & Evidence Ledger
Maintains tamper-evident legal records of evidence acquisition, custodial transfers, and forensic integrity.
"""

import json
from pathlib import Path
from datetime import datetime
from forensic_toolkit.utils import log, PROJECT_ROOT
from forensic_toolkit.hashing import calculate_sha256, calculate_md5

COC_FILE = PROJECT_ROOT / "Hashes" / "chain_of_custody.json"


def load_chain_of_custody() -> dict:
    """Load or initialize the Chain of Custody ledger."""
    if COC_FILE.exists():
        try:
            return json.loads(COC_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Initialize default case ledger
    default_ledger = {
        "case_number": "CASE-2026-DFIR-001",
        "case_name": "Finance Server Unauthorized Data Exfiltration Investigation",
        "investigating_agency": "Cyber Forensics & Incident Response Unit",
        "lead_investigator": "Forensic Investigator / SOC Analyst",
        "date_opened": "2026-07-07 14:30:00",
        "evidence_items": [],
        "custody_transfers": [
            {
                "timestamp": "2026-07-07 14:35:00",
                "released_by": "SOC Gateway Monitor",
                "received_by": "Forensic Response Team",
                "purpose": "Evidence acquisition and volatile log preservation",
                "notes": "Firewall, VPN, and server syslog files captured from SRV-FIN-01 and VPN Gateway"
            }
        ]
    }
    save_chain_of_custody(default_ledger)
    return default_ledger


def save_chain_of_custody(data: dict):
    """Persist the Chain of Custody ledger to disk."""
    COC_FILE.parent.mkdir(parents=True, exist_ok=True)
    COC_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def sync_evidence_items(evidence_dir: Path = None) -> dict:
    """
    Ensure all files in Evidence/ are recorded in the Chain of Custody ledger
    with cryptographic hashes and custody status.
    """
    if evidence_dir is None:
        evidence_dir = PROJECT_ROOT / "Evidence"

    ledger = load_chain_of_custody()
    existing_items = {item["filename"]: item for item in ledger.get("evidence_items", [])}

    updated_items = []
    item_counter = 1

    for fpath in sorted(evidence_dir.glob("*")):
        if fpath.is_file():
            sha256 = calculate_sha256(fpath)
            md5 = calculate_md5(fpath)
            size = fpath.stat().st_size

            if fpath.name in existing_items:
                item = existing_items[fpath.name]
                # Check integrity against baseline
                baseline = item.get("baseline_sha256", sha256)
                item["current_sha256"] = sha256
                item["integrity_status"] = "VERIFIED" if sha256 == baseline else "TAMPERED"
                item["current_md5"] = md5
                item["size_bytes"] = size
                updated_items.append(item)
            else:
                # New evidence item
                item_id = f"EV-{item_counter:03d}"
                item_counter += 1
                updated_items.append({
                    "evidence_id": item_id,
                    "filename": fpath.name,
                    "description": get_evidence_description(fpath.name),
                    "source_device": "SRV-FIN-01 / VPN Gateway",
                    "acquired_by": ledger.get("lead_investigator", "DFIR Analyst"),
                    "acquisition_time": datetime.fromtimestamp(fpath.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    "baseline_sha256": sha256,
                    "current_sha256": sha256,
                    "baseline_md5": md5,
                    "current_md5": md5,
                    "size_bytes": size,
                    "storage_location": str(fpath.parent),
                    "integrity_status": "VERIFIED"
                })

    ledger["evidence_items"] = updated_items
    ledger["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_chain_of_custody(ledger)
    return ledger


def record_custody_transfer(released_by: str, received_by: str, purpose: str, notes: str = "") -> dict:
    """Record an official custody transfer entry in the ledger."""
    ledger = load_chain_of_custody()
    ledger["custody_transfers"].append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "released_by": released_by,
        "received_by": received_by,
        "purpose": purpose,
        "notes": notes
    })
    save_chain_of_custody(ledger)
    log(f"Custody Transfer Recorded: {released_by} -> {received_by} ({purpose})")
    return ledger


def get_evidence_description(filename: str) -> str:
    """Heuristic description based on evidence file type."""
    descriptions = {
        "firewall.log": "Perimeter network packet filter access logs with stateful rule triggers.",
        "system.log": "Linux/Unix operating system authentication and daemon activity log (syslog).",
        "vpn.log": "Corporate VPN gateway remote authentication session logs.",
        "email_thread.txt": "Internal security operations center escalation communications.",
        "incident_report.txt": "Preliminary SOC security alert and triage notes.",
        "ransomware_note.txt": "Extortion / ransom communication artifact recovered during triage.",
        "phishing_email.txt": "Suspicious email lure with deceptive credential harvesting hook.",
        "invoice.txt": "Fictional invoice training document.",
        "meeting_minutes.txt": "Incident response coordination meeting minutes."
    }
    return descriptions.get(filename, "Digital evidence file recovered for forensic triage.")

