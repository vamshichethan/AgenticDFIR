#!/usr/bin/env python3

"""
AI Cyber Forensics & Incident Response Platform
Version : 2.0
Author  : CSRL Workshop & DFIR Engineering

Main Interactive CLI Console
"""

import os
import sys
import subprocess
from pathlib import Path

# Ensure root importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from forensic_toolkit.system_info import system_information
from forensic_toolkit.ollama_info import ollama_information, get_ollama_path
from forensic_toolkit.artifacts import collect_artifacts
from forensic_toolkit.hashing import hash_menu
from forensic_toolkit.process_info import process_information
from forensic_toolkit.timeline import create_timeline
from forensic_toolkit.report import generate_report
from forensic_toolkit.ioc_analyzer import scan_evidence_directory
from forensic_toolkit.chain_of_custody import load_chain_of_custody


def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def banner():
    clear()
    print("=" * 70)
    print("      🛡️  AI CYBER FORENSIC & INCIDENT RESPONSE PLATFORM v2.0")
    print("          Offline AI-Assisted DFIR Toolkit & Security Suite")
    print("=" * 70)
    print(" 1. Live System Diagnostics & Hardware Profiling")
    print(" 2. Live Process Forensics & Anomaly Triage")
    print(" 3. Forensic Artifact & Persistence Discovery")
    print(" 4. Cryptographic Hashing & Evidence Integrity (SHA-256 / MD5 / Entropy)")
    print(" 5. Chronological Master Super-Timeline & Kill Chain Correlation")
    print(" 6. Indicators of Compromise (IOC) & MITRE ATT&CK Mapping")
    print(" 7. Chain of Custody & Legal Evidence Ledger")
    print(" 8. AI-Assisted Executive Incident Report (MD / HTML / DOCX)")
    print(" 9. Ollama Local LLM Status & Model Inventory")
    print("10. Launch Interactive Web Dashboard (FastAPI GUI)")
    print("11. Exit")
    print("=" * 70)


def view_iocs_and_mitre():
    print("\n" + "=" * 70)
    print("INDICATORS OF COMPROMISE (IOC) & MITRE ATT&CK MAPPING")
    print("=" * 70)
    data = scan_evidence_directory()
    print(f"\nTotal Files Scanned: {data['scanned_files_count']}")
    print(f"Total Unique IPs Discovered: {data['total_unique_ips']} (Malicious: {data['malicious_ip_count']})\n")

    print(f"{'IP ADDRESS':<18} {'THREAT LEVEL':<18} {'ROLE'}")
    print("-" * 70)
    for ip in data["iocs"]["ip_addresses"]:
        if ip["threat_level"] != "INTERNAL":
            print(f"{ip['ip']:<18} {ip['threat_level']:<18} {ip['role']}")

    print("\n\nMITRE ATT&CK MATRIX ALIGNMENT:")
    print("-" * 70)
    for m in data["mitre_attack"]:
        print(f"[{m['technique_id']}] {m['technique_name']} ({m['tactic']}) - Source: {m['evidence_source']}")

    input("\nPress Enter to continue...")


def view_chain_of_custody():
    print("\n" + "=" * 70)
    print("LEGAL EVIDENCE CHAIN OF CUSTODY LEDGER")
    print("=" * 70)
    ledger = load_chain_of_custody()
    print(f"Case ID : {ledger.get('case_number')}")
    print(f"Title   : {ledger.get('case_name')}")
    print(f"Lead    : {ledger.get('lead_investigator')}")
    print(f"Items   : {len(ledger.get('evidence_items', []))} cataloged evidence artifacts\n")

    print(f"{'ITEM ID':<10} {'FILENAME':<24} {'INTEGRITY':<12} {'SHA-256 CHECK'} ")
    print("-" * 70)
    for item in ledger.get("evidence_items", []):
        sha_short = item.get("current_sha256", "")[:16] + "..."
        print(f"{item.get('evidence_id', 'EV-00'):<10} {item.get('filename', '')[:23]:<24} {item.get('integrity_status', 'VERIFIED'):<12} {sha_short}")

    input("\nPress Enter to continue...")


def launch_web_gui():
    print("\nStarting Web GUI on http://127.0.0.1:8000 ...")
    print("Press Ctrl+C to stop.\n")
    try:
        import uvicorn
        uvicorn.run("gui_app:app", host="127.0.0.1", port=8000, reload=False)
    except KeyboardInterrupt:
        print("\nWeb GUI stopped.")
    except Exception as e:
        print(f"Error launching Web GUI: {e}")
        input("\nPress Enter to continue...")


def main():
    while True:
        banner()
        choice = input("Enter Choice (1-11): ").strip()

        if choice == "1":
            system_information()
        elif choice == "2":
            process_information()
        elif choice == "3":
            collect_artifacts()
        elif choice == "4":
            hash_menu()
        elif choice == "5":
            create_timeline()
        elif choice == "6":
            view_iocs_and_mitre()
        elif choice == "7":
            view_chain_of_custody()
        elif choice == "8":
            res = generate_report()
            print("\n[OK] Report generated successfully!")
            print(f"Markdown : {res['report_md_path']}")
            print(f"HTML     : {res['report_html_path']}")
            print(f"DOCX     : {res['report_docx_path']}")
            input("\nPress Enter to continue...")
        elif choice == "9":
            ollama_information()
        elif choice == "10":
            launch_web_gui()
        elif choice == "11":
            print("\nExiting AI Cyber Forensics Toolkit. Stay secure!\n")
            break
        else:
            print("\nInvalid choice. Please select 1-11.")
            input("Press Enter to continue...")


if __name__ == "__main__":
    main()
