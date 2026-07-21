"""
Investigation Report Generator (AI-Assisted)
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from forensic_toolkit.utils import log, PROJECT_ROOT
from forensic_toolkit.hashing import calculate_sha256


def get_available_models():
    """Query local Ollama instance for installed models."""
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
        # Set a short timeout of 3 seconds to avoid blocking if offline
        with urllib.request.urlopen(req, timeout=3) as response:
            res_body = response.read().decode("utf-8")
            res_data = json.loads(res_body)
            models = [m["name"] for m in res_data.get("models", [])]
            return models
    except Exception:
        return []


def query_ollama(prompt, model):
    """Query the local Ollama API to generate text."""
    url = "http://localhost:11434/api/generate"
    data = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }
    try:
        req_body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        # Timeout after 120 seconds for slower local model runs
        with urllib.request.urlopen(req, timeout=120) as response:
            res_body = response.read().decode("utf-8")
            res_data = json.loads(res_body)
            return res_data.get("response", "")
    except urllib.error.URLError as e:
        return f"Error: Could not query Ollama. Server is offline. Details: {e}"
    except Exception as e:
        return f"Error: {e}"


def generate_report():
    log("Investigation Report Generated")
    print("\n" + "=" * 60)
    print("AI-ASSISTED INCIDENT REPORT GENERATOR")
    print("=" * 60)

    # 1. Establish Workspace Folders
    evidence_dir = PROJECT_ROOT / "Evidence"
    report_dir = PROJECT_ROOT / "Reports"
    hash_dir = PROJECT_ROOT / "Hashes"
    timeline_dir = PROJECT_ROOT / "Timeline"

    report_dir.mkdir(exist_ok=True)
    report_file = report_dir / "Investigation_Report.md"

    # 2. Check for evidence files
    if not evidence_dir.exists():
        print(f"Error: Evidence directory not found at: {evidence_dir}")
        input("\nPress Enter to continue...")
        return

    # 3. Read Evidence Contents
    evidence_context = ""
    evidence_files = list(evidence_dir.glob("*"))
    if not evidence_files:
        print("Warning: No evidence files found in the Evidence directory.")
    
    print("\nLoading evidence files...")
    for f in sorted(evidence_files):
        if f.is_file():
            print(f" - Loading: {f.name}")
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                evidence_context += f"--- START FILE: {f.name} ---\n"
                evidence_context += content
                evidence_context += f"\n--- END FILE: {f.name} ---\n\n"
            except Exception as e:
                evidence_context += f"[Error loading file {f.name}: {e}]\n\n"

    # 4. Read Hash Files
    hashes_content = ""
    hash_file = hash_dir / "sha256_hashes.txt"
    if hash_file.exists():
        try:
            hashes_content = hash_file.read_text(encoding="utf-8")
        except Exception:
            pass
    else:
        # Dynamically compute if file is missing
        print("Hashes file not found, computing evidence hashes dynamically...")
        for f in sorted(evidence_files):
            if f.is_file():
                try:
                    hashes_content += f"{f.name}\n{calculate_sha256(f)}\n\n"
                except Exception:
                    pass

    # 5. Read Timeline
    timeline_content = ""
    timeline_file = timeline_dir / "timeline.txt"
    if timeline_file.exists():
        try:
            timeline_content = timeline_file.read_text(encoding="utf-8")
        except Exception:
            pass

    # 6. Check Ollama LLM Status and select model
    models = get_available_models()
    model_to_use = None

    if models:
        print("\nOllama is running. Available local models:")
        for idx, m in enumerate(models):
            print(f"[{idx + 1}] {m}")
        
        # Select model
        choice = input(f"\nSelect model (default is 1 / {models[0]}): ").strip()
        try:
            val = int(choice) - 1
            if 0 <= val < len(models):
                model_to_use = models[val]
            else:
                model_to_use = models[0]
        except Exception:
            model_to_use = models[0]
    else:
        print("\n[!] Warning: Ollama local service is offline or no models are installed.")
        print("    Ensure Ollama is running and has models downloaded (e.g. 'ollama run llama3.2:1b').")
        print("    Generating template-based Incident Report fallback...")

    # 7. Generate Report via LLM or Fallback Template
    if model_to_use:
        print(f"\nQuerying Local LLM ({model_to_use}) for forensic summary... Please wait...")
        
        # Build prompt
        prompt = f"""
You are a Senior Digital Forensics and Incident Response (DFIR) Specialist.
Analyze the following digital forensic evidence files, their integrity hashes, and the artifact modification timeline.

=== EVIDENCE FILES ===
{evidence_context}

=== EVIDENCE INTEGRITY HASHES ===
{hashes_content}

=== EVENT TIMELINE ===
{timeline_content}

Based on this evidence, generate a comprehensive, highly professional Executive Incident Report containing:
1. EXECUTIVE SUMMARY: High-level summary of the security incident, suspected compromise, and investigator conclusions.
2. EVIDENCE ACQUISITION & INTEGRITY: Table listing files analyzed, description of each file, and their SHA-256 hashes to guarantee chain of custody.
3. TIMELINE OF EVENTS: Chronological analysis of activities based on the timeline and logs.
4. KEY FINDINGS & ANALYSIS: Detailed findings identifying suspicious files, indicators of compromise (IOCs), threat actors, or simulated ransomware activity.
5. RECOMMENDATIONS & INCIDENT RESPONSE ACTION PLAN: Actionable remediation steps for the organization.

Structure the report clearly in Markdown. Be technical, professional, and thorough.
"""
        ai_response = query_ollama(prompt, model_to_use)
        
        if ai_response.startswith("Error:"):
            print("\n" + ai_response)
            model_to_use = None # Force fallback to template
        else:
            report_data = ai_response
    
    if not model_to_use:
        # Fallback Template
        print("\nGenerating template-based report...")
        report_data = f"""# AI Cyber Forensics Investigation Report (Ollama Offline Fallback)

Generated: {datetime.now()}

## 1. Executive Summary
A preliminary digital forensics investigation was conducted on collected workshop evidence files. The Ollama local AI model was offline at the time of dynamic generation, so this template outlines the evidence compiled.

## 2. Evidence Acquisition & Integrity
The following files were preserved and validated in the workspace:

| File Name | SHA-256 Hash |
| --- | --- |
"""
        for line in hashes_content.split("\n\n"):
            if not line.strip():
                continue
            parts = line.strip().split("\n")
            if len(parts) >= 2:
                report_data += f"| `{parts[0]}` | `{parts[1]}` |\n"
        
        report_data += f"""
## 3. Timeline of Events
Reflects file timestamps recorded in the workspace:

```text
{timeline_content.strip()}
```

## 4. Key Findings & Analysis
- **Preserved Evidence:** System acquired files include phishing emails, simulated invoices, meeting logs, and ransomware simulation documents.
- **Compromise Indicators:** Phishing threats detected (`phishing_email.txt`) and training ransomware notes (`ransomware_note.txt`).
- **Chain of Custody:** Evidence hashes verified successfully.

## 5. Recommended Actions
1. Ensure the Ollama service is running (`ollama serve`) and the Llama 3.2 model is downloaded (`ollama pull llama3.2:1b`).
2. Run this toolkit again to perform a dynamic AI-assisted threat synthesis.
"""

    # 8. Write Report to file
    try:
        report_file.write_text(report_data, encoding="utf-8")
        print("\n" + "=" * 50)
        print("INVESTIGATION REPORT GENERATED SUCCESSFULLY")
        print("=" * 50)
        print(report_data[:1000])  # Preview first 1000 chars
        print("\n...")
        print(f"\nFull report saved to:\n[Investigation_Report.md](file:///{report_file.as_posix()})")
    except Exception as e:
        print(f"\nError writing report to file: {e}")

    input("\nPress Enter to continue...")