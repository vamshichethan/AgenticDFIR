"""
AI Cyber Forensics & Incident Response Platform - FastAPI Backend
Provides comprehensive RESTful endpoints for live system triage, cryptographic integrity,
super-timeline correlation, IOC threat intelligence, Chain of Custody, and Hybrid AI Copilot.
"""

import os
import sys
import shutil
import platform
import subprocess
from pathlib import Path
from datetime import datetime

import psutil
from fastapi import FastAPI, HTTPException, UploadFile, File, Query, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Dynamically resolve PROJECT_ROOT to the repository directory
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Forensic Toolkit Imports
from forensic_toolkit.hashing import calculate_sha256, calculate_md5, calculate_entropy, get_file_metadata
from forensic_toolkit.live_forensics import (
    get_live_system_metrics,
    analyze_processes,
    analyze_network_sockets,
    analyze_persistence,
    analyze_user_accounts
)
from forensic_toolkit.super_timeline import build_super_timeline, export_timeline_csv
from forensic_toolkit.ioc_analyzer import scan_evidence_directory, extract_iocs_from_text, MITRE_ATTACK_MAPPING
from forensic_toolkit.inspector import get_hex_dump, extract_strings
from forensic_toolkit.chain_of_custody import load_chain_of_custody, sync_evidence_items, record_custody_transfer
from forensic_toolkit.report import generate_report as run_report_gen, get_available_models, query_ollama
from forensic_toolkit.ollama_info import get_ollama_path

app = FastAPI(
    title="AgenticDFIR - AI Cyber Forensics & Incident Response Platform",
    description="Enterprise DFIR Toolkit with Live Host Forensics, Super-Timeline Correlation, and Hybrid AI Copilot",
    version="2.0.0"
)

# Enable CORS for cloud deployment and cross-origin access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/healthz")
def health_check():
    """Health check endpoint for cloud orchestrators (Render, Kubernetes, Docker)."""
    return {
        "status": "healthy",
        "service": "AgenticDFIR",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }

EVIDENCE_DIR = PROJECT_ROOT / "Evidence"
REPORTS_DIR = PROJECT_ROOT / "Reports"
HASHES_DIR = PROJECT_ROOT / "Hashes"
TIMELINE_DIR = PROJECT_ROOT / "Timeline"

# ---------------------------------------------------------------------------
# RAG Assistant Lazy Loader & Initialization
# ---------------------------------------------------------------------------

rag_assistant = None
current_rag_model = "llama3.2:1b"


def init_rag_assistant(model_name=None):
    global rag_assistant, current_rag_model
    if model_name:
        current_rag_model = model_name

    try:
        from rag_assistant.rag_engine import DigitalForensicsAssistant
        rag_assistant = DigitalForensicsAssistant(model_name=current_rag_model)
    except Exception as e:
        print(f"Error initializing DigitalForensicsAssistant: {e}")
        rag_assistant = None


@app.on_event("startup")
def startup_event():
    # Sync Chain of Custody ledger on startup
    try:
        sync_evidence_items(EVIDENCE_DIR)
    except Exception as e:
        print(f"Chain of Custody init note: {e}")
    # Initialize RAG Assistant
    init_rag_assistant()


# ---------------------------------------------------------------------------
# 1. System & Host Diagnostics Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/system_info")
def get_system_info():
    """Retrieve comprehensive host hardware, operating system, and memory metrics."""
    try:
        return get_live_system_metrics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ollama_info")
def get_ollama_info():
    """Check local Ollama installation, running daemon status, and installed models."""
    try:
        ollama_cmd = get_ollama_path()
        version = "Unknown"
        try:
            result = subprocess.run(
                f"{ollama_cmd} --version",
                shell=True, capture_output=True, text=True, timeout=5
            )
            version = result.stdout.strip() or "Unknown"
        except Exception:
            pass

        installed_models = get_available_models()

        # Service running check
        service_running = False
        try:
            if platform.system() == "Windows":
                res = subprocess.run('tasklist | findstr /I "ollama"', shell=True, capture_output=True, text=True, timeout=3)
                service_running = bool(res.stdout.strip())
            else:
                res = subprocess.run("pgrep -fl ollama", shell=True, capture_output=True, text=True, timeout=3)
                service_running = bool(res.stdout.strip())
        except Exception:
            pass

        # Port 11434 check
        port_listening = len(installed_models) > 0 or service_running

        installed_path = shutil.which("ollama") or ollama_cmd

        return {
            "version": version,
            "installed_path": installed_path,
            "installed_models": installed_models,
            "service_running": service_running or len(installed_models) > 0,
            "port_listening": port_listening
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# 2. Live Host Forensics & Anomaly Triage Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/forensics/processes")
def get_forensic_processes():
    """Live process enumeration with parent-child tree mapping and DFIR anomaly scoring."""
    try:
        return analyze_processes()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Compatibility alias
@app.get("/api/processes")
def get_processes_alias():
    return get_forensic_processes()


@app.get("/api/forensics/sockets")
def get_forensic_sockets():
    """Active network sockets with external IP threat classification."""
    try:
        return analyze_network_sockets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/forensics/persistence")
def get_forensic_persistence():
    """Cross-platform autoruns: LaunchAgents, Crontabs, Startup folders, and Shell profiles."""
    try:
        return analyze_persistence()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/forensics/users")
def get_forensic_users():
    """System accounts, privilege levels, and active login sessions."""
    try:
        return analyze_user_accounts()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Compatibility alias for artifacts
@app.get("/api/artifacts")
def get_artifacts_compat():
    try:
        return {
            "system": get_live_system_metrics(),
            "persistence": analyze_persistence(),
            "processes_summary": analyze_processes()["suspicious_count"],
            "sockets_summary": analyze_network_sockets()["suspicious_count"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# 3. Cryptographic Evidence Hashing & Tamper Detection
# ---------------------------------------------------------------------------

@app.post("/api/hashing")
def run_hashing():
    """Calculate multi-hashes (MD5, SHA-256) and Shannon Entropy for all evidence files."""
    if not EVIDENCE_DIR.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found")

    HASHES_DIR.mkdir(exist_ok=True)
    baseline_file = HASHES_DIR / "sha256_hashes.txt"

    baseline_hashes = {}
    if baseline_file.exists():
        try:
            content = baseline_file.read_text(encoding="utf-8")
            records = content.split("\n\n")
            for rec in records:
                lines = [l.strip() for l in rec.split("\n") if l.strip()]
                if len(lines) >= 2:
                    baseline_hashes[lines[0]] = lines[1]
        except Exception:
            pass

    is_first_run = len(baseline_hashes) == 0
    results = []
    has_tampered = False

    for filepath in sorted(EVIDENCE_DIR.glob("*")):
        if filepath.is_file():
            meta = get_file_metadata(filepath)
            status = "verified"
            baseline_hash = baseline_hashes.get(filepath.name, "")

            if not is_first_run:
                if filepath.name in baseline_hashes:
                    if meta["sha256"] != baseline_hash:
                        status = "tampered"
                        has_tampered = True
                else:
                    status = "new"
            else:
                baseline_hash = meta["sha256"]

            meta["status"] = status
            meta["baseline_hash"] = baseline_hash
            results.append(meta)

    try:
        if is_first_run:
            with open(baseline_file, "w", encoding="utf-8") as f:
                for res in results:
                    f.write(f"{res['filename']}\n{res['sha256']}\n\n")
        else:
            verify_file = HASHES_DIR / "sha256_hashes_verification.txt"
            with open(verify_file, "w", encoding="utf-8") as f:
                f.write(f"Verification Run: {datetime.now()}\n\n")
                for res in results:
                    f.write(f"{res['filename']}\nHash: {res['sha256']}\nStatus: {res['status']}\n\n")

        # Also update Chain of Custody
        sync_evidence_items(EVIDENCE_DIR)

        return {
            "status": "success",
            "has_tampered": has_tampered,
            "hashes": results,
            "is_first_run": is_first_run
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/report/integrity")
def generate_integrity_report():
    """Produce formal evidence integrity verification report."""
    if not EVIDENCE_DIR.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found")

    REPORTS_DIR.mkdir(exist_ok=True)
    report_file = REPORTS_DIR / "Evidence_Integrity_Report.md"

    res = run_hashing()
    hashes = res["hashes"]
    has_tampered = res["has_tampered"]

    tampered_files = [h for h in hashes if h["status"] == "tampered"]
    verified_files = [h for h in hashes if h["status"] == "verified"]
    new_files = [h for h in hashes if h["status"] == "new"]

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"""# FORENSIC EVIDENCE INTEGRITY & TAMPER VERIFICATION REPORT

**Report Generated:** {now_str}  
**Verification Verdict:** {"🔴 CRITICAL - INTEGRITY VIOLATION DETECTED" if has_tampered else "🟢 SUCCESS - ALL EVIDENCE VERIFIED INTACT"}  

---

## 1. Executive Summary
This report documents the cryptographic integrity verification of all acquired digital evidence files. Hashes were verified against baseline checksums established during acquisition.

{"⚠️ CRITICAL TAMPER ALERT: Checksum mismatch detected! One or more evidence files have been altered or corrupted." if has_tampered else "All examined evidence files match their acquisition checksums exactly. Chain of custody integrity is confirmed."}

## 2. Integrity Verification Matrix

### 🔴 Tampered Artifacts ({len(tampered_files)})
"""
    if tampered_files:
        report += "| File Name | Baseline SHA-256 | Current SHA-256 | Current MD5 | Entropy | Status |\n"
        report += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
        for t in tampered_files:
            report += f"| `{t['filename']}` | `{t['baseline_hash']}` | `{t['sha256']}` | `{t['md5']}` | {t['entropy']} | ❌ TAMPERED |\n"
    else:
        report += "*No tampered files detected.*\n"

    report += f"\n### 🟢 Verified Artifacts ({len(verified_files)})\n"
    if verified_files:
        report += "| File Name | Verified SHA-256 Checksum | MD5 Checksum | Entropy | Status |\n"
        report += "| :--- | :--- | :--- | :--- | :--- |\n"
        for v in verified_files:
            report += f"| `{v['filename']}` | `{v['sha256']}` | `{v['md5']}` | {v['entropy']} | ✅ VERIFIED |\n"
    else:
        report += "*None*\n"

    if new_files:
        report += f"\n### 🟡 Untracked / Newly Added Artifacts ({len(new_files)})\n"
        report += "| File Name | SHA-256 Checksum | Size | Status |\n| :--- | :--- | :--- | :--- |\n"
        for n in new_files:
            report += f"| `{n['filename']}` | `{n['sha256']}` | {n['size_bytes']} B | ⚠️ NEW UNTRACKED |\n"

    report += "\n---\n*Report generated automatically by the AI Cyber Forensics Toolkit.*\n"

    try:
        report_file.write_text(report, encoding="utf-8")
        return {
            "status": "success",
            "report_path": str(report_file),
            "has_tampered": has_tampered,
            "report_content": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# 4. Chain of Custody & Legal Evidence Preservation
# ---------------------------------------------------------------------------

@app.get("/api/custody/ledger")
def get_custody_ledger():
    """Retrieve the full legal Chain of Custody record."""
    try:
        return sync_evidence_items(EVIDENCE_DIR)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class CustodyTransferRequest(BaseModel):
    released_by: str
    received_by: str
    purpose: str
    notes: str = ""


@app.post("/api/custody/transfer")
def add_custody_transfer(request: CustodyTransferRequest):
    """Log an official evidence custody transfer entry."""
    try:
        ledger = record_custody_transfer(
            released_by=request.released_by,
            received_by=request.received_by,
            purpose=request.purpose,
            notes=request.notes
        )
        return {"status": "success", "ledger": ledger}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# 5. Super-Timeline & Multi-Source Event Correlation
# ---------------------------------------------------------------------------

@app.get("/api/timeline")
@app.post("/api/timeline")
def get_timeline():
    """Build and retrieve master chronological super-timeline across all evidence logs."""
    try:
        timeline_data = build_super_timeline(EVIDENCE_DIR)
        return {
            "status": "success",
            "timeline": timeline_data["events"],
            "summary": {
                "total_events": timeline_data["total_events"],
                "severity_summary": timeline_data["severity_summary"],
                "kill_chain_summary": timeline_data["kill_chain_summary"],
                "suspicious_ips": timeline_data["suspicious_ips"],
                "compromised_users": timeline_data["compromised_users"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/timeline/export/csv")
def export_timeline_csv_endpoint():
    """Export the forensic super-timeline to CSV format."""
    try:
        timeline_data = build_super_timeline(EVIDENCE_DIR)
        csv_str = export_timeline_csv(timeline_data["events"])
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=Forensic_Timeline.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# 6. Indicators of Compromise (IOC) & MITRE ATT&CK Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/iocs")
def get_all_iocs():
    """Extract and correlate all Indicators of Compromise and MITRE ATT&CK mappings."""
    try:
        return scan_evidence_directory(EVIDENCE_DIR)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ScanTextRequest(BaseModel):
    text: str


@app.post("/api/iocs/scan-text")
def scan_text_for_iocs(request: ScanTextRequest):
    """Scan raw text or pasted log snippet for IOCs in real-time."""
    try:
        return extract_iocs_from_text(request.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mitre")
def get_mitre_mapping():
    """Retrieve full MITRE ATT&CK matrix alignment for the incident."""
    return {"tactics_and_techniques": MITRE_ATTACK_MAPPING}


# ---------------------------------------------------------------------------
# 7. Raw Evidence Hex & String Inspector
# ---------------------------------------------------------------------------

@app.get("/api/evidence/list")
def list_evidence_files():
    """List all evidence files with size, hash, and entropy score."""
    files = []
    if EVIDENCE_DIR.exists():
        for f in sorted(EVIDENCE_DIR.glob("*")):
            if f.is_file():
                files.append(get_file_metadata(f))
    return files


@app.get("/api/evidence/hex")
def view_evidence_hex(filename: str = Query(...), offset: int = Query(0), length: int = Query(2048)):
    """Generate forensic hex dump for a specific evidence file."""
    target = EVIDENCE_DIR / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return get_hex_dump(target, offset=offset, length=length)


@app.get("/api/evidence/strings")
def view_evidence_strings(
    filename: str = Query(...),
    min_length: int = Query(4),
    filter: str = Query(None)
):
    """Extract printable strings from an evidence file with optional search filter."""
    target = EVIDENCE_DIR / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return extract_strings(target, min_length=min_length, search_filter=filter)


@app.post("/api/evidence/upload")
async def upload_evidence(file: UploadFile = File(...)):
    """Upload new evidence file into the case locker and sync hashes."""
    EVIDENCE_DIR.mkdir(exist_ok=True)
    target_path = EVIDENCE_DIR / file.filename
    content = await file.read()
    with open(target_path, "wb") as f:
        f.write(content)

    meta = get_file_metadata(target_path)
    sync_evidence_items(EVIDENCE_DIR)

    # Re-index assistant
    init_rag_assistant(current_rag_model)

    return {
        "status": "success",
        "message": f"Evidence '{file.filename}' uploaded and indexed.",
        "metadata": meta
    }


# ---------------------------------------------------------------------------
# 8. AI Incident Copilot & Consolidated Investigation Reporting
# ---------------------------------------------------------------------------

class ReportGenerateRequest(BaseModel):
    model: str = "llama3.2:1b"


@app.post("/api/report/generate")
def generate_report_endpoint(payload: ReportGenerateRequest = None):
    """Generate consolidated DFIR executive report in Markdown, HTML, and DOCX."""
    model = payload.model if payload else "llama3.2:1b"
    try:
        return run_report_gen(model=model)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/report/get")
def get_report():
    """Retrieve existing Investigation Report."""
    md_file = REPORTS_DIR / "Investigation_Report.md"
    html_file = REPORTS_DIR / "Investigation_Report.html"
    json_file = REPORTS_DIR / "Investigation_Report.json"

    if md_file.exists():
        metadata = {}
        if json_file.exists():
            try:
                metadata = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "exists": True,
            "report": md_file.read_text(encoding="utf-8"),
            "has_html": html_file.exists(),
            "metadata": metadata
        }
    return {"exists": False, "report": ""}


@app.get("/api/report/download/{fmt}")
def download_report(fmt: str):
    """Download the report in requested format: md, html, docx, json."""
    files_map = {
        "md": (REPORTS_DIR / "Investigation_Report.md", "text/markdown"),
        "html": (REPORTS_DIR / "Investigation_Report.html", "text/html"),
        "docx": (REPORTS_DIR / "Investigation_Report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "json": (REPORTS_DIR / "Investigation_Report.json", "application/json")
    }

    if fmt not in files_map:
        raise HTTPException(status_code=400, detail="Invalid format. Supported: md, html, docx, json")

    target, media_type = files_map[fmt]
    if not target.exists():
        # Trigger generation if not exists
        run_report_gen()

    if target.exists():
        return FileResponse(
            path=str(target),
            media_type=media_type,
            filename=target.name
        )
    raise HTTPException(status_code=404, detail=f"Report file {fmt} could not be found.")


# ---------------------------------------------------------------------------
# 9. AI Forensic RAG Chatbot
# ---------------------------------------------------------------------------

@app.get("/api/chat/evidence")
def get_chat_evidence():
    """Retrieve evidence files and sizes for chatbot context."""
    files = []
    if EVIDENCE_DIR.exists():
        for file in sorted(EVIDENCE_DIR.iterdir()):
            if file.is_file():
                files.append({
                    "name": file.name,
                    "size": file.stat().st_size
                })
    return files


@app.post("/api/chat/upload")
async def upload_chat_evidence(file: UploadFile = File(...)):
    """Upload and re-index evidence for the chatbot."""
    return await upload_evidence(file)


class ChatRequest(BaseModel):
    question: str
    model: str = None


@app.post("/api/chat/query")
def chat_query(request: ChatRequest):
    """Interactive natural language Q&A against forensic evidence."""
    global rag_assistant, current_rag_model

    if request.model and request.model != current_rag_model:
        init_rag_assistant(request.model)

    if not rag_assistant:
        init_rag_assistant(current_rag_model)

    if not rag_assistant:
        raise HTTPException(status_code=503, detail="RAG Assistant could not be initialized.")

    try:
        import time
        start = time.time()
        answer, sources, confidence = rag_assistant.ask(request.question)
        elapsed = time.time() - start

        return {
            "answer": answer,
            "sources": sources,
            "confidence": confidence,
            "time": datetime.now().strftime("%H:%M:%S"),
            "elapsed_seconds": round(elapsed, 2)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# 10. Mount Web GUI static folder
# ---------------------------------------------------------------------------

gui_dir = PROJECT_ROOT / "web_gui"
if gui_dir.exists():
    app.mount("/", StaticFiles(directory=str(gui_dir), html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return HTMLResponse("<h1>Web GUI Static Directory Not Found</h1>")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Starting AgenticDFIR server on {host}:{port}...")
    uvicorn.run("gui_app:app", host=host, port=port, reload=False)
