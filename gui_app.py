import os
import sys
import platform
import subprocess
import shutil
import json
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

import psutil
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Dynamically resolve PROJECT_ROOT to the repository directory
PROJECT_ROOT = Path(__file__).resolve().parent

# Ensure forensic_toolkit packages can be imported
sys.path.insert(0, str(PROJECT_ROOT))

from forensic_toolkit.hashing import calculate_sha256
from forensic_toolkit.ollama_info import get_ollama_path

app = FastAPI(title="AI Cyber Forensics Toolkit Web API")

EVIDENCE_DIR = PROJECT_ROOT / "Evidence"


# ---------------------------------------------------------------------------
# RAG Assistant Lazy Loader & Initialization
# ---------------------------------------------------------------------------

rag_assistant = None
current_rag_model = "llama3.2:1b"

def init_rag_assistant(model_name=None):
    global rag_assistant, current_rag_model
    if model_name:
        current_rag_model = model_name
    
    # Check if VectorDB directory exists and contains files. If not, auto-create it.
    vector_db_path = PROJECT_ROOT / "VectorDB"
    if not vector_db_path.exists() or not list(vector_db_path.glob("*")):
        print("VectorDB not found or empty. Auto-building from Evidence folder...")
        try:
            from rag_assistant.create_embeddings import create_vector_database
            create_vector_database()
        except Exception as e:
            print(f"Error building vector database: {e}")
            
    try:
        from rag_assistant.rag_engine import DigitalForensicsAssistant
        rag_assistant = DigitalForensicsAssistant(model_name=current_rag_model)
    except Exception as e:
        print(f"Error initializing DigitalForensicsAssistant: {e}")
        rag_assistant = None

@app.on_event("startup")
def startup_event():
    init_rag_assistant()


# ---------------------------------------------------------------------------
# Helper: query local Ollama LLM
# ---------------------------------------------------------------------------

def query_ollama(prompt: str, model: str) -> str:
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
        with urllib.request.urlopen(req, timeout=120) as response:
            res_body = response.read().decode("utf-8")
            res_data = json.loads(res_body)
            return res_data.get("response", "")
    except urllib.error.URLError as e:
        return f"Error: Could not query Ollama. Server is offline. Details: {e}"
    except Exception as e:
        return f"Error: {e}"


def get_available_models():
    """Query local Ollama instance for installed models."""
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as response:
            res_body = response.read().decode("utf-8")
            res_data = json.loads(res_body)
            return [m["name"] for m in res_data.get("models", [])]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# /api/system_info
# ---------------------------------------------------------------------------

@app.get("/api/system_info")
def get_system_info():
    try:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/") if platform.system() != "Windows" else psutil.disk_usage("C:\\")

        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_usage_percent": cpu_usage,
            "memory": {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "available_gb": round(mem.available / (1024 ** 3), 2),
                "percentage": mem.percent
            },
            "disk": {
                "total_gb": round(disk.total / (1024 ** 3), 2),
                "used_gb": round(disk.used / (1024 ** 3), 2),
                "free_gb": round(disk.free / (1024 ** 3), 2),
                "percentage": disk.percent
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/ollama_info
# ---------------------------------------------------------------------------

@app.get("/api/ollama_info")
def get_ollama_info():
    try:
        ollama_cmd = get_ollama_path()

        # Version
        version = ""
        try:
            result = subprocess.run(
                f"{ollama_cmd} --version",
                shell=True, capture_output=True, text=True, timeout=5
            )
            version = result.stdout.strip()
        except Exception:
            version = "Unknown"

        # Installed models
        installed_models = get_available_models()

        # Service running check (process list)
        service_running = False
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    'tasklist | findstr /I "ollama"',
                    shell=True, capture_output=True, text=True, timeout=5
                )
                service_running = bool(result.stdout.strip())
            else:
                result = subprocess.run(
                    "pgrep -fl ollama",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                service_running = bool(result.stdout.strip())
        except Exception:
            pass

        # Port 11434 listening
        port_listening = False
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    "netstat -ano | findstr 11434",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                port_listening = bool(result.stdout.strip())
            else:
                result = subprocess.run(
                    "ss -lntp | grep 11434",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                port_listening = bool(result.stdout.strip())
        except Exception:
            pass

        # Resolve installed path
        installed_path = shutil.which("ollama") or ollama_cmd

        return {
            "version": version,
            "installed_path": installed_path,
            "installed_models": installed_models,
            "service_running": service_running,
            "port_listening": port_listening
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/processes
# ---------------------------------------------------------------------------

@app.get("/api/processes")
def get_processes():
    try:
        ollama_processes = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                if "ollama" in proc.info["name"].lower():
                    ollama_processes.append({
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "cpu_percent": proc.info["cpu_percent"],
                        "memory_mb": round(proc.info["memory_info"].rss / (1024 ** 2), 2)
                        if proc.info["memory_info"] else 0
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return {"ollama_processes": ollama_processes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/artifacts
# ---------------------------------------------------------------------------

@app.get("/api/artifacts")
def get_artifacts():
    try:
        ollama_cmd = get_ollama_path()
        home = Path.home()
        model_dir = home / ".ollama"

        files = []
        total_files = 0
        if model_dir.exists():
            for root, _, filenames in os.walk(model_dir):
                for fname in filenames:
                    fpath = Path(root) / fname
                    try:
                        size_mb = round(fpath.stat().st_size / (1024 ** 2), 3)
                        files.append({
                            "name": fname,
                            "path": str(fpath),
                            "size_mb": size_mb
                        })
                        total_files += 1
                    except Exception:
                        pass
            files = files[:50]  # cap at 50 entries

        return {
            "installed_path": shutil.which("ollama") or ollama_cmd,
            "model_directory": str(model_dir),
            "total_files": total_files,
            "files": files
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/hashing
# ---------------------------------------------------------------------------

@app.post("/api/hashing")
def run_hashing():
    evidence_dir = PROJECT_ROOT / "Evidence"
    hash_dir = PROJECT_ROOT / "Hashes"

    if not evidence_dir.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found")

    hash_dir.mkdir(exist_ok=True)
    output_file = hash_dir / "sha256_hashes.txt"

    # Read existing baseline hashes if present
    baseline_hashes = {}
    if output_file.exists():
        try:
            content = output_file.read_text(encoding="utf-8")
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

    # Compute current hashes
    for filepath in evidence_dir.glob("*"):
        if filepath.is_file():
            digest = calculate_sha256(filepath)

            status = "verified"
            baseline_hash = baseline_hashes.get(filepath.name, "")

            if not is_first_run:
                if filepath.name in baseline_hashes:
                    if digest != baseline_hash:
                        status = "tampered"
                        has_tampered = True
                else:
                    status = "new"
            else:
                baseline_hash = digest

            results.append({
                "filename": filepath.name,
                "hash": digest,
                "baseline_hash": baseline_hash,
                "size_bytes": filepath.stat().st_size,
                "status": status
            })

    # Save baseline on first run
    try:
        if is_first_run:
            with open(output_file, "w", encoding="utf-8") as f:
                for res in results:
                    f.write(f"{res['filename']}\n{res['hash']}\n\n")
        else:
            verify_file = hash_dir / "sha256_hashes_verification.txt"
            with open(verify_file, "w", encoding="utf-8") as f:
                f.write(f"Verification Run: {datetime.now()}\n\n")
                for res in results:
                    f.write(f"{res['filename']}\nHash: {res['hash']}\nStatus: {res['status']}\n\n")

        return {
            "status": "success",
            "has_tampered": has_tampered,
            "hashes": results,
            "is_first_run": is_first_run
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/report/integrity
# ---------------------------------------------------------------------------

@app.post("/api/report/integrity")
def generate_integrity_report():
    evidence_dir = PROJECT_ROOT / "Evidence"
    hash_dir = PROJECT_ROOT / "Hashes"
    report_dir = PROJECT_ROOT / "Reports"

    if not evidence_dir.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found")

    hash_dir.mkdir(exist_ok=True)
    report_dir.mkdir(exist_ok=True)
    baseline_file = hash_dir / "sha256_hashes.txt"
    report_file = report_dir / "Evidence_Integrity_Report.md"

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

    tampered_files = []
    verified_files = []
    new_files = []

    for filepath in evidence_dir.glob("*"):
        if filepath.is_file():
            digest = calculate_sha256(filepath)
            if filepath.name in baseline_hashes:
                baseline_hash = baseline_hashes[filepath.name]
                if digest == baseline_hash:
                    verified_files.append((filepath.name, digest))
                else:
                    tampered_files.append((filepath.name, baseline_hash, digest))
            else:
                new_files.append((filepath.name, digest))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"""# FORENSIC EVIDENCE INTEGRITY REPORT

Generated on: {now_str}
Verification Status: {"🔴 WARNING - INTEGRITY VIOLATION DETECTED" if tampered_files else "🟢 SUCCESS - ALL FILES VERIFIED"}

---

## 1. Executive Summary
This report verifies the integrity of the forensic evidence files against the baseline checksums recorded at the time of acquisition.

{"⚠️ CRITICAL WARNING: Tampering or corruption has been detected in the evidence files listed below. The integrity of the dataset is compromised." if tampered_files else "All analyzed evidence files match their original acquisition checksums. Data integrity is confirmed."}

## 2. Integrity Verification Results

### 🔴 Tampered / Mismatched Files ({len(tampered_files)})
{"*None*" if not tampered_files else ""}
"""
    if tampered_files:
        report += "| File Name | Baseline SHA-256 Checksum | Current SHA-256 Checksum | Status |\n"
        report += "| --- | --- | --- | --- |\n"
        for name, baseline, current in tampered_files:
            report += f"| `{name}` | `{baseline}` | `{current}` | ❌ TAMPERED |\n"

    report += f"""
### 🟢 Verified / Intact Files ({len(verified_files)})
{"*None*" if not verified_files else ""}
"""
    if verified_files:
        report += "| File Name | Verified SHA-256 Checksum | Status |\n"
        report += "| --- | --- | --- |\n"
        for name, digest in verified_files:
            report += f"| `{name}` | `{digest}` | ✅ VERIFIED |\n"

    if new_files:
        report += f"""
### 🟡 Untracked / New Files ({len(new_files)})
"""
        report += "| File Name | Current SHA-256 Checksum | Status |\n"
        report += "| --- | --- | --- |\n"
        for name, digest in new_files:
            report += f"| `{name}` | `{digest}` | ⚠️ NEW UNTRACKED |\n"

    report += "\n---\nReport generated automatically by the AI Cyber Forensics Toolkit.\n"

    try:
        report_file.write_text(report, encoding="utf-8")
        return {
            "status": "success",
            "report_path": str(report_file),
            "has_tampered": len(tampered_files) > 0,
            "report_content": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/timeline
# ---------------------------------------------------------------------------

@app.post("/api/timeline")
def run_timeline():
    evidence_dir = PROJECT_ROOT / "Evidence"
    timeline_dir = PROJECT_ROOT / "Timeline"

    if not evidence_dir.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found")

    timeline_dir.mkdir(exist_ok=True)
    output_file = timeline_dir / "timeline.txt"

    events = []
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            for filepath in sorted(evidence_dir.iterdir()):
                if filepath.is_file():
                    mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
                    mtime_str = mtime.strftime("%Y-%m-%d %H:%M:%S.%f")
                    events.append({
                        "filename": filepath.name,
                        "modified_time": mtime_str
                    })
                    f.write(f"{mtime_str}  {filepath.name}\n")
        return {"status": "success", "file_written": str(output_file), "timeline": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# /api/report/generate
# ---------------------------------------------------------------------------

@app.post("/api/report/generate")
def run_report_generation(payload: dict):
    model = payload.get("model", "llama3.2:1b")

    evidence_dir = PROJECT_ROOT / "Evidence"
    report_dir = PROJECT_ROOT / "Reports"
    hash_file = PROJECT_ROOT / "Hashes" / "sha256_hashes.txt"
    timeline_file = PROJECT_ROOT / "Timeline" / "timeline.txt"

    if not evidence_dir.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found")

    report_dir.mkdir(exist_ok=True)
    report_file = report_dir / "Investigation_Report.md"

    # 1. Load Evidence
    evidence_context = ""
    for f in sorted(evidence_dir.glob("*")):
        if f.is_file():
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                evidence_context += f"--- START FILE: {f.name} ---\n{content}\n--- END FILE: {f.name} ---\n\n"
            except Exception:
                pass

    # 2. Load Hashes
    hashes_content = ""
    if hash_file.exists():
        hashes_content = hash_file.read_text(encoding="utf-8")

    # 3. Load Timeline
    timeline_content = ""
    if timeline_file.exists():
        timeline_content = timeline_file.read_text(encoding="utf-8")

    # 4. Generate Prompt
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

    ai_response = query_ollama(prompt, model)

    if ai_response.startswith("Error:"):
        report_data = f"""# AI Cyber Forensics Investigation Report (Ollama Offline Fallback)

Generated: {datetime.now()}

## 1. Executive Summary
A preliminary digital forensics investigation was conducted on collected workshop evidence files. The Ollama local AI model was offline at the time of dynamic generation.

## 2. Evidence Acquisition & Integrity
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

## 4. Recommended Actions
1. Ensure the Ollama service is running (`ollama serve`) and the Llama 3.2 model is downloaded (`ollama pull llama3.2:1b`).
"""
    else:
        report_data = ai_response

    try:
        report_file.write_text(report_data, encoding="utf-8")
        return {"status": "success", "model_used": model, "report": report_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write report: {e}")


# ---------------------------------------------------------------------------
# /api/report/get
# ---------------------------------------------------------------------------

@app.get("/api/report/get")
def get_report():
    report_file = PROJECT_ROOT / "Reports" / "Investigation_Report.md"
    if report_file.exists():
        return {"exists": True, "report": report_file.read_text(encoding="utf-8")}
    return {"exists": False, "report": ""}


# ---------------------------------------------------------------------------
# AI Forensic RAG Chatbot API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/chat/evidence")
def get_chat_evidence():
    evidence_dir = PROJECT_ROOT / "Evidence"
    files = []
    if evidence_dir.exists():
        for file in sorted(evidence_dir.iterdir()):
            if file.is_file():
                files.append({
                    "name": file.name,
                    "size": file.stat().st_size
                })
    return files


@app.post("/api/chat/upload")
async def upload_chat_evidence(file: UploadFile = File(...)):
    evidence_dir = PROJECT_ROOT / "Evidence"
    evidence_dir.mkdir(exist_ok=True)
    
    file_path = evidence_dir / file.filename
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
        
    # Re-index the evidence
    try:
        from rag_assistant.create_embeddings import create_vector_database
        create_vector_database()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to index evidence: {e}")
        
    # Reinitialize the assistant
    init_rag_assistant(current_rag_model)
    
    return {"message": f"Successfully uploaded and indexed {file.filename}"}


class ChatRequest(BaseModel):
    question: str
    model: str = None


@app.post("/api/chat/query")
def chat_query(request: ChatRequest):
    global rag_assistant, current_rag_model
    
    # Switch model if requested and different
    if request.model and request.model != current_rag_model:
        init_rag_assistant(request.model)
        
    if not rag_assistant:
        # Try initializing again
        init_rag_assistant(current_rag_model)
        
    if not rag_assistant:
        raise HTTPException(status_code=503, detail="RAG Assistant is not initialized. Please ensure Ollama is running.")
        
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
# Mount Web GUI static folder after all API endpoints
# ---------------------------------------------------------------------------

gui_dir = PROJECT_ROOT / "web_gui"
if gui_dir.exists():
    app.mount("/", StaticFiles(directory=str(gui_dir), html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return HTMLResponse("<h1>Web GUI Static Directory Not Found</h1>")
