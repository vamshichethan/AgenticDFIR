"""
Unified Document Generator — Technical Report & Operation Manual
AI-Powered Digital Forensics Copilot
"""

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from datetime import datetime
import os

# Colors matching the user's screenshot and modern aesthetics
COLOR_PRIMARY_BLUE = RGBColor(79, 110, 242)    # Royal Blue for header text
COLOR_TITLE_NAVY   = RGBColor(15, 23, 42)      # Very dark slate/navy for main title
COLOR_TEXT_DARK    = RGBColor(30, 41, 59)      # Slate 800 for body text
COLOR_MUTED_GRAY   = RGBColor(100, 116, 139)   # Slate 500 for subtitles/metadata
COLOR_CYAN_ACCENT  = RGBColor(6, 182, 212)     # Cyan for section underlines/accents
COLOR_WHITE        = RGBColor(255, 255, 255)
COLOR_LIGHT_BG     = "F8FAFC"                  # Slate 50 for callout boxes
COLOR_BORDER_LIGHT = "E2E8F0"                  # Slate 200 for tables

def set_cell_bg(cell, hex_color: str):
    """Set table cell background color."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)

def add_horizontal_rule(doc, color_hex="E2E8F0", size="6"):
    """Add a thin horizontal separator line."""
    p = doc.add_paragraph()
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), size)
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), color_hex)
    pBdr.append(bottom)
    pPr.append(pBdr)
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(8)
    return p

def add_title_header(doc, text):
    """Helper for H1 titles with bottom borders."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(24)
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(20)
    run.font.color.rgb = COLOR_TITLE_NAVY
    add_horizontal_rule(doc, "4F6EF2", size="12")
    return p

def add_section_header(doc, text):
    """Helper for H2 headers."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(14)
    run.font.color.rgb = COLOR_PRIMARY_BLUE
    return p

def add_sub_section_header(doc, text):
    """Helper for H3 headers."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(12)
    run.font.color.rgb = COLOR_TITLE_NAVY
    return p

def add_body(doc, text):
    """Helper for body paragraphs."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    run = p.add_run(text)
    run.font.size = Pt(11)
    run.font.color.rgb = COLOR_TEXT_DARK
    return p

def add_bullet(doc, text, level=0):
    """Helper for bulleted lists."""
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.left_indent = Inches(0.25 * (level + 1))
    p.paragraph_format.line_spacing = 1.15
    run = p.add_run(text)
    run.font.size = Pt(11)
    run.font.color.rgb = COLOR_TEXT_DARK
    return p

def add_code_block(doc, text):
    """Helper for monospace code block simulation."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.rows[0].cells[0]
    cell.width = Inches(6.5)
    set_cell_bg(cell, "F1F5F9")  # Slate 100
    
    # Configure thin border
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    for border_name in ['top', 'left', 'bottom', 'right']:
        border = OxmlElement(f'w:{border_name}')
        border.set(qn('w:val'), 'single')
        border.set(qn('w:sz'), '4')
        border.set(qn('w:color'), 'CBD5E1')  # Slate 300
        tcBorders.append(border)
    tcPr.append(tcBorders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.left_indent = Inches(0.1)
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(9.5)
    run.font.color.rgb = COLOR_PRIMARY_BLUE
    doc.add_paragraph() # spacer

def add_callout(doc, label, text, icon="ℹ️", hex_bg="EFF6FF", text_color=COLOR_TEXT_DARK):
    """A beautiful styled alert/callout box."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.rows[0].cells[0]
    cell.width = Inches(6.5)
    set_cell_bg(cell, hex_bg)
    
    # Left thick accent border only
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    left = OxmlElement('w:left')
    left.set(qn('w:val'), 'single')
    left.set(qn('w:sz'), '24') # 3pt
    left.set(qn('w:color'), '4F6EF2')
    tcBorders.append(left)
    for border_name in ['top', 'bottom', 'right']:
        b = OxmlElement(f'w:{border_name}')
        b.set(qn('w:val'), 'none')
        tcBorders.append(b)
    tcPr.append(tcBorders)

    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.left_indent = Inches(0.1)
    
    run_icon = p.add_run(f"{icon}  {label} ")
    run_icon.bold = True
    run_icon.font.size = Pt(10.5)
    run_icon.font.color.rgb = COLOR_PRIMARY_BLUE
    
    run_text = p.add_run(text)
    run_text.font.size = Pt(10.5)
    run_text.font.color.rgb = text_color
    doc.add_paragraph() # spacer

def create_styled_cover_page(doc):
    """Generates the cover page matching the Nitk CSE user screenshot exactly."""
    # Top spacing
    p_top_space = doc.add_paragraph()
    p_top_space.paragraph_format.space_before = Pt(40)
    
    # 1. Header/Super-title: TECHNICAL REPORT & OPERATION MANUAL
    p_header = doc.add_paragraph()
    p_header.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_header.paragraph_format.space_after = Pt(48)
    run_header = p_header.add_run("TECHNICAL REPORT & OPERATION MANUAL")
    run_header.bold = True
    run_header.font.size = Pt(13)
    run_header.font.color.rgb = COLOR_PRIMARY_BLUE
    
    # 2. Main Title: AI-Powered Digital Forensics Copilot
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(18)
    run_title = p_title.add_run("AI-Powered Digital Forensics Copilot")
    run_title.bold = True
    run_title.font.size = Pt(28)
    run_title.font.color.rgb = COLOR_TITLE_NAVY
    
    # 3. Subtitle: A Local Retrieval-Augmented Generation (RAG) Assistant for Cyber Incident Response
    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(160) # Large vertical gap to center the logo/affiliation
    run_sub = p_sub.add_run("A Local Retrieval-Augmented Generation (RAG) Assistant for Cyber Incident Response")
    run_sub.italic = True
    run_sub.font.size = Pt(13.5)
    run_sub.font.color.rgb = COLOR_MUTED_GRAY
    
    # 4. Affiliation details at the bottom-middle
    p_affil = doc.add_paragraph()
    p_affil.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_affil.paragraph_format.space_after = Pt(48)
    p_affil.paragraph_format.line_spacing = 1.2
    
    run_affil1 = p_affil.add_run("Cyber Security Research Lab (CSRL)\n")
    run_affil1.bold = True
    run_affil1.font.size = Pt(11.5)
    run_affil1.font.color.rgb = COLOR_TITLE_NAVY
    
    run_affil2 = p_affil.add_run("Department of Computer Science and Engineering\n")
    run_affil2.bold = True
    run_affil2.font.size = Pt(11.5)
    run_affil2.font.color.rgb = COLOR_TITLE_NAVY
    
    run_affil3 = p_affil.add_run("National Institute of Technology Karnataka (NITK), Surathkal")
    run_affil3.bold = True
    run_affil3.font.size = Pt(11.5)
    run_affil3.font.color.rgb = COLOR_TITLE_NAVY
    
    # 5. Date: July 2026
    p_date = doc.add_paragraph()
    p_date.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_date.paragraph_format.space_before = Pt(20)
    run_date = p_date.add_run("July 2026")
    run_date.font.size = Pt(11)
    run_date.font.color.rgb = COLOR_MUTED_GRAY
    
    doc.add_page_break()

# =============================================================================
# DOCUMENT BUILDER
# =============================================================================

def build_unified_document(output_path: str):
    doc = Document()
    
    # Standard margins
    for s in doc.sections:
        s.top_margin = Inches(1.0)
        s.bottom_margin = Inches(1.0)
        s.left_margin = Inches(1.0)
        s.right_margin = Inches(1.0)
        
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(11)
    
    # Create cover page matching user's custom Nitk CSE layout
    create_styled_cover_page(doc)
    
    # ─────────────────────────────────────────────────────────────────────────
    # PART I: TECHNICAL REPORT
    # ─────────────────────────────────────────────────────────────────────────
    add_title_header(doc, "PART I: TECHNICAL REPORT")
    
    add_section_header(doc, "1. System Overview & Architecture")
    add_body(doc, 
             "The AI-Powered Digital Forensics Copilot is an offline-first incident response workstation "
             "designed to perform automated analysis of collected system evidence, verify chain of custody, "
             "and generate comprehensive digital forensics summaries without external internet connectivity. "
             "By utilizing local Retrieval-Augmented Generation (RAG) through Ollama, this toolkit guarantees "
             "strict confidentiality and privacy for corporate and forensic datasets.")
    
    add_body(doc, 
             "The system is designed with a three-tier architecture: the Presentation layer (featuring both "
             "a visual browser-based single-page application and a terminal CLI utility), the Application "
             "layer powered by a FastAPI ASGI server, and the Storage layer using standard local directory "
             "structures to hold logs, hashes, and evidence files.")

    # Purpose and Use
    add_sub_section_header(doc, "1.1 Purpose and Use of the Application")
    add_body(doc,
             "The primary purpose of the AI-Powered Digital Forensics Copilot is to serve as an offline, "
             "confidential incident response training and analysis assistant for security analysts, incident "
             "responders, and academic research labs (such as NITK's Cyber Security Research Lab). "
             "Traditional incident analysis workflows often depend on cloud APIs to process forensic telemetry; "
             "however, uploading sensitive network captures, system logs, or employee credentials violates "
             "confidentiality. The toolkit solves this privacy concern by keeping all telemetry parsing, "
             "hashing, and LLM synthesis strictly local (offline).")
             
    add_body(doc, "Specifically, the application is used to:")
    add_bullet(doc, "Establish and enforce evidence integrity by auto-comparing active SHA-256 hashes against a sealed baseline.")
    add_bullet(doc, "Synthesize multi-source forensic logs (VPN authentication logs, Linux system events, network firewall rules, and email feeds) into a unified chronological event timeline.")
    add_bullet(doc, "Implement Retrieval-Augmented Generation (RAG) using a locally compiled database of evidence snippets, allowing a local LLM (llama3.2:1b) to draft professional executive incident summaries offline.")

    # Target Cyber Security Incident Scenario
    add_sub_section_header(doc, "1.2 Target Cyber Security Incident Scenario")
    add_body(doc,
             "The toolkit is preloaded with simulated evidence files depicting a realistic 'Insider Threat / VPN Credential Compromise and Exfiltration' scenario targeting a Finance application server (SRV-FIN-01). The simulated attack chain follows these operational phases:")
    add_bullet(doc, "Failed Login Attempts & Compromise: Inbound VPN log files (vpn.log) show five failed login attempts for administrator accounts from rogue external IP 203.45.18.101 starting at 14:02:55. A successful authentication occurs for employee 'j.smith' at 14:20:22, starting an SSH session.")
    add_bullet(doc, "SSH Connection & Database Queries: Local host syslog events (system.log) record SSH login acceptance. At 14:22:17, a custom utility script 'finance_export.sh' executes SQL queries against a PostgreSQL database to extract billing logs and transactions.")
    add_bullet(doc, "Archive Compression: The dumped database credentials and tables are compressed into a single 45.2 MB archive file (/tmp/finance_export/archive.zip) at 14:23:51.")
    add_bullet(doc, "Command & Control Exfiltration: Active network firewall rules (firewall.log) and curl output verify the establishment of an HTTPS connection to suspicious external IP 198.51.100.20 on port 443. The archive.zip file is successfully uploaded/exfiltrated, completing at 14:31:10.")
    add_bullet(doc, "Lateral Reconnaissance Attempt: Following exfiltration, outbound SSH requests to external host 45.33.18.7 at 14:40:15 are dropped and logged as DENIED by firewall egress filters, preventing lateral spread.")
    
    add_body(doc,
             "The student or investigator is tasked with utilizing the Copilot to analyze these raw files, identify the timeline, check which files were modified/tampered, and let the local LLM generate a comprehensive forensic report.")

    # Directory Structure
    add_sub_section_header(doc, "1.3 Directory Layout & Filesystem Design")
    add_body(doc, "The workspace follows a modular filesystem layout supporting clean separation of modules:")
    dirs = [
        ("forensic_toolkit/",          "Core Python package containing analysis sub-modules"),
        ("web_gui/",                   "Static dashboard assets (HTML, CSS, JavaScript)"),
        ("Evidence/",                  "Target directory where forensic evidence logs are loaded"),
        ("Evidence_Backup/",           "Reference files used to restore logs during demonstration runs"),
        ("Hashes/",                    "Stores SHA-256 baseline references and verification logs"),
        ("Timeline/",                  "Output directory containing generated file modification timeline"),
        ("Reports/",                   "Investigation reports and integrity logs"),
        ("Logs/",                      "Audit trails capturing tool runtime events"),
        ("gui_app.py",                 "FastAPI backend entrypoint hosting HTTP endpoints"),
        ("start.bat / stop.bat",       "Lifecycle scripts for Windows execution"),
    ]
    for d, desc in dirs:
        add_bullet(doc, f"{d:<25} - {desc}")
        
    add_section_header(doc, "2. Technical Component Deep-Dive")
    add_body(doc, 
             "The toolkit is built on native Python modules complemented by high-performance third-party libraries. "
             "Below is the breakdown of key codebase files and their corresponding technical role:")
             
    add_sub_section_header(doc, "2.1 hashing.py (SHA-256 Hashing engine)")
    add_body(doc, 
             "Computes cryptographic signatures of evidence logs. It uses Python's native hashlib "
             "library to read files in 4,096-byte chunk blocks. This prevents RAM spikes when processing larger "
             "binary dumps. The baseline is stored as plaintext pairs mapping file name to hex digest.")
             
    add_sub_section_header(doc, "2.2 system_info.py (Host Profiling)")
    add_body(doc, 
             "Queries host attributes via the platform package. To retrieve detailed system memory attributes "
             "without third-party dependency flags on CLI execution, WMI is targeted through a subprocess-launched "
             "Powershell CLI call on Windows, falling back to traditional free/df system commands on Linux/Unix shells.")
             
    add_sub_section_header(doc, "2.3 timeline.py (Temporal Event Reconstruction)")
    add_body(doc, 
             "Collects file modification times (st_mtime) from the Evidence/ directory. Reconstructs a "
             "chronological order of file modifications. Helps identify correlation during security incidents.")
             
    add_sub_section_header(doc, "2.4 report.py & gui_app.py (AI Generation & Local RAG)")
    add_body(doc, 
             "Orchestrates report construction. Gathers the text of all files inside Evidence/ along with "
             "the calculated SHA-256 checksums and the chronological timeline. Packages this raw context "
             "into a system-instructed prompt sent to the local Ollama daemon on port 11434. Uses standard "
             "Python urllib libraries to query the Ollama REST API with a fallback routine to auto-inject "
             "metadata into a predefined template if the local model is unreachable.")

    add_section_header(doc, "3. API Endpoints Map")
    add_body(doc, "The FastAPI backend acts as an integration router exposing the following HTTP routes:")
    
    # API endpoints table
    api_tbl = doc.add_table(rows=1, cols=4)
    api_tbl.style = "Table Grid"
    api_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(["Method", "Endpoint", "Parameters", "Description"]):
        cell = api_tbl.rows[0].cells[j]
        set_cell_bg(cell, "4F6EF2")
        run = cell.paragraphs[0].add_run(h)
        run.bold = True
        run.font.color.rgb = COLOR_WHITE
        
    endpoints = [
        ("GET",  "/api/system_info",     "None", "Fetches host hardware stats, active RAM and disk utilization"),
        ("GET",  "/api/ollama_info",      "None", "Returns Ollama version, local models list, and port status"),
        ("GET",  "/api/processes",        "None", "Scans active process list to find running Ollama daemon processes"),
        ("GET",  "/api/artifacts",        "None", "Crawls ~/.ollama folder listing local model manifest files"),
        ("POST", "/api/hashing",          "None", "Computes and compares evidence signatures; handles baseline logic"),
        ("POST", "/api/timeline",         "None", "Parses timestamps and dumps chronological timeline sequence"),
        ("POST", "/api/report/generate",  "JSON payload", "Routinely queries local LLM model to generate investigation report"),
        ("GET",  "/api/report/get",       "None", "Loads generated Investigation_Report.md for front-end rendering")
    ]
    for method, route, params, desc in endpoints:
        row = api_tbl.add_row()
        row.cells[0].paragraphs[0].add_run(method).bold = True
        row.cells[1].paragraphs[0].add_run(route).font.name = "Courier New"
        row.cells[2].paragraphs[0].add_run(params).font.size = Pt(10)
        row.cells[3].paragraphs[0].add_run(desc).font.size = Pt(10)
    doc.add_paragraph()
    
    add_section_header(doc, "4. Verification Algorithm Design")
    add_body(doc, 
             "To maintain strict forensic auditability, the hashing system relies on automatic "
             "State Transition detection based on the presence of a baseline file. "
             "The logic flows according to the following state diagram:")
             
    # State diagram table representation
    add_code_block(doc, 
                   "                [ Compute SHA256 Hashes Clicked ]\n"
                   "                                |\n"
                   "                                v\n"
                   "                  / Hashes/sha256_hashes.txt \\\n"
                   "                 /        exists?             \\\n"
                   "                /                              \\\n"
                   "               [ NO ]                      [ YES ]\n"
                   "                 |                            |\n"
                   "                 v                            v\n"
                   "      [ FIRST-RUN / BASELINE ]       [ VERIFICATION-RUN ]\n"
                   "                 |                            |\n"
                   "                 |-- Generate hashes          |-- Generate hashes\n"
                   "                 |-- Save baseline            |-- Compare with baseline\n"
                   "                 |-- Status = verified        |-- Highlight mismatch as TAMPERED\n"
                   "                 v                            v\n"
                   "         [ Green Status Banner ]      [ Green/Red Alert Banner ]")
                   
    add_body(doc, 
             "This logic prevents the system from automatically overwriting previous records during "
             "a verification run, ensuring that unauthorized filesystem changes are flagged dynamically.")

    doc.add_page_break()

    # ─────────────────────────────────────────────────────────────────────────
    # PART II: OPERATION MANUAL
    # ─────────────────────────────────────────────────────────────────────────
    add_title_header(doc, "PART II: OPERATION MANUAL")
    
    add_section_header(doc, "1. Environment Setup & Installation")
    add_body(doc, "Ensure your system meets the minimum requirements before executing launch scripts:")
    add_bullet(doc, "Python: Python 3.10 or higher must be installed and added to the system PATH.")
    add_bullet(doc, "Node.js (Optional): Node.js v18.0.0 or higher (v20+ or v22+ LTS is recommended) can be installed. Note that the dashboard is served statically by the FastAPI server, so a Node runtime is not strictly required to run the application, but is recommended for environment alignment.")
    add_bullet(doc, "Ollama: Ollama Desktop must be installed locally (download from https://ollama.com).")
    add_bullet(doc, "Hardware: A minimum of 8 GB of RAM is recommended to run local inference (llama3.2:1b) and embedding (nomic-embed-text) models.")

    add_sub_section_header(doc, "1.1 Automatic Dependency Management (Windows)")
    add_body(doc, "The launch script automatically manages dependencies inside a local Python virtual environment (.venv) on Windows. It performs the following setup operations automatically on first launch:")
    add_bullet(doc, "Checks if a virtual environment exists. If it finds a Unix-style environment, it deletes it to prevent Windows run conflicts.")
    add_bullet(doc, "Creates a native Windows virtual environment (.venv) using the system python.")
    add_bullet(doc, "Upgrades pip and automatically installs uvicorn, fastapi, langchain, chromadb, and other required packages listed in requirements.txt.")

    add_sub_section_header(doc, "1.2 Manual Dependency Installation (Fallback / Non-Windows)")
    add_body(doc, "On non-Windows systems, navigate to the project directory and install the packages manually using:")
    add_code_block(doc, "pip install -r requirements.txt")

    add_sub_section_header(doc, "1.3 Fetching the LLM & Embedding Models")
    add_body(doc, "The start.bat script automatically checks and pulls the required Ollama models. If you are running manually, you must pull them using:")
    add_code_block(doc, "ollama pull llama3.2:1b\nollama pull nomic-embed-text")
    
    add_section_header(doc, "2. Execution & Lifecycle")
    add_body(doc, "The application can be started using the provided batch execution wrappers or direct terminal commands.")

    add_sub_section_header(doc, "2.1 Windows One-Click Launch (Recommended)")
    add_body(doc, "Simply double-click or run the start.bat wrapper script located in the repository root directory:")
    add_code_block(doc, "start.bat")
    add_body(doc, 
             "This script is fully automated and robust. It performs Python version checks, builds/updates "
             "the local virtual environment, installs dependencies, verifies the Ollama service status, "
             "automatically pulls missing models (llama3.2:1b and nomic-embed-text), launches the "
             "browser at http://127.0.0.1:8000, and starts the FastAPI backend server using the .venv environment.")

    add_sub_section_header(doc, "2.2 Stopping the workstation")
    add_body(doc, "To stop uvicorn and background listeners cleanly, run the stop.bat script or press Ctrl+C inside the terminal window.")

    add_section_header(doc, "3. Interface Step-by-Step Operation Guide")
    
    add_sub_section_header(doc, "3.1 Dashboard & Live Sockets")
    add_body(doc, 
             "Upon loading, the workstation home tab profiles host CPU usage, RAM utilization, and disk partitions. "
             "Additionally, it verifies whether the Ollama socket (port 11434) is reachable, giving investigators "
             "immediate status reports on RAG availability.")
             
    add_sub_section_header(doc, "3.2 Artifact Discovery")
    add_body(doc, 
             "Select the 'Artifact Discovery' tab to inspect details about local LLM files. The toolkit crawls "
             "the ~/.ollama local database, outputting a listing of model layers, sizes, and binary artifacts "
             "stored on disk.")
             
    add_sub_section_header(doc, "3.3 Chronological Timeline Generator")
    add_body(doc, 
             "Navigate to the 'Hashes & Timeline' tab. Click the 'Build Forensic Timeline' button. "
             "The system parses timestamps on files inside the Evidence/ folder and displays them "
             "in a vertical chronological event feed. The generated output is written to Timeline/timeline.txt.")

    add_section_header(doc, "4. Tamper Detection Walkthrough")
    add_body(doc, 
             "To demonstrate the evidence verification and integrity check capabilities, follow this step-by-step workflow:")

    add_callout(doc, "Step 1: Baseline Establishment", 
                "Open the 'Hashes & Timeline' tab and click the 'Compute SHA256 Hashes' button. "
                "The system displays a green banner indicating 'BASELINE RECORDED'. "
                "All 9 logs inside the Evidence/ directory are cataloged, and their hash values are written to Hashes/sha256_hashes.txt.",
                icon="📊")

    add_callout(doc, "Step 2: Simulate File Modification", 
                "Open a text editor (e.g. Notepad) and edit any log file directly inside the Evidence/ directory "
                "(for example, edit Evidence/vpn.log by adding a space character to the last line). Save the file.",
                icon="✏️", hex_bg="FFF7ED")

    add_callout(doc, "Step 3: Verification Execution", 
                "Return to the browser dashboard and click the 'Compute SHA256 Hashes' button again. "
                "The system runs a verification scan. It highlights the modified log row in red with a status of 'TAMPERED'. "
                "It displays a warning banner and shows both the modified hash value and the original baseline hash value side-by-side for comparison.",
                icon="🚨", hex_bg="FEF2F2")

    add_callout(doc, "Step 4: Restoring the Files", 
                "To reset the workshop environment, copy the pristine copy from Evidence_Backup/vpn.log "
                "and overwrite Evidence/vpn.log. Running the hash calculation again will restore the status to 'Verified'.",
                icon="🔄")

    add_section_header(doc, "5. AI Incident Report Generation")
    add_body(doc, 
             "Once the timeline and hashes are computed, select the 'AI Incident Copilot' tab to generate a final report:")
    add_bullet(doc, "Select your active local model from the dropdown menu (e.g., llama3.2:1b).")
    add_bullet(doc, "Click the 'Generate AI Incident Report' button.")
    add_bullet(doc, "The backend gathers the contents of all files in Evidence/, compares them with the baseline hashes and timelines, and queries the local LLM. A markdown-formatted report is returned to the dashboard.")
    add_bullet(doc, "The report is saved locally as Reports/Investigation_Report.md for offline access.")

    add_section_header(doc, "6. Troubleshooting Guide")
    add_callout(doc, "Ollama is Offline", 
                "If the status shows red/inactive, open a command prompt and run 'ollama serve'. "
                "Ensure that the model is pulled using 'ollama pull llama3.2:1b'.", 
                icon="⚠️", hex_bg="FEF2F2")
    add_callout(doc, "No Models Listed in Dropdown", 
                "Refresh the dashboard. If the list is still empty, double check that your Ollama installation "
                "is running and reachable. Verify by running 'ollama list' in a terminal.", 
                icon="⚠️", hex_bg="FFF7ED")
    add_callout(doc, "Tampering Not Detected", 
                "Ensure you edited the files inside the Evidence/ folder, not the reference files in Evidence_Backup/.", 
                icon="💡", hex_bg="F0FDF4")

    doc.save(output_path)
    print(f"[OK] Unified Manual saved to: {output_path}")

if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    docs_dir = os.path.join(base, "Docs")
    os.makedirs(docs_dir, exist_ok=True)
    
    unified_path = os.path.join(docs_dir, "Technical_Report_and_Operation_Manual_Unified.docx")
    build_unified_document(unified_path)
