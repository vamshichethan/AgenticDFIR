"""
Document Generator — Technical Report + User Manual
AI Cyber Forensics Workshop Toolkit
"""

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from datetime import datetime
import os

# ── colour palette ────────────────────────────────────────────────────────────
DARK_NAVY   = RGBColor(0x07, 0x09, 0x13)   # #070913 — app bg
CYAN        = RGBColor(0x06, 0xB6, 0xD4)   # #06b6d4
PURPLE      = RGBColor(0xA8, 0x55, 0xF7)   # #a855f7
WHITE       = RGBColor(0xFF, 0xFF, 0xFF)
DARK_TEXT   = RGBColor(0x1E, 0x20, 0x30)   # near-black for body text
LIGHT_GREY  = RGBColor(0xF3, 0xF4, 0xF6)
MID_GREY    = RGBColor(0x6B, 0x72, 0x80)
RED         = RGBColor(0xEF, 0x44, 0x44)
GREEN       = RGBColor(0x10, 0xB9, 0x81)
YELLOW      = RGBColor(0xF5, 0x9E, 0x0B)


# ── helpers ───────────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color: str):
    """Set table cell background colour."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def add_horizontal_rule(doc, color="CCCCCC"):
    """Add a horizontal line paragraph."""
    p = doc.add_paragraph()
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "6")
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), color)
    pBdr.append(bottom)
    pPr.append(pBdr)
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(4)
    return p


def h1(doc, text, color=DARK_NAVY):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(24)
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(20)
    run.font.color.rgb = color
    return p


def h2(doc, text, color=DARK_NAVY):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(14)
    run.font.color.rgb = color
    add_horizontal_rule(doc, "06B6D4")
    return p


def h3(doc, text, color=DARK_NAVY):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(2)
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(12)
    run.font.color.rgb = color
    return p


def body(doc, text, bold_parts=None):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(text)
    run.font.size = Pt(11)
    run.font.color.rgb = DARK_TEXT
    return p


def bullet(doc, text, level=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.left_indent = Inches(0.25 * (level + 1))
    run = p.add_run(text)
    run.font.size = Pt(11)
    run.font.color.rgb = DARK_TEXT
    return p


def code_block(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.left_indent = Inches(0.4)
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x06, 0xB6, 0xD4)
    return p


def info_box(doc, label, text, label_color=CYAN):
    """A coloured callout box."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
    cell = tbl.rows[0].cells[0]
    set_cell_bg(cell, "EFF6FF")
    cell.width = Inches(6)
    p = cell.paragraphs[0]
    run_lbl = p.add_run(f"{label}  ")
    run_lbl.bold = True
    run_lbl.font.size = Pt(11)
    run_lbl.font.color.rgb = label_color
    run_txt = p.add_run(text)
    run_txt.font.size = Pt(11)
    run_txt.font.color.rgb = DARK_TEXT
    doc.add_paragraph()   # spacer


def cover_page(doc, title, subtitle, author, date_str, version):
    """Build a styled cover page."""
    # Coloured banner table
    banner = doc.add_table(rows=1, cols=1)
    banner.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = banner.rows[0].cells[0]
    set_cell_bg(cell, "070913")
    cell.width = Inches(7)
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(30)
    p.paragraph_format.space_after = Pt(30)

    r = p.add_run("🔐  AI CYBER FORENSICS WORKSHOP")
    r.bold = True
    r.font.size = Pt(22)
    r.font.color.rgb = CYAN

    doc.add_paragraph()

    # Title
    pt = doc.add_paragraph()
    pt.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pt.paragraph_format.space_before = Pt(16)
    rt = pt.add_run(title)
    rt.bold = True
    rt.font.size = Pt(26)
    rt.font.color.rgb = DARK_NAVY

    # Subtitle
    ps = doc.add_paragraph()
    ps.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rs = ps.add_run(subtitle)
    rs.font.size = Pt(14)
    rs.font.color.rgb = MID_GREY

    doc.add_paragraph()
    add_horizontal_rule(doc, "06B6D4")
    doc.add_paragraph()

    # Meta table
    meta = doc.add_table(rows=4, cols=2)
    meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    labels = ["Author", "Version", "Date", "Subject"]
    values = [author, version, date_str, "Digital Forensics & AI — Workshop Project"]
    for i, (lbl, val) in enumerate(zip(labels, values)):
        row = meta.rows[i]
        lc = row.cells[0]
        vc = row.cells[1]
        set_cell_bg(lc, "F0FDFF")
        lp = lc.paragraphs[0]
        lr = lp.add_run(lbl)
        lr.bold = True
        lr.font.color.rgb = CYAN
        lr.font.size = Pt(11)
        vp = vc.paragraphs[0]
        vr = vp.add_run(val)
        vr.font.size = Pt(11)
        vr.font.color.rgb = DARK_TEXT

    doc.add_page_break()


# =============================================================================
# TECHNICAL REPORT
# =============================================================================

def build_technical_report(output_path: str):
    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin = Cm(2.5)
        section.bottom_margin = Cm(2.5)
        section.left_margin = Cm(3)
        section.right_margin = Cm(2.5)

    # Default font
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(11)

    cover_page(
        doc,
        title="Technical Report",
        subtitle="AI Cyber Forensics Toolkit — Design, Architecture & Implementation",
        author="CSRL Workshop Team",
        date_str=datetime.now().strftime("%d %B %Y"),
        version="v1.0"
    )

    # ── 1. Executive Overview ──────────────────────────────────────────────────
    h1(doc, "1. Executive Overview")
    body(doc,
         "The AI Cyber Forensics Toolkit is a full-stack, offline-first digital forensic analysis "
         "platform developed for the CSRL Cyber Security & AI Workshop. It provides investigators, "
         "students, and researchers with a unified environment to perform evidence acquisition, "
         "SHA-256 integrity verification, chronological timeline reconstruction, process and system "
         "monitoring, LLM artifact discovery, and AI-assisted incident report generation — all "
         "without any internet dependency.")
    body(doc,
         "The project is delivered in two complementary interfaces: a browser-based Web Dashboard "
         "served by a FastAPI backend, and a traditional terminal-based CLI application. Both "
         "interfaces share the same underlying Python forensic_toolkit library, ensuring "
         "consistency and code reuse.")

    # ── 2. System Architecture ────────────────────────────────────────────────
    h1(doc, "2. System Architecture")

    h2(doc, "2.1 High-Level Architecture")
    body(doc,
         "The system follows a three-tier architecture comprising a Presentation Layer (Web GUI / CLI), "
         "an Application Layer (FastAPI REST API), and a Data/Storage Layer (local filesystem).")

    # Architecture table
    arch_tbl = doc.add_table(rows=4, cols=3)
    arch_tbl.style = "Table Grid"
    arch_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Tier", "Component", "Technology"]
    rows_data = [
        ("Presentation", "Web Dashboard", "HTML5 · Vanilla CSS · JavaScript (ES2022)"),
        ("Application", "REST API Backend", "Python 3.x · FastAPI · Uvicorn ASGI"),
        ("Application", "CLI Interface", "Python 3.x · forensic_toolkit package"),
        ("Data / Storage", "Evidence & Outputs", "Local filesystem (Evidence/, Hashes/, Timeline/, Reports/, Logs/)"),
    ]
    for j, h in enumerate(headers):
        cell = arch_tbl.rows[0].cells[j]
        set_cell_bg(cell, "070913")
        run = cell.paragraphs[0].add_run(h)
        run.bold = True
        run.font.color.rgb = CYAN
        run.font.size = Pt(11)

    for i, (t, c, tech) in enumerate(rows_data, 1):
        row = arch_tbl.add_row()
        row.cells[0].paragraphs[0].add_run(t).font.size = Pt(10)
        row.cells[1].paragraphs[0].add_run(c).font.size = Pt(10)
        row.cells[2].paragraphs[0].add_run(tech).font.size = Pt(10)
    doc.add_paragraph()

    h2(doc, "2.2 Directory Structure")
    body(doc, "The repository is organised as follows:")
    dirs = [
        ("AI-Cyber-Forensics-Workshop/", "Repository root"),
        ("  forensic_toolkit/",          "Core Python library — all forensic modules"),
        ("  web_gui/",                   "Static Web Dashboard (index.html · style.css · app.js)"),
        ("  Evidence/",                  "Simulated evidence files for analysis"),
        ("  Evidence_Backup/",           "Original copies used for reference"),
        ("  Hashes/",                    "Saved SHA-256 baselines & verification logs"),
        ("  Timeline/",                  "Chronological timeline output files"),
        ("  Reports/",                   "Generated Markdown investigation reports"),
        ("  Logs/",                      "Investigation audit trail (investigation.log)"),
        ("  Docs/",                      "Documentation assets"),
        ("  gui_app.py",                 "FastAPI application entry point"),
        ("  forensic_toolkit/main.py",   "CLI entry point"),
        ("  start.bat",                  "One-click launcher (Windows)"),
    ]
    for path, desc in dirs:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.3)
        p.paragraph_format.space_after = Pt(2)
        r1 = p.add_run(f"{path:<42}")
        r1.font.name = "Courier New"
        r1.font.size = Pt(9)
        r1.font.color.rgb = CYAN
        r2 = p.add_run(f"  {desc}")
        r2.font.size = Pt(10)
        r2.font.color.rgb = MID_GREY

    # ── 3. Technology Stack ───────────────────────────────────────────────────
    h1(doc, "3. Technology Stack")

    stack_tbl = doc.add_table(rows=1, cols=4)
    stack_tbl.style = "Table Grid"
    stack_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(["Category", "Technology", "Version", "Purpose"]):
        cell = stack_tbl.rows[0].cells[j]
        set_cell_bg(cell, "0D0F21")
        run = cell.paragraphs[0].add_run(h)
        run.bold = True
        run.font.color.rgb = CYAN
        run.font.size = Pt(10)

    stack_data = [
        ("Backend Language", "Python",       "3.10+",   "Core application logic & forensic modules"),
        ("Web Framework",    "FastAPI",       "0.115+",  "REST API, automatic OpenAPI docs"),
        ("ASGI Server",      "Uvicorn",       "0.34+",   "High-performance async HTTP server"),
        ("System Metrics",   "psutil",        "6.x",     "CPU, RAM, Disk, Process monitoring"),
        ("Frontend",         "HTML5 + CSS3",  "—",       "Responsive single-page dashboard"),
        ("Frontend JS",      "Vanilla ES2022","—",       "Async fetch, DOM manipulation"),
        ("Fonts",            "Plus Jakarta Sans + JetBrains Mono", "—", "UI typography"),
        ("Icons",            "Material Icons Round", "—","Navigation & action icons"),
        ("Hashing",          "hashlib (SHA-256)", "stdlib", "Evidence integrity verification"),
        ("Local AI",         "Ollama",        "Any",     "Offline LLM inference engine"),
        ("Recommended LLM",  "llama3.2:1b",   "Any",     "Forensic report generation"),
        ("Doc Generation",   "python-docx",   "1.2+",    "Automated report & manual export"),
    ]
    for cat, tech, ver, purpose in stack_data:
        row = stack_tbl.add_row()
        for j, val in enumerate([cat, tech, ver, purpose]):
            row.cells[j].paragraphs[0].add_run(val).font.size = Pt(10)
    doc.add_paragraph()

    # ── 4. Forensic Toolkit Modules ───────────────────────────────────────────
    h1(doc, "4. Forensic Toolkit Modules")
    body(doc,
         "All forensic logic is encapsulated within the forensic_toolkit Python package. "
         "Each module has a single responsibility, making the codebase maintainable and extensible.")

    modules = [
        ("hashing.py",      "SHA-256 Hash Generator",
         "Implements calculate_sha256(file_path) using Python's built-in hashlib library. "
         "Reads files in 4 096-byte chunks to handle large binary files without memory issues. "
         "The hash_menu() function provides an interactive CLI interface that iterates over all "
         "files in the Evidence/ directory and saves digests to Hashes/sha256_hashes.txt."),

        ("system_info.py",  "System Information Collector",
         "Collects host metadata using Python's platform module: hostname, OS name and release, "
         "kernel version, CPU architecture, and processor model. On Windows, PowerShell is used "
         "to query physical memory via WMI (Get-CimInstance Win32_PhysicalMemory). The Web API "
         "supplements this with real-time CPU%, RAM%, and disk usage from psutil."),

        ("ollama_info.py",  "Ollama LLM Environment Inspector",
         "Locates the Ollama executable using shutil.which() and known Windows installation paths "
         "(%LOCALAPPDATA%\\Programs\\Ollama\\ollama.exe). Checks whether the ollama process is "
         "running via tasklist/pgrep, and whether port 11434 is listening. Enumerates installed "
         "models by calling the Ollama REST API (GET /api/tags)."),

        ("artifacts.py",    "AI Artifact Discovery",
         "Scans the user's ~/.ollama directory using os.walk() to enumerate all cached model "
         "manifest and blob files. Reports file names, full paths, and sizes in MB. "
         "This provides investigators with a complete picture of locally stored AI model artefacts."),

        ("process_info.py", "Running Process Investigation",
         "Queries the operating system for active Ollama-related processes using tasklist/pgrep "
         "and netstat, identifying PIDs and open TCP ports. The Web API uses psutil.process_iter() "
         "for structured JSON output including CPU% and RSS memory usage per process."),

        ("timeline.py",     "Forensic File Timeline Generator",
         "Iterates over the Evidence/ directory and extracts st_mtime (last-modified timestamp) "
         "from each file's os.stat() result. Events are sorted chronologically and written to "
         "Timeline/timeline.txt, providing a chain-of-custody-friendly modification timeline."),

        ("report.py",       "AI-Assisted Incident Report Generator",
         "Orchestrates evidence reading, hash loading, and timeline loading into a structured "
         "LLM prompt sent to the local Ollama /api/generate endpoint (POST, timeout 120 s). "
         "If Ollama is offline the module falls back to a Markdown template populated with "
         "the available evidence metadata. Reports are saved to Reports/Investigation_Report.md."),

        ("utils.py",        "Shared Utilities",
         "Provides PROJECT_ROOT path resolution and the log(message) function which appends "
         "timestamped audit entries to Logs/investigation.log."),
    ]

    for filename, title, description in modules:
        h3(doc, f"4.{modules.index((filename, title, description))+1}  {filename} — {title}")
        body(doc, description)

    # ── 5. Web API Endpoints ──────────────────────────────────────────────────
    h1(doc, "5. Web API Endpoints")
    body(doc,
         "The FastAPI backend (gui_app.py) exposes the following RESTful endpoints. "
         "Interactive documentation is available at http://127.0.0.1:8000/docs when the server is running.")

    api_tbl = doc.add_table(rows=1, cols=4)
    api_tbl.style = "Table Grid"
    api_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h_text in enumerate(["Method", "Endpoint", "Auth", "Description"]):
        cell = api_tbl.rows[0].cells[j]
        set_cell_bg(cell, "0D0F21")
        run = cell.paragraphs[0].add_run(h_text)
        run.bold = True
        run.font.color.rgb = CYAN
        run.font.size = Pt(10)

    endpoints = [
        ("GET",    "/api/system_info",      "None", "Returns hostname, OS, CPU%, RAM%, disk usage"),
        ("GET",    "/api/ollama_info",       "None", "Returns Ollama version, installed models, service/port status"),
        ("GET",    "/api/processes",         "None", "Lists active Ollama processes with PID, CPU%, RAM"),
        ("GET",    "/api/artifacts",         "None", "Scans ~/.ollama for model blob files"),
        ("POST",   "/api/hashing",           "None", "Compute SHA-256 for all Evidence/ files; auto-detects first vs verification run"),
        ("POST",   "/api/report/integrity",  "None", "Generate a Markdown evidence integrity report"),
        ("POST",   "/api/timeline",          "None", "Build chronological timeline from Evidence/ file timestamps"),
        ("POST",   "/api/report/generate",   "JSON body: {model}", "Generate AI incident report via Ollama; falls back to template if offline"),
        ("GET",    "/api/report/get",        "None", "Retrieve the last generated Investigation_Report.md"),
        ("GET",    "/",                      "None", "Serve the static Web Dashboard (index.html)"),
    ]

    method_colors = {"GET": "1E7E34", "POST": "0C5460", "DELETE": "721C24"}

    for method, endpoint, auth, desc in endpoints:
        row = api_tbl.add_row()
        mc = row.cells[0]
        set_cell_bg(mc, method_colors.get(method, "333333"))
        mr = mc.paragraphs[0].add_run(method)
        mr.bold = True
        mr.font.color.rgb = WHITE
        mr.font.size = Pt(10)

        for j, val in enumerate([endpoint, auth, desc], 1):
            r = row.cells[j].paragraphs[0].add_run(val)
            r.font.size = Pt(9)
            if j == 1:
                r.font.name = "Courier New"
                r.font.color.rgb = CYAN
    doc.add_paragraph()

    # ── 6. Evidence Integrity Verification ────────────────────────────────────
    h1(doc, "6. Evidence Integrity Verification — Algorithm")

    h2(doc, "6.1 SHA-256 Hashing Methodology")
    body(doc,
         "SHA-256 (Secure Hash Algorithm 256-bit) is a one-way cryptographic hash function "
         "that produces a deterministic 64-character hexadecimal digest for any given input. "
         "Even a single-bit change in the source file produces a completely different digest "
         "(avalanche effect), making it ideal for tamper detection in digital forensics.")

    h2(doc, "6.2 First-Run vs Verification-Run Logic")
    body(doc, "The /api/hashing endpoint implements a two-phase workflow:")

    steps = [
        ("Phase 1 — Baseline Recording (First Run)",
         "When Hashes/sha256_hashes.txt does not exist or is empty, the system is in "
         "first-run mode. SHA-256 digests are computed for every file in Evidence/ and "
         "saved to Hashes/sha256_hashes.txt in the format: <filename>\\n<digest>\\n\\n. "
         "All files are reported as status: verified."),
        ("Phase 2 — Verification Run (Subsequent Runs)",
         "When a baseline file exists and is non-empty, each file's current digest is "
         "compared against the stored baseline. If the digests match, status is verified. "
         "If they differ, status is tampered and the UI highlights the file in red. "
         "New files not present in the baseline receive status new. "
         "Results are written to Hashes/sha256_hashes_verification.txt."),
    ]
    for phase, text in steps:
        h3(doc, phase)
        body(doc, text)

    h2(doc, "6.3 Baseline File Format")
    code_block(doc, "email_thread.txt")
    code_block(doc, "848645ae2cc7e016de8f7033950daf26a2d87efae800c8ad5f5b6f5eb2644a4e")
    code_block(doc, "")
    code_block(doc, "firewall.log")
    code_block(doc, "2b31b846737a5aaa661ba11b52cab5a8432567a27d3bea35f78907ab539ae70a")
    code_block(doc, "...")

    # ── 7. AI Integration ─────────────────────────────────────────────────────
    h1(doc, "7. AI Integration — Ollama Offline LLM")

    h2(doc, "7.1 Architecture")
    body(doc,
         "The toolkit integrates with Ollama — a locally hosted LLM runtime. All AI inference "
         "runs entirely on the user's machine with no internet connection required, satisfying "
         "data privacy and chain-of-custody requirements in forensic contexts.")
    body(doc,
         "Communication is via Ollama's local REST API at http://localhost:11434. "
         "The toolkit sends a POST request to /api/generate with stream: false and a 120-second "
         "timeout. If the service is unavailable, the fallback template report is generated instead.")

    h2(doc, "7.2 Prompt Engineering")
    body(doc,
         "The forensic prompt instructs the model to act as a Senior DFIR Specialist and produce "
         "a structured Markdown report with five sections: Executive Summary, Evidence Acquisition "
         "& Integrity, Timeline of Events, Key Findings & Analysis, and Recommendations & "
         "Incident Response Action Plan. The prompt includes the full content of all evidence "
         "files, SHA-256 hash records, and the chronological timeline.")

    h2(doc, "7.3 Recommended Model")
    body(doc,
         "llama3.2:1b is recommended for workshop use due to its low resource footprint (~800 MB "
         "RAM). Install with: ollama pull llama3.2:1b. Larger models (llama3.2:3b, mistral, "
         "gemma2) can be used for higher-quality reports if system resources permit.")

    # ── 8. Security Considerations ────────────────────────────────────────────
    h1(doc, "8. Security & Privacy Considerations")
    bullets = [
        "All processing is strictly local — no data leaves the machine.",
        "The Ollama inference endpoint binds to localhost (127.0.0.1:11434) by default.",
        "The FastAPI server binds to 127.0.0.1:8000 — not accessible from the network.",
        "Evidence files are read-only during analysis; the toolkit does not modify them.",
        "SHA-256 baselines are stored in plaintext for auditability — protect the Hashes/ directory.",
        "The investigation.log provides a timestamped audit trail of all actions performed.",
    ]
    for b in bullets:
        bullet(doc, b)

    # ── 9. Performance Characteristics ───────────────────────────────────────
    h1(doc, "9. Performance Characteristics")
    perf_data = [
        ("System Info API", "< 1 second",   "psutil call, single OS query"),
        ("SHA-256 Hashing (9 evidence files)", "< 0.5 seconds", "hashlib, 4 KB chunk read"),
        ("Timeline Generation", "< 0.2 seconds", "os.stat() on each file"),
        ("AI Report Generation", "30 – 300 seconds", "Dependent on model size & hardware"),
        ("Web Dashboard Load", "< 1 second", "Static HTML/CSS/JS, no external CDN"),
    ]
    perf_tbl = doc.add_table(rows=1, cols=3)
    perf_tbl.style = "Table Grid"
    for j, h_text in enumerate(["Operation", "Typical Duration", "Notes"]):
        cell = perf_tbl.rows[0].cells[j]
        set_cell_bg(cell, "0D0F21")
        run = cell.paragraphs[0].add_run(h_text)
        run.bold = True
        run.font.color.rgb = CYAN
        run.font.size = Pt(10)
    for op, dur, note in perf_data:
        row = perf_tbl.add_row()
        for j, val in enumerate([op, dur, note]):
            row.cells[j].paragraphs[0].add_run(val).font.size = Pt(10)
    doc.add_paragraph()

    # ── 10. Conclusion ────────────────────────────────────────────────────────
    h1(doc, "10. Conclusion")
    body(doc,
         "The AI Cyber Forensics Toolkit delivers a production-quality, fully offline digital "
         "forensic analysis platform suited for academic workshops, security training, and "
         "introductory DFIR exercises. Its modular Python architecture ensures each forensic "
         "capability is independently testable and extensible. The dual-interface design "
         "(Web Dashboard + CLI) accommodates both visual learners and command-line practitioners, "
         "while the Ollama integration demonstrates responsible, privacy-preserving AI deployment "
         "in sensitive investigative contexts.")
    body(doc,
         "Future enhancements may include network packet capture analysis, Windows Registry "
         "artefact parsing, memory forensics integration, and multi-model comparison for "
         "AI-generated reports.")

    doc.save(output_path)
    print(f"[OK] Technical Report saved: {output_path}")


# =============================================================================
# USER MANUAL
# =============================================================================

def build_user_manual(output_path: str):
    doc = Document()

    for section in doc.sections:
        section.top_margin = Cm(2.5)
        section.bottom_margin = Cm(2.5)
        section.left_margin = Cm(3)
        section.right_margin = Cm(2.5)

    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(11)

    cover_page(
        doc,
        title="User Manual",
        subtitle="AI Cyber Forensics Toolkit — Step-by-Step Operation Guide",
        author="CSRL Workshop Team",
        date_str=datetime.now().strftime("%d %B %Y"),
        version="v1.0"
    )

    # ── Table of Contents hint ────────────────────────────────────────────────
    h1(doc, "Table of Contents")
    toc_items = [
        "1. Introduction & Overview",
        "2. System Requirements",
        "3. Installation & First-Time Setup",
        "4. Starting the Application",
        "5. Web Dashboard — Tab-by-Tab Guide",
        "   5.1  Security Dashboard",
        "   5.2  Artifact Discovery",
        "   5.3  Hashes & Timeline",
        "   5.4  AI Incident Copilot",
        "6. Step-by-Step: Tamper Detection Demo",
        "7. CLI Interface Guide",
        "8. Understanding the Output Files",
        "9. Troubleshooting",
        "10. Frequently Asked Questions",
    ]
    for item in toc_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        run = p.add_run(item)
        run.font.size = Pt(11)
        run.font.color.rgb = DARK_TEXT
        if item.startswith("   "):
            p.paragraph_format.left_indent = Inches(0.4)

    doc.add_page_break()

    # ── 1. Introduction ───────────────────────────────────────────────────────
    h1(doc, "1. Introduction & Overview")
    body(doc,
         "Welcome to the AI Cyber Forensics Toolkit. This tool is designed for the CSRL Workshop "
         "to help students and practitioners learn the fundamentals of digital forensics investigation "
         "using a real, working software environment.")
    body(doc,
         "The toolkit allows you to:")
    capabilities = [
        "Monitor live system resources (CPU, RAM, Disk) in real time",
        "Discover locally installed AI (Ollama) model artefacts and processes",
        "Compute and verify SHA-256 cryptographic hashes of evidence files to detect tampering",
        "Build a chronological timeline of evidence file activity",
        "Generate professional forensic investigation reports using a local AI model (Ollama)",
    ]
    for cap in capabilities:
        bullet(doc, cap)

    info_box(doc, "ℹ️  Note:",
             "All operations run entirely on your local machine. No data is sent to the internet.",
             CYAN)

    # ── 2. System Requirements ────────────────────────────────────────────────
    h1(doc, "2. System Requirements")

    req_tbl = doc.add_table(rows=1, cols=3)
    req_tbl.style = "Table Grid"
    for j, h_text in enumerate(["Component", "Minimum", "Recommended"]):
        cell = req_tbl.rows[0].cells[j]
        set_cell_bg(cell, "070913")
        run = cell.paragraphs[0].add_run(h_text)
        run.bold = True
        run.font.color.rgb = CYAN
        run.font.size = Pt(11)
    reqs = [
        ("Operating System", "Windows 10 (64-bit)", "Windows 11 (64-bit)"),
        ("Python",           "3.10",                "3.11 or 3.12"),
        ("RAM",              "4 GB",                "8 GB+ (for AI report generation)"),
        ("Disk Space",       "1 GB free",           "5 GB+ (for LLM model files)"),
        ("CPU",              "Dual-core 2 GHz",     "Quad-core 3 GHz+"),
        ("Browser",          "Any modern browser",  "Chrome / Edge (latest)"),
        ("Ollama (optional)","Latest release",       "Latest release + llama3.2:1b"),
    ]
    for comp, mini, rec in reqs:
        row = req_tbl.add_row()
        for j, val in enumerate([comp, mini, rec]):
            r = row.cells[j].paragraphs[0].add_run(val)
            r.font.size = Pt(11)
    doc.add_paragraph()

    # ── 3. Installation ───────────────────────────────────────────────────────
    h1(doc, "3. Installation & First-Time Setup")

    h2(doc, "3.1 Python Dependencies")
    body(doc, "Open a Command Prompt or PowerShell window in the project directory and run:")
    code_block(doc, "pip install fastapi uvicorn psutil python-docx")
    body(doc, "If you are using a virtual environment (recommended):")
    code_block(doc, "python -m venv .venv")
    code_block(doc, ".venv\\Scripts\\activate")
    code_block(doc, "pip install fastapi uvicorn psutil python-docx")

    h2(doc, "3.2 Installing Ollama (Optional — Required for AI Reports)")
    body(doc,
         "1.  Download Ollama from https://ollama.com and install it.")
    body(doc,
         "2.  Open a terminal and pull the recommended model:")
    code_block(doc, "ollama pull llama3.2:1b")
    body(doc,
         "3.  Verify the installation:")
    code_block(doc, "ollama list")
    info_box(doc, "⚠️  Without Ollama:",
             "The toolkit will still work fully. AI report generation will use a template "
             "fallback instead of a live LLM response.",
             YELLOW)

    # ── 4. Starting the Application ───────────────────────────────────────────
    h1(doc, "4. Starting the Application")

    h2(doc, "4.1 One-Click Start (Recommended — Windows)")
    body(doc, "Double-click start.bat in the project root. It will:")
    bullet(doc, "Start the Ollama service in the background (if installed)")
    bullet(doc, "Launch your default web browser at http://127.0.0.1:8000")
    bullet(doc, "Start the FastAPI backend server on port 8000")

    h2(doc, "4.2 Manual Start")
    body(doc, "If you prefer to start manually:")
    code_block(doc, "# 1. (Optional) Start Ollama service")
    code_block(doc, "ollama serve")
    code_block(doc, "")
    code_block(doc, "# 2. Start the FastAPI server")
    code_block(doc, "python -m uvicorn gui_app:app --host 127.0.0.1 --port 8000")
    code_block(doc, "")
    code_block(doc, "# 3. Open browser at http://127.0.0.1:8000")

    h2(doc, "4.3 Stopping the Application")
    body(doc, "Double-click stop.bat, or press Ctrl+C in the terminal running uvicorn.")

    # ── 5. Web Dashboard ──────────────────────────────────────────────────────
    h1(doc, "5. Web Dashboard — Tab-by-Tab Guide")
    body(doc,
         "The dashboard is a single-page application with four tabs accessible from the "
         "left sidebar. The header always shows the current OS, live CPU%, and RAM%.")

    # 5.1 Security Dashboard
    h2(doc, "5.1  🖥️  Security Dashboard")
    body(doc,
         "The first tab loads automatically and displays real-time system information. "
         "It refreshes every 3 seconds.")

    dash_items = [
        ("System Information card",
         "Shows Hostname, Operating System, OS Version, Architecture, and Processor model."),
        ("Hardware Utilization card",
         "Shows animated progress bars for CPU usage (%), Memory usage (used GB / total GB), "
         "and Primary Disk usage (% used, free GB)."),
        ("Active Ollama Processes table",
         "Lists any running ollama.exe processes with their PID, CPU%, and RAM in MB. "
         "If Ollama is not running, the table displays a 'No processes detected' message."),
        ("Network Sockets card",
         "Shows whether port 11434 (Ollama's default API port) is actively listening. "
         "A green dot means Ollama is reachable; a red dot means it is offline."),
        ("Sidebar Ollama status",
         "The bottom-left status indicator shows Online (green) or Offline / Inactive (red)."),
    ]
    for item, desc in dash_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.left_indent = Inches(0.2)
        r1 = p.add_run(f"▸  {item}: ")
        r1.bold = True
        r1.font.size = Pt(11)
        r1.font.color.rgb = CYAN
        r2 = p.add_run(desc)
        r2.font.size = Pt(11)
        r2.font.color.rgb = DARK_TEXT

    # 5.2 Artifact Discovery
    h2(doc, "5.2  📂  Artifact Discovery")
    body(doc,
         "Click 'Artifact Discovery' in the sidebar to load this tab.")
    bullet(doc, "Ollama Environment Details — shows the full filesystem path to the Ollama executable and its model cache directory (~/.ollama).")
    bullet(doc, "Cache Storage — displays the total number of model manifest and blob files stored locally.")
    bullet(doc, "Model Cache Files table — lists every file found in the ~/.ollama directory with its name, full path, and size in MB. Up to 50 files are shown.")

    # 5.3 Hashes & Timeline
    h2(doc, "5.3  🔑  Hashes & Timeline")
    body(doc,
         "This is the core forensic analysis tab. It contains two action buttons and two result panels.")

    h3(doc, "Compute SHA256 Hashes button")
    body(doc,
         "Clicking this button sends a POST request to /api/hashing. The system automatically "
         "determines whether this is a first run or a verification run:")
    bullet(doc, "First Run (no baseline saved): Computes hashes for all files in Evidence/ and saves them as the baseline. A green banner confirms 'BASELINE RECORDED'. All files show ✅ Verified.")
    bullet(doc, "Verification Run (baseline exists): Computes new hashes and compares them to the saved baseline. Files whose hashes match show ✅ Verified. Files whose hashes differ show ⚠️ TAMPERED with both the current hash and the original baseline hash displayed in red.")

    h3(doc, "Build Forensic Timeline button")
    body(doc,
         "Clicking this button sends a POST request to /api/timeline. The system reads the "
         "last-modified timestamp (st_mtime) of every file in Evidence/ and displays them in "
         "chronological order in the stepper timeline panel. The timeline is also saved to "
         "Timeline/timeline.txt.")

    h3(doc, "Evidence Integrity Verification table columns")
    cols = [
        ("File Name",       "The filename from the Evidence/ directory"),
        ("SHA-256 Checksum","The current cryptographic hash of the file; if tampered, the original baseline hash is shown below in red"),
        ("Status",          "✅ Verified | ⚠️ TAMPERED | 🆕 New File"),
    ]
    for col, desc in cols:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.3)
        p.paragraph_format.space_after = Pt(3)
        r1 = p.add_run(f"{col}: ")
        r1.bold = True
        r1.font.size = Pt(11)
        r2 = p.add_run(desc)
        r2.font.size = Pt(11)
        r2.font.color.rgb = DARK_TEXT

    # 5.4 AI Copilot
    h2(doc, "5.4  🤖  AI Incident Copilot")
    body(doc,
         "This tab generates a full professional forensic investigation report using a local LLM.")
    bullet(doc, "Target Local LLM dropdown: Lists all Ollama models installed on your machine. If none are installed, it shows a guidance message.")
    bullet(doc, "Generate AI Incident Report button: Loads all Evidence/ files, hashes, and timeline data, then sends a structured DFIR prompt to the selected Ollama model. Generation can take 30 seconds to several minutes depending on model size and hardware.")
    bullet(doc, "Executive Investigation Report panel: Displays the rendered Markdown report. The report is simultaneously saved to Reports/Investigation_Report.md.")
    bullet(doc, "Status badge: Shows NOT GENERATED / SYNTHESIZING... / COMPLETED / FAILED.")
    info_box(doc, "💡  Tip:",
             "Run 'Compute SHA256 Hashes' and 'Build Forensic Timeline' before generating "
             "the AI report so that hash and timeline data are available in the prompt.",
             GREEN)

    # ── 6. Tamper Detection Demo ──────────────────────────────────────────────
    h1(doc, "6. Step-by-Step: Tamper Detection Demonstration")
    body(doc,
         "This is the key learning exercise of the workshop. Follow these steps carefully.")

    steps = [
        ("Step 1 — Record the Baseline",
         "Open the Hashes & Timeline tab. Click 'Compute SHA256 Hashes'. "
         "A green banner appears: '✅ BASELINE RECORDED'. All 9 evidence files show Verified status. "
         "The baseline is saved to Hashes/sha256_hashes.txt."),
        ("Step 2 — Tamper with an Evidence File",
         "Using any text editor, open Evidence/vpn.log (NOT Evidence_Backup/). "
         "Make any change — add a space, change a character, add a line. Save the file."),
        ("Step 3 — Run Hashing Again",
         "Return to the browser. Click 'Compute SHA256 Hashes' again. "
         "A red banner now appears: '🚨 VERIFICATION RUN — Tampering detected'. "
         "The row for vpn.log is highlighted in red and shows ⚠️ TAMPERED. "
         "The table displays both the new (current) hash and the original baseline hash for comparison."),
        ("Step 4 — Restore the File",
         "To reset for the next demonstration, copy the original file from Evidence_Backup/vpn.log "
         "back to Evidence/vpn.log. Run hashing again to confirm it returns to Verified status."),
    ]
    for i, (title, desc) in enumerate(steps, 1):
        # Numbered step box
        tbl = doc.add_table(rows=1, cols=2)
        tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        num_cell = tbl.rows[0].cells[0]
        num_cell.width = Inches(0.5)
        set_cell_bg(num_cell, "06B6D4")
        np = num_cell.paragraphs[0]
        np.alignment = WD_ALIGN_PARAGRAPH.CENTER
        nr = np.add_run(str(i))
        nr.bold = True
        nr.font.size = Pt(18)
        nr.font.color.rgb = WHITE

        txt_cell = tbl.rows[0].cells[1]
        set_cell_bg(txt_cell, "F0FDFF")
        tp = txt_cell.paragraphs[0]
        tr1 = tp.add_run(title + "\n")
        tr1.bold = True
        tr1.font.size = Pt(11)
        tr1.font.color.rgb = DARK_NAVY
        tr2 = tp.add_run(desc)
        tr2.font.size = Pt(10)
        tr2.font.color.rgb = DARK_TEXT
        doc.add_paragraph()

    info_box(doc, "⚠️  Important:",
             "Always edit files inside the Evidence/ folder, not Evidence_Backup/. "
             "The hashing system only monitors the Evidence/ directory.",
             RED)

    # ── 7. CLI Interface ──────────────────────────────────────────────────────
    h1(doc, "7. CLI Interface Guide")
    body(doc,
         "The toolkit includes a traditional terminal-based interface for environments where "
         "a browser is not available.")
    body(doc, "To launch the CLI:")
    code_block(doc, "python forensic_toolkit/main.py")
    body(doc, "The main menu presents 9 options:")

    cli_opts = [
        ("1", "System Information",     "Display OS, CPU, memory, and disk details"),
        ("2", "Ollama Information",      "Show Ollama version, running status, and port"),
        ("3", "Installed Models",        "List all locally installed Ollama models"),
        ("4", "Running Processes",       "Show Ollama-related processes and network ports"),
        ("5", "Collect AI Artifacts",    "Scan ~/.ollama for model files"),
        ("6", "Generate SHA256 Hashes",  "Hash all files in Evidence/ and save to Hashes/"),
        ("7", "Timeline Generator",      "Build file modification timeline from Evidence/"),
        ("8", "Investigation Report (AI-Assisted)", "Generate report via Ollama or fallback template"),
        ("9", "Exit",                    "Quit the toolkit"),
    ]
    cli_tbl = doc.add_table(rows=1, cols=3)
    cli_tbl.style = "Table Grid"
    for j, h_text in enumerate(["#", "Option", "Description"]):
        cell = cli_tbl.rows[0].cells[j]
        set_cell_bg(cell, "070913")
        run = cell.paragraphs[0].add_run(h_text)
        run.bold = True
        run.font.color.rgb = CYAN
        run.font.size = Pt(10)
    for num, opt, desc in cli_opts:
        row = cli_tbl.add_row()
        nc = row.cells[0]
        set_cell_bg(nc, "0D1A26")
        nr = nc.paragraphs[0].add_run(num)
        nr.bold = True
        nr.font.color.rgb = CYAN
        nr.font.size = Pt(11)
        row.cells[1].paragraphs[0].add_run(opt).font.size = Pt(10)
        row.cells[2].paragraphs[0].add_run(desc).font.size = Pt(10)
    doc.add_paragraph()

    # ── 8. Output Files ───────────────────────────────────────────────────────
    h1(doc, "8. Understanding the Output Files")

    output_files = [
        ("Hashes/sha256_hashes.txt",
         "The SHA-256 baseline file. Created on the first hashing run. "
         "Contains filename and digest pairs separated by blank lines. "
         "Do not manually edit this file as it serves as the chain-of-custody reference."),
        ("Hashes/sha256_hashes_verification.txt",
         "Written on every subsequent (verification) hashing run. "
         "Contains the timestamp of the verification, current hashes, and status (verified/tampered) for each file."),
        ("Timeline/timeline.txt",
         "A plain-text chronological listing of evidence files sorted by last-modified timestamp. "
         "Format: YYYY-MM-DD HH:MM:SS.ffffff  filename"),
        ("Reports/Investigation_Report.md",
         "The AI-generated (or template-based) investigation report in Markdown format. "
         "Can be opened in any Markdown viewer or text editor."),
        ("Reports/Evidence_Integrity_Report.md",
         "The evidence integrity report generated by the /api/report/integrity endpoint. "
         "Contains a table listing all evidence files with their verification status."),
        ("Logs/investigation.log",
         "An audit trail of all significant actions performed (hashing, timeline, report generation). "
         "Each entry is timestamped. Useful for demonstrating audit logging in forensic workflows."),
    ]
    for filename, desc in output_files:
        h3(doc, filename)
        body(doc, desc)

    # ── 9. Troubleshooting ────────────────────────────────────────────────────
    h1(doc, "9. Troubleshooting")

    issues = [
        ("Dashboard shows no data / all fields display '-'",
         "Cause: The FastAPI server is not running.\n"
         "Fix: Run start.bat or execute: python -m uvicorn gui_app:app --host 127.0.0.1 --port 8000"),
        ("Ollama status shows 'Offline / Inactive'",
         "Cause: The Ollama service is not running.\n"
         "Fix: Open a terminal and run: ollama serve\n"
         "     Or double-click start.bat which starts Ollama automatically."),
        ("AI report generation fails or shows 'Error: Could not query Ollama'",
         "Cause: Ollama is offline, or no models are installed.\n"
         "Fix 1: Ensure Ollama is running (ollama serve).\n"
         "Fix 2: Pull a model: ollama pull llama3.2:1b\n"
         "Note: The toolkit will automatically generate a template-based fallback report."),
        ("Hashing shows 'Evidence directory not found' (HTTP 404)",
         "Cause: The Evidence/ directory is missing or empty.\n"
         "Fix: Ensure the Evidence/ folder exists in the project root and contains files."),
        ("Modified file still shows 'Verified' after tampering",
         "Cause: You edited a file in Evidence_Backup/ instead of Evidence/.\n"
         "Fix: Only edit files inside the Evidence/ directory. The hashing system does not monitor Evidence_Backup/."),
        ("start.bat opens and closes immediately",
         "Cause: Python or uvicorn is not installed, or there is an import error.\n"
         "Fix: Open a terminal, navigate to the project directory, and run:\n"
         "     python -m uvicorn gui_app:app --host 127.0.0.1 --port 8000\n"
         "     Read the error message that appears."),
    ]
    for issue, solution in issues:
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        cell = tbl.rows[0].cells[0]
        set_cell_bg(cell, "FFF7ED")
        p1 = cell.paragraphs[0]
        r1 = p1.add_run(f"❗  {issue}")
        r1.bold = True
        r1.font.size = Pt(11)
        r1.font.color.rgb = RGBColor(0xC2, 0x41, 0x0C)

        p2 = cell.add_paragraph()
        r2 = p2.add_run(solution)
        r2.font.size = Pt(10)
        r2.font.name = "Courier New"
        r2.font.color.rgb = DARK_TEXT
        doc.add_paragraph()

    # ── 10. FAQ ───────────────────────────────────────────────────────────────
    h1(doc, "10. Frequently Asked Questions")

    faqs = [
        ("Does this tool require an internet connection?",
         "No. The entire toolkit — including the AI report generation — operates fully offline. "
         "Ollama runs the LLM locally on your machine."),
        ("Can I add my own evidence files?",
         "Yes. Simply copy any text or binary files into the Evidence/ directory before running "
         "the hashing or timeline operations."),
        ("What happens if I run 'Compute SHA256 Hashes' more than twice?",
         "The second and all subsequent runs are treated as verification runs. The baseline "
         "stored in Hashes/sha256_hashes.txt is never overwritten automatically."),
        ("Can I use a different AI model?",
         "Yes. Any model installed via ollama pull will appear in the AI Copilot model dropdown. "
         "Larger models (mistral, llama3.2:3b, gemma2) produce more detailed reports but require "
         "more RAM and take longer."),
        ("Where are the generated reports saved?",
         "Reports/ directory in the project root. "
         "Investigation_Report.md for the AI report, "
         "Evidence_Integrity_Report.md for the integrity report."),
        ("Is the Evidence_Backup/ folder used by the hashing system?",
         "No. The hashing system only reads from Evidence/. "
         "Evidence_Backup/ is for your reference only — use it to restore original files after tampering demonstrations."),
    ]

    for q, a in faqs:
        h3(doc, f"Q: {q}")
        body(doc, f"A: {a}")

    doc.save(output_path)
    print(f"[OK] User Manual saved:     {output_path}")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    docs_dir = os.path.join(base, "Docs")
    os.makedirs(docs_dir, exist_ok=True)

    tech_path   = os.path.join(docs_dir, "Technical_Report_AI_Cyber_Forensics_Toolkit.docx")
    manual_path = os.path.join(docs_dir, "User_Manual_AI_Cyber_Forensics_Toolkit.docx")

    build_technical_report(tech_path)
    build_user_manual(manual_path)

    print("\n[DONE] Both documents created successfully in the Docs/ folder.")
    print(f"   -> {tech_path}")
    print(f"   -> {manual_path}")
