#!/usr/bin/env bash

# AI Cyber Forensics & Incident Response Platform - 1-Click Launcher (macOS / Linux)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  🛡️  AI CYBER FORENSIC & INCIDENT RESPONSE PLATFORM v2.0"
echo "=========================================================="

# 1. Release port 8000 if in use
PORT_PID=$(lsof -ti:8000 2>/dev/null || true)
if [ -n "$PORT_PID" ]; then
    echo "[INFO] Port 8000 occupied by PID $PORT_PID. Terminating..."
    kill -9 $PORT_PID 2>/dev/null || true
    sleep 1
fi

# 2. Check for Python 3
PYTHON_BIN=""
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo "[ERROR] Python 3 is not installed or not in PATH."
    exit 1
fi

echo "[INFO] Using Python: $($PYTHON_BIN --version)"

# 3. Create or verify virtual environment
if [ ! -d ".venv" ] || [ ! -f ".venv/bin/python" ]; then
    echo "[INFO] Creating virtual environment (.venv)..."
    $PYTHON_BIN -m venv .venv
fi

# Activate virtualenv
source .venv/bin/activate

# 4. Install / Verify dependencies
echo "[INFO] Verifying dependencies..."
pip install -q -r requirements.txt || pip install -r requirements.txt

# 5. Check Ollama (Optional - falls back gracefully to Heuristic Engine if offline)
if command -v ollama &>/dev/null; then
    echo "[INFO] Ollama detected. Checking background service..."
    if ! pgrep -x "ollama" &>/dev/null; then
        echo "[INFO] Starting Ollama in background..."
        nohup ollama serve >/dev/null 2>&1 &
        sleep 2
    fi
else
    echo "[INFO] Ollama not found. The toolkit will run using the Built-in DFIR Expert Engine."
    echo "       (To enable local LLMs, download Ollama from https://ollama.com)"
fi

# 6. Start FastAPI server & Open browser
echo "[INFO] Launching FastAPI Web Service on http://127.0.0.1:8000 ..."

# Attempt to open browser automatically
if command -v open &>/dev/null; then
    (sleep 2 && open "http://127.0.0.1:8000") &
elif command -v xdg-open &>/dev/null; then
    (sleep 2 && xdg-open "http://127.0.0.1:8000") &
fi

exec uvicorn gui_app:app --host 127.0.0.1 --port 8000

