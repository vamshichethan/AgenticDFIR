#!/usr/bin/env bash

# Stop script for AI Cyber Forensics Platform
echo "Shutting down AI Cyber Forensics Toolkit services..."

PORT_PID=$(lsof -ti:8000 2>/dev/null || true)
if [ -n "$PORT_PID" ]; then
    echo "Killing process on port 8000 (PID: $PORT_PID)..."
    kill -9 $PORT_PID 2>/dev/null || true
fi

# Kill any stray uvicorn processes started for gui_app
pkill -f "uvicorn gui_app:app" 2>/dev/null || true

echo "All services stopped."

