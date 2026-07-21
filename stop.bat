@echo off
echo ===================================================
echo Stopping AI Cyber Forensic Toolkit Services...
echo ===================================================

:: Stop FastAPI / Uvicorn Server running on port 8000
echo Stopping FastAPI backend on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    echo Killing process listening on port 8000 (PID: %%a)
    taskkill /F /PID %%a >nul 2>&1
)

:: Stop Ollama server if running
echo Stopping local Ollama server...
taskkill /F /IM ollama.exe >nul 2>&1

echo.
echo Services stopped successfully.
timeout /t 3 >nul
