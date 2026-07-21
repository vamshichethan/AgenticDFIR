@echo off
:: 0. Force working directory to the batch script's directory
cd /d "%~dp0"

echo ===================================================
echo Starting AI Cyber Forensic Toolkit Web Service...
echo ===================================================

:: Free up port 8000 if occupied
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    echo [INFO] Port 8000 is occupied. Terminating conflicting process with PID %%a...
    taskkill /F /PID %%a >nul 2>&1
)

:: 1. Check if Python or Python launcher (py) is installed
set "PYTHON_CMD="
where python >nul 2>nul
if "%ERRORLEVEL%" == "0" (
    set "PYTHON_CMD=python"
    goto :python_found
)
where py >nul 2>nul
if "%ERRORLEVEL%" == "0" (
    set "PYTHON_CMD=py"
    goto :python_found
)

echo [ERROR] Python is not installed or not added to your system Path!
echo Please install Python 3.10 or higher and make sure to check "Add Python to PATH".
pause
exit /b

:python_found
:: 2. Check Python version (requires >= 3.10)
%PYTHON_CMD% -c "import sys; sys.exit(0 if sys.version_info.major==3 and sys.version_info.minor>=10 else 1)" >nul 2>nul
if "%ERRORLEVEL%" == "0" goto :python_version_ok
echo [ERROR] Python 3.10 or higher is required to run this application.
%PYTHON_CMD% --version
pause
exit /b

:python_version_ok
:: 3. Check if virtual environment is valid and clean if broken/non-Windows
if not exist ".venv" goto :skip_venv_clean

:: Check if Windows-style virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Detected non-Windows or incomplete virtual environment. Re-creating...
    rmdir /s /q .venv
    goto :skip_venv_clean
)

:: Check if the virtual environment is working (base Python executable must exist)
.venv\Scripts\python.exe -c "import sys" >nul 2>nul
if not "%ERRORLEVEL%" == "0" (
    echo [INFO] Virtual environment is broken or refers to a missing Python interpreter. Re-creating...
    rmdir /s /q .venv
)

:skip_venv_clean
:: 4. Create local Windows virtual environment if it doesn't exist
if exist ".venv" goto :venv_exists
echo [INFO] Creating Python virtual environment (.venv)...
%PYTHON_CMD% -m venv .venv
if "%ERRORLEVEL%" == "0" goto :venv_exists
echo [ERROR] Failed to create Python virtual environment.
pause
exit /b

:venv_exists
:: 5. Install Python dependencies
echo [INFO] Checking and installing Python dependencies inside .venv...
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
if "%ERRORLEVEL%" == "0" goto :dependencies_ok
echo [ERROR] Failed to install required Python dependencies.
pause
exit /b

:dependencies_ok
:: 6. Check if Ollama is installed
set "OLLAMA_INSTALLED=0"
where ollama >nul 2>nul
if "%ERRORLEVEL%"=="0" set "OLLAMA_INSTALLED=1"
if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" set "OLLAMA_INSTALLED=1"

if "%OLLAMA_INSTALLED%"=="1" goto :ollama_installed
echo [WARNING] Ollama is not installed or not found in system Path.
if exist "OllamaSetup.exe" goto :launch_ollama_installer
echo ===================================================
echo [ERROR] Ollama is not installed!
echo Please download and install Ollama from https://ollama.com
echo or place 'OllamaSetup.exe' in this directory.
echo ===================================================
pause
exit /b

:launch_ollama_installer
echo Found local installer OllamaSetup.exe. Launching installer...
echo Please complete the setup wizard and then restart start.bat.
start /wait "" "OllamaSetup.exe"
exit /b

:ollama_installed
:: 7. Check if Ollama is running, start if not
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe">NUL
if "%ERRORLEVEL%"=="0" goto :ollama_running
echo [INFO] Starting local Ollama service in the background...
set "OLLAMA_EXE=%LOCALAPPDATA%\Programs\Ollama\ollama.exe"
if exist "%OLLAMA_EXE%" goto :start_ollama_exe
start /B "" ollama serve
goto :wait_ollama

:start_ollama_exe
start /B "" "%OLLAMA_EXE%" serve

:wait_ollama
timeout /t 5 >nul

:ollama_running
echo [INFO] Ollama service is running.

:: 8. Check and pull required Ollama models
echo [INFO] Checking required Ollama models...
ollama list | findstr /I "llama3.2:1b" >nul
if "%ERRORLEVEL%" == "0" goto :llama_ok
echo [INFO] Pulling missing model: llama3.2:1b...
ollama pull llama3.2:1b
:llama_ok
echo [INFO] Model 'llama3.2:1b' is ready.

ollama list | findstr /I "nomic-embed-text" >nul
if "%ERRORLEVEL%" == "0" goto :nomic_ok
echo [INFO] Pulling missing model: nomic-embed-text...
ollama pull nomic-embed-text
:nomic_ok
echo [INFO] Model 'nomic-embed-text' is ready.

ollama list | findstr /I "qwen2.5:1.5b" >nul
if "%ERRORLEVEL%" == "0" goto :qwen1_ok
echo [INFO] Pulling missing model: qwen2.5:1.5b...
ollama pull qwen2.5:1.5b
:qwen1_ok
echo [INFO] Model 'qwen2.5:1.5b' is ready.

ollama list | findstr /I "qwen2.5:0.5b" >nul
if "%ERRORLEVEL%" == "0" goto :qwen0_ok
echo [INFO] Pulling missing model: qwen2.5:0.5b...
ollama pull qwen2.5:0.5b
:qwen0_ok
echo [INFO] Model 'qwen2.5:0.5b' is ready.


:: 9. Launch browser page
echo [INFO] Launching Dashboard UI in browser...
start http://127.0.0.1:8000

:: 10. Start FastAPI backend using virtual environment Python
echo [INFO] Starting FastAPI API server...
.venv\Scripts\python.exe -m uvicorn gui_app:app --host 127.0.0.1 --port 8000


