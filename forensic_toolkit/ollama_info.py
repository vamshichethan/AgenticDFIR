"""
Ollama Information Module
"""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from forensic_toolkit.utils import log


def get_ollama_path():
    """Find the path to the Ollama executable."""
    # 1. Check if in system PATH
    if shutil.which("ollama"):
        return "ollama"
    
    # 2. Check standard Windows location
    if platform.system() == "Windows":
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            win_path = Path(local_appdata) / "Programs" / "Ollama" / "ollama.exe"
            if win_path.exists():
                return f'"{win_path}"'
        # Fallback to home folder
        home_path = Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe"
        if home_path.exists():
            return f'"{home_path}"'
    else:
        # Standard Linux paths
        linux_paths = ["/usr/local/bin/ollama", "/usr/bin/ollama", "/bin/ollama"]
        for p in linux_paths:
            if os.path.exists(p):
                return p
                
    return "ollama"  # Fallback


def run_command(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except Exception as e:
        return str(e)


def ollama_information():
    log("Ollama Information Collected")
    print("\n" + "=" * 60)
    print("OLLAMA INFORMATION")
    print("=" * 60)

    ollama_cmd = get_ollama_path()

    print("\nOllama Version")
    print("-" * 60)
    print(run_command(f"{ollama_cmd} --version"))

    print("\nInstalled Models")
    print("-" * 60)
    print(run_command(f"{ollama_cmd} list"))

    print("\nRunning Service / Process Status")
    print("-" * 60)
    if platform.system() == "Windows":
        status_out = run_command("tasklist | findstr /I \"ollama\"")
        if status_out:
            print("Ollama process is running:\n" + status_out)
        else:
            print("Ollama process is not running.")
    else:
        if shutil.which("systemctl"):
            print(run_command("systemctl status ollama --no-pager"))
        else:
            status_out = run_command("pgrep -fl ollama")
            print(status_out if status_out else "Ollama is not running (no process found).")

    print("\nListening Port")
    print("-" * 60)
    if platform.system() == "Windows":
        print(run_command("netstat -ano | findstr 11434"))
    else:
        print(run_command("ss -lntp | grep 11434 || netstat -lntp | grep 11434"))

    input("\nPress Enter to continue...")