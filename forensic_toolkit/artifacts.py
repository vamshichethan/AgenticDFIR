"""
Artifact Discovery Module
"""

import os
import platform
import subprocess
from pathlib import Path
from forensic_toolkit.ollama_info import get_ollama_path


def run(cmd):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)


def collect_artifacts():
    print("\n" + "=" * 60)
    print("AI ARTIFACT DISCOVERY")
    print("=" * 60)

    ollama_cmd = get_ollama_path()

    print("\n1. Ollama Installation")
    if platform.system() == "Windows":
        # Resolve path using 'where' command or fall back to the path we retrieved
        where_out = run(f"where {ollama_cmd}").strip()
        print(where_out if where_out else ollama_cmd)
    else:
        which_out = run(f"which {ollama_cmd}").strip()
        print(which_out if which_out else ollama_cmd)

    print("\n2. Installed Models")
    print(run(f"{ollama_cmd} list"))

    print("\n3. Model Directory")
    home = Path.home()
    model_path = home / ".ollama"

    if model_path.exists():
        print(model_path)
    else:
        print("Directory not found")

    print("\n4. Model Files")
    if model_path.exists():
        # Traverse filesystem dynamically using Python's os.walk to keep it cross-platform
        files_found = []
        for root, _, files in os.walk(model_path):
            for file in files:
                files_found.append(os.path.join(root, file))
        
        if files_found:
            for f in files_found[:20]:  # Limit output to 20 files
                print(f)
            if len(files_found) > 20:
                print(f"\n... and {len(files_found) - 20} more files.")
        else:
            print("No model files found.")
    else:
        print("Model directory not found.")

    input("\nPress Enter...")