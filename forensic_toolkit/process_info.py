"""
Running Process Investigation
"""

import platform
import subprocess
from forensic_toolkit.utils import log


def run(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)


def process_information():
    log("Running Process Investigation")
    print("\n" + "=" * 60)
    print("RUNNING PROCESS INVESTIGATION")
    print("=" * 60)

    print("\nRunning Ollama Process")
    print("-" * 60)

    if platform.system() == "Windows":
        output = run("tasklist | findstr /I \"ollama\"")
        if output.strip():
            print(output)
        else:
            print("No running Ollama process found.")
    else:
        output = run("ps aux | grep ollama | grep -v grep")
        if output.strip():
            print(output)
        else:
            print("No running Ollama process found.")

    print("\nListening Network Ports")
    print("-" * 60)

    if platform.system() == "Windows":
        print(run("netstat -ano | findstr 11434"))
    else:
        print(run("ss -lntp | grep 11434 || netstat -lntp | grep 11434"))

    input("\nPress Enter to continue...")