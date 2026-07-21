import os
import platform
from forensic_toolkit.utils import log

def system_information():

    print("\n========== SYSTEM INFORMATION ==========\n")

    print("Hostname :", platform.node())

    print("Operating System :", platform.system())

    print("Release :", platform.release())

    print("Version :", platform.version())

    print("Machine :", platform.machine())

    print("Processor :", platform.processor())

    print()

    if platform.system() == "Windows":
        # Memory Info
        print("Memory Information:")
        print("-" * 30)
        # Query total physical memory in GB using powershell (avoiding psutil to keep zero dependencies)
        try:
            import subprocess
            mem_cmd = "powershell -Command \"Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object { [Math]::Round($_.Sum / 1GB, 2) }\""
            total_gb = subprocess.run(mem_cmd, shell=True, capture_output=True, text=True).stdout.strip()
            if total_gb:
                print(f"Total Physical Memory: {total_gb} GB")
            else:
                os.system("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /Value")
        except Exception:
            os.system("wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /Value")
        print()
        
        # Disk Info
        print("Disk Information:")
        print("-" * 30)
        os.system("wmic logicaldisk get deviceid, size, freespace")
    else:
        os.system("free -h")
        print()
        os.system("df -h")

    print()
    input("\nPress Enter to continue...")