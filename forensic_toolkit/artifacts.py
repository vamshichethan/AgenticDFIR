"""
Forensic Artifact Discovery Module
Discovers live host artifacts, persistence mechanisms, user accounts, and AI runtime metadata.
"""

import platform
from pathlib import Path
from forensic_toolkit.utils import log
from forensic_toolkit.live_forensics import analyze_persistence, analyze_user_accounts, get_live_system_metrics
from forensic_toolkit.ollama_info import get_ollama_path


def collect_artifacts():
    log("Forensic Artifact Discovery Run")
    print("\n" + "=" * 70)
    print("DIGITAL FORENSIC ARTIFACT DISCOVERY")
    print("=" * 70)

    # 1. System Telemetry
    sys_m = get_live_system_metrics()
    print(f"\n1. System Profile: {sys_m['hostname']} ({sys_m['os']} {sys_m['release']})")
    print(f"   Uptime: {sys_m['uptime']} | Boot: {sys_m['boot_time']}")
    print(f"   CPUs: {sys_m['cpu_count_logical']} Logical | RAM: {sys_m['memory']['used_gb']}/{sys_m['memory']['total_gb']} GB")

    # 2. Persistence / Autoruns
    persist = analyze_persistence()
    print(f"\n2. Persistence & Autorun Hooks ({persist['total_autoruns']} artifacts discovered)")
    print("-" * 70)
    for a in persist["autoruns"][:15]:
        print(f"   [{a['type']}] {a['name']:<25} ({a['location']})")

    # 3. User Accounts
    users = analyze_user_accounts()
    print(f"\n3. User Sessions & Accounts")
    print("-" * 70)
    if users["active_sessions"]:
        for s in users["active_sessions"]:
            print(f"   Active Session: User '{s['username']}' on {s['terminal']} from {s['host']} (since {s['started']})")
    else:
        print("   No active remote sessions detected.")

    if users["interactive_accounts"]:
        print(f"   Interactive System Users ({len(users['interactive_accounts'])}):")
        for u in users["interactive_accounts"][:8]:
            print(f"    - {u['username']} (UID: {u['uid']}, Home: {u['home']}, Shell: {u['shell']})")

    # 4. AI Runtime Artifacts
    print("\n4. AI Runtime & Local Model Artifacts")
    print("-" * 70)
    ollama_cmd = get_ollama_path()
    home = Path.home()
    model_path = home / ".ollama"
    print(f"   Ollama Command: {ollama_cmd}")
    print(f"   Model Directory: {model_path} ({'Exists' if model_path.exists() else 'Not Found'})")

    input("\nPress Enter to continue...")
