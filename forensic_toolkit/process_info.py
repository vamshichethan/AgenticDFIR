"""
Running Process & Network Investigation Module
Performs live process enumeration, anomaly detection, and listening network ports analysis.
"""

from forensic_toolkit.utils import log
from forensic_toolkit.live_forensics import analyze_processes, analyze_network_sockets


def process_information():
    log("Live Process & Network Investigation Run")
    print("\n" + "=" * 70)
    print("LIVE PROCESS & NETWORK CONNECTION INVESTIGATION")
    print("=" * 70)

    # 1. Process Anomalies
    proc_data = analyze_processes()
    print(f"\n1. Process Inventory ({proc_data['total_processes']} running processes)")
    print(f"   Suspicious / Flagged Processes: {proc_data['suspicious_count']}")
    print("-" * 70)
    print(f"{'PID':<7} {'USER':<12} {'CPU%':<6} {'MEM(MB)':<10} {'NAME':<20} {'ANOMALIES'}")
    print("-" * 70)

    for p in proc_data["processes"][:25]:
        anom_str = " | ".join(p["anomalies"]) if p["anomalies"] else "Normal"
        if p["is_suspicious"]:
            anom_str = f"[!] {anom_str}"
        print(f"{p['pid']:<7} {p['user'][:11]:<12} {p['cpu_percent']:<6} {p['memory_mb']:<10} {p['name'][:19]:<20} {anom_str[:40]}")

    # 2. Active Sockets
    sock_data = analyze_network_sockets()
    print(f"\n\n2. Network Connections & Listening Sockets ({sock_data['total_connections']} connections)")
    print(f"   Suspicious / Outbound Threat Sockets: {sock_data['suspicious_count']}")
    print("-" * 70)
    print(f"{'PROTO':<6} {'LOCAL ADDRESS':<22} {'REMOTE ADDRESS':<22} {'STATE':<12} {'PROCESS':<16} {'THREAT TAG'}")
    print("-" * 70)

    for s in sock_data["connections"][:20]:
        threat = s["threat_tag"] or "—"
        print(f"{s['protocol']:<6} {s['local_address']:<22} {s['remote_address']:<22} {s['status']:<12} {s['process_name'][:15]:<16} {threat[:30]}")

    input("\nPress Enter to continue...")
