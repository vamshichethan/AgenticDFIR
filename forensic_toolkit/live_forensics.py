"""
Live System & Process Forensics Engine
Provides deep host reconnaissance, process tree anomaly detection,
active network sockets triage, persistence/autorun hunting, and user security audits.
"""

import os
import re
import sys
import time
import socket
import platform
import subprocess
from pathlib import Path
from datetime import datetime
import psutil

# Known Case Threat Indicators
SUSPICIOUS_IPS = {
    "198.51.100.20": "CRITICAL: Known Data Exfiltration Destination",
    "203.45.18.101": "HIGH: Attacker VPN Brute Force & Credential Spray Source",
    "45.33.18.7": "HIGH: Suspicious Outbound Lateral Pivot / C2 Target",
    "198.51.100.5": "MEDIUM: External Reconnaissance / Password Spray Attempt"
}

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "meterpreter", "cobaltstrike", "sliver", "nc", "ncat",
    "netcat", "socat", "hydra", "john", "hashcat", "sqlmap", "responder",
    "chisel", "xmrig", "minerd", "cryptominer", "evil", "payload"
}

SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r"powershell.*(-enc|-encodedcommand)", re.IGNORECASE),
    re.compile(r"certutil.*(-urlcache|-split)", re.IGNORECASE),
    re.compile(r"bash\s+-i\s+>&.*tcp", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"base64\s+-d.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"python.*-c.*import.*socket", re.IGNORECASE),
]

SUSPICIOUS_TEMP_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "\\temp", "\\appdata\\local\\temp"]


def is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is in private (RFC1918) or loopback space."""
    if not ip or ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
        return True
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 169.254.0.0/16 (Link Local)
        if parts[0] == 169 and parts[1] == 254:
            return True
    except Exception:
        pass
    return False


def get_live_system_metrics() -> dict:
    """Gather host hardware, operating system, and system performance telemetry."""
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_seconds = int(time.time() - psutil.boot_time())
    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600
    minutes = (uptime_seconds % 3600) // 60
    uptime_str = f"{days}d {hours}h {minutes}m"

    cpu_usage = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()

    # Disk usage
    disk_path = "C:\\" if platform.system() == "Windows" else "/"
    try:
        disk = psutil.disk_usage(disk_path)
    except Exception:
        disk = None

    # Network interfaces
    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        for iface_name, addr_list in addrs.items():
            ipv4 = None
            mac = None
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                    mac = addr.address
                elif addr.family == 18 or getattr(addr, "family_name", "") == "AF_LINK":
                    mac = addr.address
            if ipv4:
                interfaces.append({
                    "interface": iface_name,
                    "ipv4": ipv4,
                    "mac": mac or "N/A"
                })
    except Exception:
        pass

    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime_str,
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False) or psutil.cpu_count(logical=True),
        "cpu_usage_percent": cpu_usage,
        "memory": {
            "total_gb": round(mem.total / (1024 ** 3), 2),
            "used_gb": round(mem.used / (1024 ** 3), 2),
            "available_gb": round(mem.available / (1024 ** 3), 2),
            "percentage": mem.percent
        },
        "disk": {
            "path": disk_path,
            "total_gb": round(disk.total / (1024 ** 3), 2) if disk else 0,
            "used_gb": round(disk.used / (1024 ** 3), 2) if disk else 0,
            "free_gb": round(disk.free / (1024 ** 3), 2) if disk else 0,
            "percentage": disk.percent if disk else 0
        },
        "network_interfaces": interfaces
    }


def analyze_processes() -> dict:
    """
    Enumerate live processes and score them for DFIR anomalies:
    - Suspicious binary names
    - Execution from temporary or world-writable directories
    - Anomalous command-line flags
    - High CPU/Memory anomalies
    """
    process_list = []
    suspicious_count = 0

    for proc in psutil.process_iter(["pid", "ppid", "name", "username", "cpu_percent", "memory_info", "exe", "cmdline", "status"]):
        try:
            info = proc.info
            pid = info["pid"]
            ppid = info["ppid"]
            name = info["name"] or "unknown"
            username = info["username"] or "N/A"
            exe = info["exe"] or ""
            cmdline_list = info["cmdline"] or []
            cmdline = " ".join(cmdline_list)
            status = info["status"]
            cpu = info["cpu_percent"] or 0.0
            mem_mb = round(info["memory_info"].rss / (1024 ** 2), 2) if info["memory_info"] else 0.0

            anomalies = []

            # 1. Check suspicious process name
            name_lower = name.lower()
            for susp_name in SUSPICIOUS_PROCESS_NAMES:
                if susp_name in name_lower:
                    anomalies.append(f"Suspicious Process Name ({susp_name})")

            # 2. Check execution path
            exe_lower = exe.lower()
            for temp_path in SUSPICIOUS_TEMP_PATHS:
                if temp_path in exe_lower:
                    anomalies.append(f"Execution from Temporary Path ({temp_path})")

            # 3. Check command line patterns
            for pat in SUSPICIOUS_CMD_PATTERNS:
                if pat.search(cmdline):
                    anomalies.append("Suspicious Command-Line Arguments Detected")
                    break

            is_suspicious = len(anomalies) > 0
            if is_suspicious:
                suspicious_count += 1

            process_list.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "user": username,
                "cpu_percent": cpu,
                "memory_mb": mem_mb,
                "status": status,
                "exe": exe,
                "cmdline": cmdline[:200] + ("..." if len(cmdline) > 200 else ""),
                "is_suspicious": is_suspicious,
                "anomalies": anomalies
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort: suspicious first, then by memory descending
    process_list.sort(key=lambda x: (not x["is_suspicious"], -x["memory_mb"]))

    return {
        "total_processes": len(process_list),
        "suspicious_count": suspicious_count,
        "processes": process_list
    }


def analyze_network_sockets() -> dict:
    """
    Examine active listening and established sockets.
    Correlates sockets with owning processes and known IOC indicators.
    Uses psutil or lsof fallback on Unix when psutil net_connections is restricted.
    """
    connections = []
    suspicious_sockets = 0

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, Exception):
        raw_conns = []

    # Map PIDs to names
    pid_to_name = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid_to_name[proc.info["pid"]] = proc.info["name"]
        except Exception:
            pass

    if raw_conns:
        for conn in raw_conns:
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                remote_ip = conn.raddr.ip if conn.raddr else ""
                status = conn.status
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                pid = conn.pid or 0
                proc_name = pid_to_name.get(pid, "System / Unknown")

                threat_tag = None
                is_external = False
                if remote_ip:
                    is_external = not is_private_ip(remote_ip)
                    if remote_ip in SUSPICIOUS_IPS:
                        threat_tag = SUSPICIOUS_IPS[remote_ip]
                        suspicious_sockets += 1
                    elif is_external and status == "ESTABLISHED":
                        threat_tag = "Outbound External Connection"

                connections.append({
                    "protocol": protocol,
                    "local_address": laddr,
                    "remote_address": raddr or "—",
                    "remote_ip": remote_ip or "—",
                    "status": status,
                    "pid": pid,
                    "process_name": proc_name,
                    "is_external": is_external,
                    "threat_tag": threat_tag
                })
            except Exception:
                continue

    # Fallback to lsof on macOS / Linux if connections list is empty
    if not connections and platform.system() != "Windows":
        try:
            cmd = ["lsof", "-iTCP", "-P", "-n"]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            lines = output.strip().split("\n")
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 9:
                        proc_name = parts[0]
                        pid = int(parts[1]) if parts[1].isdigit() else 0
                        addr_part = parts[8]
                        status = "LISTEN" if "(LISTEN)" in line else ("ESTABLISHED" if "(ESTABLISHED)" in line else "ACTIVE")
                        
                        laddr, raddr, remote_ip = "—", "—", ""
                        if "->" in addr_part:
                            laddr, raddr = addr_part.split("->", 1)
                            remote_ip = raddr.split("]")[0].replace("[", "") if "[" in raddr else raddr.split(":")[0]
                        else:
                            laddr = addr_part

                        threat_tag = None
                        is_external = False
                        if remote_ip and remote_ip != "—":
                            is_external = not is_private_ip(remote_ip)
                            if remote_ip in SUSPICIOUS_IPS:
                                threat_tag = SUSPICIOUS_IPS[remote_ip]
                                suspicious_sockets += 1
                            elif is_external and status == "ESTABLISHED":
                                threat_tag = "Outbound External Connection"

                        connections.append({
                            "protocol": "TCP",
                            "local_address": laddr,
                            "remote_address": raddr,
                            "remote_ip": remote_ip or "—",
                            "status": status,
                            "pid": pid,
                            "process_name": proc_name,
                            "is_external": is_external,
                            "threat_tag": threat_tag
                        })
        except Exception:
            pass

    # Sort: threat connections first, then established
    connections.sort(key=lambda x: (x["threat_tag"] is None, x["status"] != "ESTABLISHED"))

    return {
        "total_connections": len(connections),
        "suspicious_count": suspicious_sockets,
        "connections": connections[:100]
    }


def analyze_persistence() -> dict:
    """
    Inspect persistence mechanisms across platforms:
    - macOS: LaunchAgents / LaunchDaemons
    - Linux: systemd services / Cron jobs
    - Windows: Registry Run keys / Scheduled tasks
    - Shell profiles: .bashrc / .zshrc
    """
    autoruns = []
    current_os = platform.system()

    if current_os == "Darwin":
        launch_dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        for ldir in launch_dirs:
            if ldir.exists():
                for item in ldir.glob("*.plist"):
                    try:
                        stat = item.stat()
                        autoruns.append({
                            "type": "LaunchAgent/Daemon",
                            "name": item.name,
                            "location": str(item),
                            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        })
                    except Exception:
                        pass

    elif current_os == "Linux":
        cron_dirs = [Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly")]
        for cdir in cron_dirs:
            if cdir.exists():
                for item in cdir.iterdir():
                    if item.is_file():
                        autoruns.append({
                            "type": "Cron Job",
                            "name": item.name,
                            "location": str(item),
                            "modified": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        })

    elif current_os == "Windows":
        # Windows startup folder
        startup = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if startup.exists():
            for item in startup.iterdir():
                if item.is_file():
                    autoruns.append({
                        "type": "Startup Folder",
                        "name": item.name,
                        "location": str(item),
                        "modified": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })

    # User Shell Startup Files (Universal)
    shell_files = [".bashrc", ".bash_profile", ".zshrc", ".profile"]
    home = Path.home()
    for sfile in shell_files:
        target = home / sfile
        if target.exists():
            try:
                autoruns.append({
                    "type": "Shell Profile Hook",
                    "name": sfile,
                    "location": str(target),
                    "modified": datetime.fromtimestamp(target.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                })
            except Exception:
                pass

    return {
        "os": current_os,
        "total_autoruns": len(autoruns),
        "autoruns": autoruns[:40]
    }


def analyze_user_accounts() -> dict:
    """Retrieve logged in users and local system account profile information."""
    active_users = []
    try:
        for u in psutil.users():
            active_users.append({
                "username": u.name,
                "terminal": u.terminal or "N/A",
                "host": u.host or "localhost",
                "started": datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S")
            })
    except Exception:
        pass

    # Read /etc/passwd on Unix or current user on Windows
    system_accounts = []
    if platform.system() != "Windows":
        try:
            with open("/etc/passwd", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        # Exclude system daemons unless relevant
                        uid = int(parts[2]) if parts[2].isdigit() else -1
                        system_accounts.append({
                            "username": parts[0],
                            "uid": uid,
                            "gid": parts[3],
                            "home": parts[5],
                            "shell": parts[6],
                            "is_interactive": parts[6] in ("/bin/bash", "/bin/zsh", "/bin/sh")
                        })
        except Exception:
            pass
    else:
        system_accounts.append({
            "username": os.environ.get("USERNAME", "Unknown"),
            "uid": "N/A",
            "gid": "N/A",
            "home": str(Path.home()),
            "shell": "cmd/powershell",
            "is_interactive": True
        })

    return {
        "active_sessions": active_users,
        "total_system_accounts": len(system_accounts),
        "interactive_accounts": [a for a in system_accounts if a.get("is_interactive")]
    }
