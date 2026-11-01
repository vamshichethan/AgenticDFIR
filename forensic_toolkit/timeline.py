"""
Timeline Generator Wrapper
Maintains backwards compatibility and invokes the super-timeline engine.
"""

from pathlib import Path
from forensic_toolkit.utils import log, PROJECT_ROOT
from forensic_toolkit.super_timeline import build_super_timeline


def create_timeline():
    """CLI trigger for timeline generation."""
    log("Timeline Generated")
    print("\n" + "=" * 60)
    print("FORENSIC SUPER-TIMELINE & EVENT CORRELATION ENGINE")
    print("=" * 60)

    evidence = PROJECT_ROOT / "Evidence"
    if not evidence.exists():
        print(f"\nError: Evidence directory not found at: {evidence}")
        input("\nPress Enter...")
        return

    try:
        data = build_super_timeline(evidence)
        print(f"\n[OK] Successfully correlated {data['total_events']} events across log sources.")
        print(f"Severity Breakdown: Critical={data['severity_summary']['CRITICAL']}, High={data['severity_summary']['HIGH']}")
        print(f"Compromised Accounts: {', '.join(data['compromised_users']) or 'None'}")
        print(f"Suspicious IPs: {', '.join(data['suspicious_ips'])}")

        outfile = PROJECT_ROOT / "Timeline" / "timeline.txt"
        print(f"\nTimeline saved to: {outfile}")
    except Exception as e:
        print(f"\nError generating timeline: {e}")

    input("\nPress Enter...")
