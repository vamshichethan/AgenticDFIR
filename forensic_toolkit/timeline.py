"""
Timeline Generator
"""

from pathlib import Path
from datetime import datetime
from forensic_toolkit.utils import log, PROJECT_ROOT


def create_timeline():
    log("Timeline Generated")
    print("\n" + "=" * 60)
    print("FORENSIC TIMELINE")
    print("=" * 60)

    evidence = PROJECT_ROOT / "Evidence"
    report = PROJECT_ROOT / "Timeline"

    if not evidence.exists():
        print(f"\nError: Evidence directory not found at: {evidence}")
        input("\nPress Enter...")
        return

    report.mkdir(exist_ok=True)
    outfile = report / "timeline.txt"

    try:
        with open(outfile, "w", encoding="utf-8") as f:
            for file in sorted(evidence.iterdir()):
                if file.is_file():
                    stat = file.stat()
                    modified = datetime.fromtimestamp(stat.st_mtime)
                    line = f"{modified}  {file.name}"
                    print(line)
                    f.write(line + "\n")

        print("\nTimeline saved to:")
        print(outfile)
    except Exception as e:
        print(f"\nError generating timeline: {e}")

    input("\nPress Enter...")