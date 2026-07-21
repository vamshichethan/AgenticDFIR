"""
Utility functions
"""

from pathlib import Path
from datetime import datetime

# Dynamically resolve PROJECT_ROOT to the repository directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_DIR = PROJECT_ROOT / "Logs"

LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "investigation.log"


def log(message):

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(f"{datetime.now()} : {message}\n")
    except Exception:
        pass