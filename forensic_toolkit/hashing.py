"""
Cryptographic Evidence Hashing & Entropy Verification Module
Calculates MD5, SHA-1, SHA-256, and Shannon Entropy for Forensic Evidence Integrity.
"""

import math
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter
from forensic_toolkit.utils import log, PROJECT_ROOT


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while chunk := file.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_md5(file_path: Path) -> str:
    """Calculate MD5 hash of a file."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        while chunk := file.read(65536):
            md5.update(chunk)
    return md5.hexdigest()


def calculate_sha1(file_path: Path) -> str:
    """Calculate SHA-1 hash of a file."""
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as file:
        while chunk := file.read(65536):
            sha1.update(chunk)
    return sha1.hexdigest()


def calculate_entropy(file_path: Path) -> float:
    """
    Calculate Shannon Entropy of a file (0.0 to 8.0 bits/byte).
    Values > 7.2 typically indicate compressed, packed, or encrypted/ransomware data.
    """
    byte_counts = Counter()
    total_bytes = 0

    with open(file_path, "rb") as file:
        while chunk := file.read(65536):
            byte_counts.update(chunk)
            total_bytes += len(chunk)

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts.values():
        p_x = count / total_bytes
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def get_file_metadata(file_path: Path) -> dict:
    """Return comprehensive cryptographic and metadata analysis of a forensic file."""
    stat = file_path.stat()
    md5 = calculate_md5(file_path)
    sha1 = calculate_sha1(file_path)
    sha256 = calculate_sha256(file_path)
    entropy = calculate_entropy(file_path)

    # Classify entropy
    if entropy >= 7.2:
        entropy_class = "High (Likely Encrypted / Compressed)"
    elif entropy >= 5.0:
        entropy_class = "Medium (Structured Binary / Rich Text)"
    else:
        entropy_class = "Low (Plain Text / Sparse Data)"

    return {
        "filename": file_path.name,
        "path": str(file_path),
        "size_bytes": stat.st_size,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "entropy": entropy,
        "entropy_class": entropy_class,
        "modified_time": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "created_time": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
    }


def hash_menu():
    """Interactive CLI menu for hash computation and verification."""
    log("Cryptographic Hashes Generated")
    print("\n" + "=" * 60)
    print("FORENSIC CRYPTOGRAPHIC INTEGRITY & HASH ENGINE")
    print("=" * 60)

    evidence_path = PROJECT_ROOT / "Evidence"
    hash_path = PROJECT_ROOT / "Hashes"

    if not evidence_path.exists():
        print(f"\nError: Evidence directory not found at: {evidence_path}")
        input("\nPress Enter to continue...")
        return

    hash_path.mkdir(exist_ok=True)
    baseline_file = hash_path / "sha256_hashes.txt"

    # Read existing baseline hashes if present
    baseline_hashes = {}
    if baseline_file.exists():
        try:
            content = baseline_file.read_text(encoding="utf-8")
            records = content.split("\n\n")
            for rec in records:
                lines = [l.strip() for l in rec.split("\n") if l.strip()]
                if len(lines) >= 2:
                    baseline_hashes[lines[0]] = lines[1]
        except Exception:
            pass

    is_first_run = len(baseline_hashes) == 0
    results = []
    has_tampered = False

    print("\nProcessing evidence files...")
    for filepath in sorted(evidence_path.glob("*")):
        if filepath.is_file():
            meta = get_file_metadata(filepath)
            status = "verified"
            baseline_hash = baseline_hashes.get(filepath.name, "")

            if not is_first_run:
                if filepath.name in baseline_hashes:
                    if meta["sha256"] != baseline_hash:
                        status = "tampered"
                        has_tampered = True
                else:
                    status = "new"
            else:
                baseline_hash = meta["sha256"]

            meta["status"] = status
            meta["baseline_hash"] = baseline_hash
            results.append(meta)

    try:
        if is_first_run:
            print("\n>>> FIRST RUN: Recording Baseline Hashes <<<\n")
            with open(baseline_file, "w", encoding="utf-8") as f:
                for res in results:
                    print(f"File   : {res['filename']} ({res['size_bytes']} bytes)")
                    print(f"SHA-256: {res['sha256']}")
                    print(f"MD5    : {res['md5']}")
                    print(f"Entropy: {res['entropy']} - {res['entropy_class']}")
                    print("Status : [Baseline Recorded]\n")
                    f.write(f"{res['filename']}\n{res['sha256']}\n\n")
            print(f"Baseline saved to: {baseline_file}")
        else:
            print("\n>>> VERIFICATION RUN: Checking against Baseline <<<\n")
            verify_file = hash_path / "sha256_hashes_verification.txt"
            with open(verify_file, "w", encoding="utf-8") as f:
                f.write(f"Verification Run: {datetime.now()}\n\n")
                for res in results:
                    print(f"File   : {res['filename']}")
                    print(f"SHA-256: {res['sha256']}")
                    if res['status'] == "tampered":
                        print(f"Status : [WARNING: TAMPERED] Expected: {res['baseline_hash']}\n")
                        f.write(f"{res['filename']}\nHash: {res['sha256']}\nStatus: tampered (Baseline: {res['baseline_hash']})\n\n")
                    elif res['status'] == "new":
                        print("Status : [NEW: Untracked] Not in baseline\n")
                        f.write(f"{res['filename']}\nHash: {res['sha256']}\nStatus: new\n\n")
                    else:
                        print("Status : [Verified] Integrity confirmed\n")
                        f.write(f"{res['filename']}\nHash: {res['sha256']}\nStatus: verified\n\n")

            print(f"Verification log saved to: {verify_file}")
            if has_tampered:
                print("\n[WARNING] Integrity violation detected in evidence files!")
            else:
                print("\n[SUCCESS] All checked files match baseline.")

    except Exception as e:
        print(f"\nError running hashes: {e}")

    input("\nPress Enter to continue...")
