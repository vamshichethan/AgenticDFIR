"""
SHA256 Evidence Hash Generator
"""

import hashlib
from pathlib import Path
from datetime import datetime
from forensic_toolkit.utils import log, PROJECT_ROOT


def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def hash_menu():
    log("SHA256 Hashes Generated")
    print("\n" + "=" * 60)
    print("SHA256 HASH GENERATOR")
    print("=" * 60)

    evidence_path = PROJECT_ROOT / "Evidence"
    hash_path = PROJECT_ROOT / "Hashes"

    if not evidence_path.exists():
        print(f"\nError: Evidence directory not found at: {evidence_path}")
        input("\nPress Enter to continue...")
        return

    hash_path.mkdir(exist_ok=True)
    output_file = hash_path / "sha256_hashes.txt"

    # Read existing baseline hashes if present
    baseline_hashes = {}
    if output_file.exists():
        try:
            content = output_file.read_text(encoding="utf-8")
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
    for filepath in evidence_path.glob("*"):
        if filepath.is_file():
            digest = calculate_sha256(filepath)
            status = "verified"
            baseline_hash = baseline_hashes.get(filepath.name, "")

            if not is_first_run:
                if filepath.name in baseline_hashes:
                    if digest != baseline_hash:
                        status = "tampered"
                        has_tampered = True
                else:
                    status = "new"
            else:
                baseline_hash = digest

            results.append({
                "filename": filepath.name,
                "hash": digest,
                "baseline_hash": baseline_hash,
                "status": status
            })

    try:
        if is_first_run:
            print("\n>>> FIRST RUN: Recording Baseline Hashes <<<\n")
            with open(output_file, "w", encoding="utf-8") as f:
                for res in results:
                    print(f"File   : {res['filename']}")
                    print(f"Hash   : {res['hash']}")
                    print("Status : [Baseline Recorded]\n")
                    f.write(f"{res['filename']}\n{res['hash']}\n\n")
            print(f"Baseline saved to: {output_file}")
        else:
            print("\n>>> VERIFICATION RUN: Checking against Baseline <<<\n")
            verify_file = hash_path / "sha256_hashes_verification.txt"
            
            # Print to stdout and compile verification report
            with open(verify_file, "w", encoding="utf-8") as f:
                f.write(f"Verification Run: {datetime.now()}\n\n")
                
                for res in results:
                    print(f"File   : {res['filename']}")
                    print(f"Hash   : {res['hash']}")
                    if res['status'] == "tampered":
                        print(f"Status : [WARNING: TAMPERED] - Expected: {res['baseline_hash']}\n")
                        f.write(f"{res['filename']}\nHash: {res['hash']}\nStatus: tampered (Baseline: {res['baseline_hash']})\n\n")
                    elif res['status'] == "new":
                        print("Status : [NEW: Untracked] - Not in baseline\n")
                        f.write(f"{res['filename']}\nHash: {res['hash']}\nStatus: new\n\n")
                    else:
                        print("Status : [Verified] - Integrity confirmed\n")
                        f.write(f"{res['filename']}\nHash: {res['hash']}\nStatus: verified\n\n")
            
            print(f"Verification log saved to: {verify_file}")
            if has_tampered:
                print("\n[WARNING] Integrity violation detected in evidence files!")
            else:
                print("\n[SUCCESS] All checked files match baseline.")
                
    except Exception as e:
        print(f"\nError running hashes: {e}")

    input("\nPress Enter to continue...")