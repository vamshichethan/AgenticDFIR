"""
Forensic Evidence Hex & String Inspector
Provides deep binary inspection, hex dump rendering, and printable string extraction.
"""

import string
from pathlib import Path
from forensic_toolkit.utils import PROJECT_ROOT

PRINTABLE_BYTES = set(bytes(string.printable, "ascii"))


def get_hex_dump(file_path: Path, offset: int = 0, length: int = 4096) -> dict:
    """
    Generate an industry-standard forensic hex dump:
    Offset (Hex) | 16 Hex Bytes | ASCII Representation
    """
    if not file_path.exists() or not file_path.is_file():
        return {"error": f"File not found: {file_path.name}"}

    total_size = file_path.stat().st_size
    lines = []

    with open(file_path, "rb") as f:
        f.seek(offset)
        chunk = f.read(length)

    bytes_read = len(chunk)

    for i in range(0, bytes_read, 16):
        sub_chunk = chunk[i:i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in sub_chunk)
        # Pad hex representation to align ASCII output
        hex_padded = f"{hex_bytes:<48}"
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub_chunk)
        line_offset = f"{offset + i:08x}"
        lines.append(f"{line_offset}  {hex_padded}  |{ascii_chars}|")

    return {
        "filename": file_path.name,
        "total_size": total_size,
        "offset": offset,
        "bytes_returned": bytes_read,
        "hex_dump": "\n".join(lines)
    }


def extract_strings(file_path: Path, min_length: int = 4, search_filter: str = None, max_results: int = 300) -> dict:
    """
    Extract printable ASCII strings from an evidence file.
    Crucial for recovering embedded URLs, IP addresses, credentials, or commands in binaries.
    """
    if not file_path.exists() or not file_path.is_file():
        return {"error": f"File not found: {file_path.name}"}

    extracted = []
    current_string = bytearray()
    search_lower = search_filter.lower() if search_filter else None

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            for byte in chunk:
                if byte in PRINTABLE_BYTES and byte not in (10, 13, 9):  # printable excluding newlines
                    current_string.append(byte)
                else:
                    if len(current_string) >= min_length:
                        try:
                            s = current_string.decode("ascii", errors="ignore")
                            if not search_lower or search_lower in s.lower():
                                extracted.append(s)
                                if len(extracted) >= max_results:
                                    break
                        except Exception:
                            pass
                    current_string = bytearray()
            if len(extracted) >= max_results:
                break

    # Final string check
    if len(current_string) >= min_length and len(extracted) < max_results:
        s = current_string.decode("ascii", errors="ignore")
        if not search_lower or search_lower in s.lower():
            extracted.append(s)

    return {
        "filename": file_path.name,
        "min_length": min_length,
        "filter": search_filter,
        "total_found": len(extracted),
        "strings": extracted
    }

