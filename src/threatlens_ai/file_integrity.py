
import hashlib
import json
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def save_baseline(file_path: str, baseline_path: str = "baseline.json") -> str:
    """Calculate a file hash and save it as a baseline."""
    target = Path(file_path).resolve()
    baseline_file = Path(baseline_path)

    if not target.is_file():
        raise FileNotFoundError(f"File not found: {target}")

    file_hash = calculate_sha256(str(target))

    if baseline_file.exists():
        data = json.loads(baseline_file.read_text(encoding="utf-8"))
    else:
        data = {}

    data[str(target)] = file_hash

    baseline_file.write_text(
        json.dumps(data, indent=4),
        encoding="utf-8",
    )

    return file_hash


def check_integrity(
    file_path: str,
    baseline_path: str = "baseline.json",
) -> str:
    """Compare a file's current hash with its saved baseline."""
    target = Path(file_path).resolve()
    baseline_file = Path(baseline_path)

    if not target.is_file():
        raise FileNotFoundError(f"File not found: {target}")

    if not baseline_file.is_file():
        raise FileNotFoundError(
            "Baseline not found. Save a baseline first."
        )

    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    saved_hash = data.get(str(target))

    if saved_hash is None:
        raise KeyError("This file has no saved baseline.")

    current_hash = calculate_sha256(str(target))

    if current_hash == saved_hash:
        return "INTEGRITY OK: No changes detected."

    return "WARNING: File modification detected!"
