
import hashlib
import json
import re
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def _load_baseline(baseline_file: Path) -> dict[str, str]:
    """Load and validate a JSON file containing SHA-256 baselines."""
    try:
        data = json.loads(baseline_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(
            f"Baseline file contains invalid JSON or text: {baseline_file}"
        ) from error

    if not isinstance(data, dict):
        raise ValueError("Invalid baseline: expected a JSON object.")

    for file_path, file_hash in data.items():
        if not isinstance(file_path, str):
            raise ValueError("Invalid baseline: file paths must be strings.")

        if not isinstance(file_hash, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", file_hash
        ):
            raise ValueError(
                f"Invalid SHA-256 hash for baseline entry: {file_path}"
            )

    return data


def save_baseline(file_path: str, baseline_path: str = "baseline.json") -> str:
    """Calculate a file hash and save it as a baseline."""
    target = Path(file_path).resolve()
    baseline_file = Path(baseline_path)

    if not target.is_file():
        raise FileNotFoundError(f"File not found: {target}")

    if baseline_file.exists():
        if not baseline_file.is_file():
            raise ValueError("Baseline path must refer to a regular file.")

        data = _load_baseline(baseline_file)
    else:
        data = {}

    file_hash = calculate_sha256(str(target))
    data[str(target)] = file_hash

    baseline_file.write_text(
        json.dumps(data, indent=4),
        encoding="utf-8",
    )

    return file_hash



def get_integrity_details(
    file_path: str,
    baseline_path: str = "baseline.json",
) -> dict:
    """Return detailed information about a file's integrity."""
    target = Path(file_path).resolve()
    baseline_file = Path(baseline_path)

    if not target.is_file():
        raise FileNotFoundError(f"File not found: {target}")

    if not baseline_file.is_file():
        raise FileNotFoundError(
            "Baseline not found. Save a baseline first."
        )

    data = _load_baseline(baseline_file)
    expected_hash = data.get(str(target))

    if expected_hash is None:
        raise KeyError("This file has no saved baseline.")

    current_hash = calculate_sha256(str(target))

    if current_hash == expected_hash:
        status = "INTEGRITY OK: No changes detected."
    else:
        status = "WARNING: File modification detected!"

    return {
        "file_path": str(target),
        "expected_sha256": expected_hash,
        "current_sha256": current_hash,
        "status": status,
    }


def check_integrity(
    file_path: str,
    baseline_path: str = "baseline.json",
) -> str:
    """Compare a file's current hash with its saved baseline."""
    details = get_integrity_details(file_path, baseline_path)
    return details["status"]

