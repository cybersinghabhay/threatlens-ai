
import json
from pathlib import Path

from threatlens_ai.directory_monitor import scan_directory


def save_directory_baseline(
    directory_path: str,
    baseline_path: str = "directory_baseline.json",
) -> dict[str, str]:
    """Scan a directory and save its file hashes as a JSON baseline."""
    file_hashes = scan_directory(directory_path)
    output_file = Path(baseline_path)

    output_file.write_text(
        json.dumps(file_hashes, indent=4),
        encoding="utf-8",
    )

    return file_hashes


def compare_directory_with_baseline(
    directory_path: str,
    baseline_path: str = "directory_baseline.json",
) -> dict[str, list[str]]:
    """Detect added, modified, and deleted files in a directory."""
    baseline_file = Path(baseline_path)

    if not baseline_file.is_file():
        raise FileNotFoundError(
            f"Directory baseline not found: {baseline_file}"
        )

    try:
        baseline = json.loads(
            baseline_file.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(
            "Directory baseline contains invalid JSON or text."
        ) from error

    if not isinstance(baseline, dict) or not all(
        isinstance(path, str)
        and isinstance(file_hash, str)
        and len(file_hash) == 64
        and all(char in "0123456789abcdefABCDEF" for char in file_hash)
        for path, file_hash in baseline.items()
    ):
        raise ValueError("Invalid directory baseline format.")

    current = scan_directory(directory_path)

    baseline_paths = set(baseline)
    current_paths = set(current)

    added = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths)
    modified = sorted(
        path
        for path in baseline_paths & current_paths
        if baseline[path].lower() != current[path].lower()
    )

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
    }
