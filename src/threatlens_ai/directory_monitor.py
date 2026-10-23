
from pathlib import Path

from threatlens_ai.file_integrity import calculate_sha256


def scan_directory(directory_path: str) -> dict[str, str]:
    """Calculate SHA-256 hashes for files, excluding Python cache folders."""
    root = Path(directory_path).resolve()

    if not root.is_dir():
        raise NotADirectoryError(
            f"Directory not found or not a directory: {root}"
        )

    file_hashes = {}

    for file_path in sorted(root.rglob("*")):
        # Ignore files inside Python cache directories.
        if "__pycache__" in file_path.parts:
            continue

        if file_path.is_file():
            resolved_path = str(file_path.resolve())
            file_hashes[resolved_path] = calculate_sha256(resolved_path)

    return file_hashes
