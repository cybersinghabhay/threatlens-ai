from datetime import datetime, timezone

from threatlens_ai.file_integrity import get_integrity_details


def generate_integrity_report(
    file_path: str,
    baseline_path: str = "baseline.json",
) -> dict:
    """Generate a structured report about a file's integrity."""
    details = get_integrity_details(file_path, baseline_path)

    return {
        **details,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    }
