
import json
from datetime import datetime, timezone
from pathlib import Path

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


def export_integrity_report(
    report: dict,
    output_path: str = "integrity_report.json",
) -> str:
    """Export an integrity report to a JSON file."""
    report_file = Path(output_path)

    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return str(report_file.resolve())
