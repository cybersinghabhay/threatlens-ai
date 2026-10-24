import json
from datetime import datetime, timezone
from pathlib import Path

from threatlens_ai.directory_integrity import (
    compare_directory_with_baseline,
)


def generate_directory_integrity_report(
    directory_path: str,
    baseline_path: str = "directory_baseline.json",
) -> dict:
    """Generate a structured report of directory integrity changes."""
    changes = compare_directory_with_baseline(
        directory_path,
        baseline_path,
    )

    summary = {
        "added": len(changes["added"]),
        "modified": len(changes["modified"]),
        "deleted": len(changes["deleted"]),
    }

    total_changes = sum(summary.values())

    return {
        "directory_path": str(Path(directory_path).resolve()),
        "baseline_path": str(Path(baseline_path).resolve()),
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "CHANGES DETECTED"
            if total_changes
            else "NO CHANGES DETECTED"
        ),
        "summary": summary,
        "total_changes": total_changes,
        "changes": changes,
    }


def export_directory_integrity_report(
    report: dict,
    output_path: str = "directory_integrity_report.json",
) -> str:
    """Export a directory integrity report to a JSON file."""
    report_file = Path(output_path)

    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return str(report_file.resolve())