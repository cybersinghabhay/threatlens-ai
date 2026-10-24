import json

from threatlens_ai.directory_integrity import (
    save_directory_baseline,
)
from threatlens_ai.directory_report import (
    generate_directory_integrity_report,
    export_directory_integrity_report,
)


def test_generate_report_with_no_changes(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    (monitored_dir / "example.txt").write_text(
        "Original content",
        encoding="utf-8",
    )

    baseline = tmp_path / "directory_baseline.json"

    save_directory_baseline(
        str(monitored_dir),
        str(baseline),
    )

    report = generate_directory_integrity_report(
        str(monitored_dir),
        str(baseline),
    )

    assert report["status"] == "NO CHANGES DETECTED"
    assert report["total_changes"] == 0
    assert report["summary"] == {
        "added": 0,
        "modified": 0,
        "deleted": 0,
    }


def test_generate_report_detects_added_file(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    baseline = tmp_path / "directory_baseline.json"

    save_directory_baseline(
        str(monitored_dir),
        str(baseline),
    )

    (monitored_dir / "new_file.txt").write_text(
        "New content",
        encoding="utf-8",
    )

    report = generate_directory_integrity_report(
        str(monitored_dir),
        str(baseline),
    )

    assert report["status"] == "CHANGES DETECTED"
    assert report["summary"]["added"] == 1
    assert report["total_changes"] == 1


def test_report_contains_utc_timestamp(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    baseline = tmp_path / "directory_baseline.json"

    save_directory_baseline(
        str(monitored_dir),
        str(baseline),
    )

    report = generate_directory_integrity_report(
        str(monitored_dir),
        str(baseline),
    )

    assert report["checked_at_utc"].endswith("+00:00")


def test_export_directory_report_to_json(tmp_path):
    report = {
        "status": "NO CHANGES DETECTED",
        "total_changes": 0,
    }

    output_file = tmp_path / "directory_report.json"

    saved_path = export_directory_integrity_report(
        report,
        str(output_file),
    )

    saved_data = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert saved_data == report
    assert saved_path == str(output_file.resolve())