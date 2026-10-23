from datetime import datetime

from threatlens_ai.file_integrity import save_baseline
from threatlens_ai.integrity_report import generate_integrity_report


def test_report_contains_correct_hashes_and_path(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    save_baseline(str(sample), str(baseline))

    report = generate_integrity_report(str(sample), str(baseline))

    assert report["file_path"] == str(sample.resolve())
    assert report["expected_sha256"] == report["current_sha256"]


def test_report_shows_unchanged_status(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    save_baseline(str(sample), str(baseline))

    report = generate_integrity_report(str(sample), str(baseline))

    assert report["status"] == "INTEGRITY OK: No changes detected."


def test_report_detects_modified_file(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    save_baseline(str(sample), str(baseline))
    sample.write_text("Modified content", encoding="utf-8")

    report = generate_integrity_report(str(sample), str(baseline))

    assert report["status"] == "WARNING: File modification detected!"
    assert report["expected_sha256"] != report["current_sha256"]


def test_report_has_utc_timestamp(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    save_baseline(str(sample), str(baseline))

    report = generate_integrity_report(str(sample), str(baseline))
    timestamp = datetime.fromisoformat(report["checked_at_utc"])

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0
