
import pytest

from threatlens_ai.file_integrity import (
    save_baseline,
    check_integrity,
)


def test_unchanged_file_passes(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    save_baseline(str(sample), str(baseline))

    result = check_integrity(str(sample), str(baseline))

    assert result == "INTEGRITY OK: No changes detected."


def test_modified_file_is_detected(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    save_baseline(str(sample), str(baseline))
    sample.write_text("Modified content", encoding="utf-8")

    result = check_integrity(str(sample), str(baseline))

    assert result == "WARNING: File modification detected!"


def test_missing_file_raises_error(tmp_path):
    missing = tmp_path / "missing.txt"
    baseline = tmp_path / "baseline.json"

    with pytest.raises(FileNotFoundError):
        check_integrity(str(missing), str(baseline))


def test_missing_baseline_raises_error(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "missing_baseline.json"
    sample.write_text("Original content", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        check_integrity(str(sample), str(baseline))
