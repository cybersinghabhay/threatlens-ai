import pytest

from threatlens_ai.file_integrity import (
    calculate_sha256,
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


def test_corrupted_baseline_raises_value_error(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"

    sample.write_text("Original content", encoding="utf-8")
    baseline.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        check_integrity(str(sample), str(baseline))


def test_non_object_baseline_raises_value_error(tmp_path):
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.json"

    sample.write_text("Original content", encoding="utf-8")
    baseline.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="expected a JSON object"):
        check_integrity(str(sample), str(baseline))


from threatlens_ai.file_integrity import calculate_sha256


def test_empty_file_has_valid_sha256(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    result = calculate_sha256(str(empty_file))

    assert result == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )

def test_empty_file_has_valid_sha256(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    result = calculate_sha256(str(empty_file))

    assert result == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )