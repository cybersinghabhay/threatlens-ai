
import json

from threatlens_ai.directory_integrity import (
    compare_directory_with_baseline,
    save_directory_baseline,
)


def test_detects_added_file(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = tmp_path / "baseline.json"

    (monitored / "existing.txt").write_text("Original", encoding="utf-8")
    save_directory_baseline(str(monitored), str(baseline))

    added_file = monitored / "new.txt"
    added_file.write_text("New file", encoding="utf-8")

    result = compare_directory_with_baseline(
        str(monitored), str(baseline)
    )

    assert result["added"] == [str(added_file.resolve())]
    assert result["modified"] == []
    assert result["deleted"] == []


def test_detects_modified_file(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = tmp_path / "baseline.json"

    target = monitored / "example.txt"
    target.write_text("Original", encoding="utf-8")
    save_directory_baseline(str(monitored), str(baseline))

    target.write_text("Changed content", encoding="utf-8")

    result = compare_directory_with_baseline(
        str(monitored), str(baseline)
    )

    assert result["added"] == []
    assert result["modified"] == [str(target.resolve())]
    assert result["deleted"] == []


def test_detects_deleted_file(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = tmp_path / "baseline.json"

    target = monitored / "example.txt"
    target.write_text("Original", encoding="utf-8")
    save_directory_baseline(str(monitored), str(baseline))

    target.unlink()

    result = compare_directory_with_baseline(
        str(monitored), str(baseline)
    )

    assert result["added"] == []
    assert result["modified"] == []
    assert result["deleted"] == [str(target.resolve())]


def test_detects_multiple_change_types(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = tmp_path / "baseline.json"

    modified_file = monitored / "modify.txt"
    deleted_file = monitored / "delete.txt"

    modified_file.write_text("Original", encoding="utf-8")
    deleted_file.write_text("Remove me", encoding="utf-8")

    save_directory_baseline(str(monitored), str(baseline))

    modified_file.write_text("Updated", encoding="utf-8")
    deleted_file.unlink()
    added_file = monitored / "added.txt"
    added_file.write_text("New", encoding="utf-8")

    result = compare_directory_with_baseline(
        str(monitored), str(baseline)
    )

    assert result["added"] == [str(added_file.resolve())]
    assert result["modified"] == [str(modified_file.resolve())]
    assert result["deleted"] == [str(deleted_file.resolve())]


def test_rejects_invalid_baseline_json(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{invalid json", encoding="utf-8")

    import pytest

    with pytest.raises(ValueError, match="invalid JSON"):
        compare_directory_with_baseline(
            str(monitored), str(baseline)
        )


def test_rejects_invalid_baseline_hash(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"example.txt": "not-a-valid-hash"}),
        encoding="utf-8",
    )

    import pytest

    with pytest.raises(ValueError, match="Invalid directory baseline"):
        compare_directory_with_baseline(
            str(monitored), str(baseline)
        )
