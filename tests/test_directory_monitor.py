
from pathlib import Path

import pytest

from threatlens_ai.directory_monitor import scan_directory
from threatlens_ai.file_integrity import calculate_sha256


def test_scan_directory_hashes_multiple_files(tmp_path):
    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"

    first_file.write_text("Hello", encoding="utf-8")
    second_file.write_text("ThreatLens AI", encoding="utf-8")

    results = scan_directory(str(tmp_path))

    assert len(results) == 2
    assert results[str(first_file.resolve())] == calculate_sha256(
        str(first_file)
    )
    assert results[str(second_file.resolve())] == calculate_sha256(
        str(second_file)
    )


def test_scan_directory_includes_nested_files(tmp_path):
    nested_directory = tmp_path / "nested"
    nested_directory.mkdir()

    nested_file = nested_directory / "example.txt"
    nested_file.write_text("Nested file", encoding="utf-8")

    results = scan_directory(str(tmp_path))

    assert str(nested_file.resolve()) in results


def test_scan_directory_ignores_python_cache(tmp_path):
    cache_directory = tmp_path / "__pycache__"
    cache_directory.mkdir()

    cache_file = cache_directory / "example.pyc"
    cache_file.write_bytes(b"test cache data")

    regular_file = tmp_path / "example.txt"
    regular_file.write_text("Keep this file", encoding="utf-8")

    results = scan_directory(str(tmp_path))

    assert str(regular_file.resolve()) in results
    assert str(cache_file.resolve()) not in results


def test_scan_directory_rejects_missing_directory(tmp_path):
    missing_directory = tmp_path / "does_not_exist"

    with pytest.raises(NotADirectoryError):
        scan_directory(str(missing_directory))


def test_scan_directory_rejects_file_path(tmp_path):
    regular_file = tmp_path / "example.txt"
    regular_file.write_text("Hello", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        scan_directory(str(regular_file))
