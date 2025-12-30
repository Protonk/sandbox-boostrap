import json
from pathlib import Path

import pytest

from book.api.carton import carton_query


def _write_temp_manifest(tmp_path: Path, logical_overrides=None) -> Path:
    logical_overrides = logical_overrides or {}
    manifest = json.loads(carton_query.CARTON_MANIFEST.read_text())
    files = []
    for entry in manifest.get("files", []):
        updated = dict(entry)
        for logical, override in logical_overrides.items():
            target_path = carton_query.LOGICAL_PATHS[logical]
            if entry.get("path") == target_path:
                updated["path"] = override["path"]
                if "sha256" in override:
                    updated["sha256"] = override["sha256"]
        files.append(updated)
    manifest["files"] = files
    manifest_path = tmp_path / "CARTON.json"
    manifest_path.write_text(json.dumps(manifest))
    return manifest_path


def test_profiles_with_operation():
    profiles = carton_query.profiles_with_operation("file-read*")
    assert profiles, "expected at least one profile with file-read*"
    assert "sys:bsd" in profiles


def test_profiles_and_signatures_for_operation():
    """Coverage helper should surface canonical status alongside counts."""
    info = carton_query.profiles_and_signatures_for_operation("file-read*")
    assert info["op_name"] == "file-read*"
    assert isinstance(info["op_id"], int)
    assert info["known"] is True
    assert "sys:bsd" in info["system_profiles"]
    counts = info.get("counts") or {}
    assert counts.get("system_profiles", 0) > 0
    assert counts.get("system_profiles_ok", 0) > 0
    assert info.get("coverage_status") == "ok"
    assert info.get("canonical_profile_status")


def test_ops_with_low_coverage_returns_sorted():
    low = carton_query.ops_with_low_coverage(threshold=0)
    assert isinstance(low, list)
    if low:
        total = low[0]["counts"]["system_profiles"]
        assert total == min(entry["counts"]["system_profiles"] for entry in low)


def test_operation_story_returns_combined_view():
    story = carton_query.operation_story("file-read*")
    assert story["op_name"] == "file-read*"
    assert story["known"] is True
    assert "sys:bsd" in story["system_profiles"]
    assert story["coverage_counts"]["system_profiles"] >= 1
    assert "system" in story["profile_layers"]
    assert story.get("coverage_status") == "ok"
    assert story.get("system_profile_status")


def test_profile_story_returns_ops_and_signatures():
    """Profile story should expose ops while reporting canonical health."""
    story = carton_query.profile_story("sys:bsd")
    assert story["profile_id"] == "sys:bsd"
    assert story["layer"] == "system"
    assert story.get("status") == "ok"
    assert story["ops"], "expected ops for sys:bsd"
    assert any(op["name"] == "file-read*" for op in story["ops"])
    assert story["filters"]["known"] is False
    assert story.get("canonical_profile_status")
    assert story.get("coverage_status") == "ok"


def test_profile_story_unknown_profile_raises(monkeypatch):
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profile_story("not-a-real-profile")
    # Known profile should expose a conservative filters block
    story = carton_query.profile_story("sys:bsd")
    assert story["filters"]["known"] is False


def test_unknown_operation_raises():
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.profiles_and_signatures_for_operation("not-a-real-op")
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.operation_story("not-a-real-op")


def test_filter_story_and_discovery_helpers():
    filters = carton_query.list_filters()
    assert "path" in filters
    story = carton_query.filter_story("path")
    assert story["filter_name"] == "path"
    assert story["known"] is True
    assert story["usage_status"] in {
        "present-in-vocab-only",
        "referenced-in-profiles",
        "referenced-in-runtime",
        "unknown",
    }
    ops = carton_query.list_operations()
    assert "file-read*" in ops
    profiles = carton_query.list_profiles()
    assert "sys:bsd" in profiles


def test_filter_story_unknown_filter_raises():
    with pytest.raises(carton_query.CartonDataError):
        carton_query.filter_story("not-a-filter")


def test_missing_mapping_yields_carton_error(monkeypatch, tmp_path):
    missing_path = str(tmp_path / "nope.json")
    manifest_path = _write_temp_manifest(tmp_path, {"carton.coverage": {"path": missing_path}})
    logical_paths = dict(carton_query.LOGICAL_PATHS)
    logical_paths["carton.coverage"] = missing_path
    monkeypatch.setattr(carton_query, "_MANIFEST_CACHE", None)
    monkeypatch.setattr(carton_query, "CARTON_MANIFEST", manifest_path)
    monkeypatch.setattr(carton_query, "LOGICAL_PATHS", logical_paths)
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profiles_and_signatures_for_operation("file-read*")


def test_malformed_mapping_yields_carton_error(monkeypatch, tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json")
    manifest_path = _write_temp_manifest(tmp_path, {"carton.coverage": {"path": str(bad_file)}})
    logical_paths = dict(carton_query.LOGICAL_PATHS)
    logical_paths["carton.coverage"] = str(bad_file)
    monkeypatch.setattr(carton_query, "_MANIFEST_CACHE", None)
    monkeypatch.setattr(carton_query, "CARTON_MANIFEST", manifest_path)
    monkeypatch.setattr(carton_query, "LOGICAL_PATHS", logical_paths)
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profiles_and_signatures_for_operation("file-read*")


def test_manifest_hash_mismatch_yields_carton_error(monkeypatch, tmp_path):
    original_manifest = json.loads(carton_query.CARTON_MANIFEST.read_text())
    coverage_path_str = carton_query.LOGICAL_PATHS["carton.coverage"]
    coverage_entry = next(entry for entry in original_manifest["files"] if entry.get("path") == coverage_path_str)
    coverage_path = Path(carton_query.ROOT / coverage_entry["path"])
    modified = tmp_path / "coverage_modified.json"
    modified.write_text(coverage_path.read_text() + "\n ")
    manifest_path = _write_temp_manifest(
        tmp_path,
        {
            "carton.coverage": {
                "path": str(modified),
                "sha256": coverage_entry["sha256"],
            }
        },
    )
    logical_paths = dict(carton_query.LOGICAL_PATHS)
    logical_paths["carton.coverage"] = str(modified)
    monkeypatch.setattr(carton_query, "_MANIFEST_CACHE", None)
    monkeypatch.setattr(carton_query, "CARTON_MANIFEST", manifest_path)
    monkeypatch.setattr(carton_query, "LOGICAL_PATHS", logical_paths)
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profiles_and_signatures_for_operation("file-read*")
