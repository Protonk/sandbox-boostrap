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


def test_runtime_signature_info():
    info = carton_query.runtime_signature_info("bucket4:v1_read")
    assert info["probes"]
    assert "read_/etc/hosts" in info["probes"]
    assert info["runtime_profile"]


def test_profiles_and_signatures_for_operation():
    info = carton_query.profiles_and_signatures_for_operation("file-read*")
    assert info["op_name"] == "file-read*"
    assert isinstance(info["op_id"], int)
    assert info["known"] is True
    assert "sys:bsd" in info["system_profiles"]
    assert "bucket4:v1_read" in info["runtime_signatures"]
    counts = info.get("counts") or {}
    assert counts.get("system_profiles", 0) > 0


def test_ops_with_low_coverage_returns_sorted():
    low = carton_query.ops_with_low_coverage(threshold=0)
    assert isinstance(low, list)
    if low:
        total = low[0]["counts"]["system_profiles"] + low[0]["counts"]["runtime_signatures"]
        assert total == min(
            entry["counts"]["system_profiles"] + entry["counts"]["runtime_signatures"] for entry in low
        )


def test_unknown_operation_raises():
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.profiles_and_signatures_for_operation("not-a-real-op")


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
