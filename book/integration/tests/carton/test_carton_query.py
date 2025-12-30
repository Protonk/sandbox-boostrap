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


def test_carton_query_smoke_and_facade_contract():
    for name in carton_query.__all__:
        assert hasattr(carton_query, name)

    paths = carton_query.list_carton_paths()
    for key in ("vocab_ops", "system_profiles", "coverage"):
        assert key in paths

    ops = carton_query.list_operations()
    profiles = carton_query.list_profiles()
    filters = carton_query.list_filters()
    assert isinstance(ops, list) and ops
    assert isinstance(profiles, list) and profiles
    assert isinstance(filters, list) and filters
    assert all(isinstance(x, str) for x in ops)
    assert all(isinstance(x, str) for x in profiles)
    assert all(isinstance(x, str) for x in filters)

    assert "file-read*" in ops
    assert "sys:bsd" in profiles
    assert "path" in filters

    assert "sys:bsd" in carton_query.profiles_with_operation("file-read*")

    info = carton_query.profiles_and_signatures_for_operation("file-read*")
    assert info.get("op_name") == "file-read*"
    assert isinstance(info.get("op_id"), int)
    assert info.get("known") is True
    assert "sys:bsd" in (info.get("system_profiles") or [])
    counts = info.get("counts") or {}
    assert counts.get("system_profiles", 0) > 0
    assert counts.get("system_profiles_ok", 0) > 0
    assert info.get("coverage_status") == "ok"

    story = carton_query.operation_story("file-read*")
    assert story.get("op_name") == "file-read*"
    assert story.get("known") is True
    assert "sys:bsd" in (story.get("system_profiles") or [])
    assert (story.get("coverage_counts") or {}).get("system_profiles", 0) >= 1
    assert "system" in (story.get("profile_layers") or {})
    assert story.get("coverage_status") == "ok"

    prof_story = carton_query.profile_story("sys:bsd")
    assert prof_story.get("profile_id") == "sys:bsd"
    assert prof_story.get("layer") == "system"
    assert prof_story.get("status") == "ok"
    assert prof_story.get("ops"), "expected ops for sys:bsd"
    assert any(op.get("name") == "file-read*" for op in (prof_story.get("ops") or []))
    assert (prof_story.get("filters") or {}).get("known") is False
    assert prof_story.get("coverage_status") == "ok"

    filter_story = carton_query.filter_story("path")
    assert filter_story.get("filter_name") == "path"
    assert filter_story.get("known") is True
    assert filter_story.get("usage_status") in {
        "present-in-vocab-only",
        "referenced-in-profiles",
        "referenced-in-runtime",
        "unknown",
    }

    low = carton_query.ops_with_low_coverage(threshold=0)
    assert isinstance(low, list)
    if low:
        totals = [entry.get("counts", {}).get("system_profiles", 0) for entry in low]
        assert totals[0] == min(totals)


def test_carton_query_unknown_ids_raise():
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.profiles_and_signatures_for_operation("definitely-not-an-op")
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.operation_story("definitely-not-an-op")

    with pytest.raises(carton_query.CartonDataError):
        carton_query.profile_story("not-a-real-profile")

    with pytest.raises(carton_query.CartonDataError):
        carton_query.filter_story("definitely-not-a-filter")


def test_carton_query_manifest_errors_are_wrapped(monkeypatch, tmp_path):
    def _install_test_manifest(manifest_path: Path, logical_paths: dict) -> None:
        monkeypatch.setattr(carton_query, "_MANIFEST_CACHE", None)
        monkeypatch.setattr(carton_query, "CARTON_MANIFEST", manifest_path)
        monkeypatch.setattr(carton_query, "LOGICAL_PATHS", logical_paths)

    missing_path = str(tmp_path / "nope.json")
    manifest_path = _write_temp_manifest(tmp_path, {"carton.coverage": {"path": missing_path}})
    logical_paths = dict(carton_query.LOGICAL_PATHS)
    logical_paths["carton.coverage"] = missing_path
    _install_test_manifest(manifest_path, logical_paths)
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profiles_and_signatures_for_operation("file-read*")

    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json")
    manifest_path = _write_temp_manifest(tmp_path, {"carton.coverage": {"path": str(bad_file)}})
    logical_paths = dict(carton_query.LOGICAL_PATHS)
    logical_paths["carton.coverage"] = str(bad_file)
    _install_test_manifest(manifest_path, logical_paths)
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profiles_and_signatures_for_operation("file-read*")

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
    _install_test_manifest(manifest_path, logical_paths)
    with pytest.raises(carton_query.CartonDataError):
        carton_query.profiles_and_signatures_for_operation("file-read*")
