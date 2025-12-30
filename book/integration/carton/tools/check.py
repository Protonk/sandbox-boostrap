#!/usr/bin/env python3
"""CARTON verification entrypoint (hashes + invariants + provenance)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api import path_utils
from book.api import world as world_mod
from book.integration.carton import bundle
from book.integration.carton import paths
from book.integration.carton import spec as spec_mod

SCHEMA_DIR = paths.SCHEMAS_DIR


def _repo_root() -> Path:
    return paths.repo_root()


def _repo_rel(path: Path, repo_root: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=repo_root)


def _baseline_world_id(repo_root: Path) -> str:
    data, resolution = world_mod.load_world(repo_root=repo_root)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def _is_repo_relative(path: str) -> bool:
    p = Path(path)
    if p.is_absolute():
        return False
    if ".." in p.parts:
        return False
    return True


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _schema_type_ok(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _validate_schema(schema: Dict[str, Any], data: Any, path: str = "$") -> List[str]:
    errors: List[str] = []
    schema_type = schema.get("type")
    if schema_type and not _schema_type_ok(schema_type, data):
        errors.append(f"{path}: expected {schema_type}, got {type(data).__name__}")
        return errors

    if schema_type == "object":
        required = schema.get("required") or []
        if isinstance(required, list):
            for key in required:
                if key not in data:
                    errors.append(f"{path}: missing required key '{key}'")
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            for key, sub_schema in props.items():
                if key in data and isinstance(sub_schema, dict):
                    errors.extend(_validate_schema(sub_schema, data[key], f"{path}.{key}"))
    if schema_type == "array":
        items = schema.get("items")
        if items and isinstance(data, list) and isinstance(items, dict):
            for idx, item in enumerate(data):
                errors.extend(_validate_schema(items, item, f"{path}[{idx}]"))
    enum = schema.get("enum")
    if enum is not None and data not in enum:
        errors.append(f"{path}: value {data!r} not in enum")
    return errors


def _check_metadata_world_id(data: Dict[str, Any], world_id: str, label: str) -> List[str]:
    meta = data.get("metadata") or {}
    if meta.get("world_id") != world_id:
        return [f"{label}: metadata.world_id mismatch ({meta.get('world_id')} != {world_id})"]
    return []


def _check_metadata_inputs(data: Dict[str, Any], label: str) -> List[str]:
    meta = data.get("metadata") or {}
    inputs = meta.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        return [f"{label}: metadata.inputs missing or empty"]
    errors = []
    for item in inputs:
        if not isinstance(item, str) or not _is_repo_relative(item):
            errors.append(f"{label}: metadata.inputs not repo-relative: {item!r}")
    return errors


def _check_top_level_world_id(data: Dict[str, Any], world_id: str, label: str) -> List[str]:
    if data.get("world_id") != world_id:
        return [f"{label}: world_id mismatch ({data.get('world_id')} != {world_id})"]
    return []


def _check_inputs_field(data: Dict[str, Any], label: str) -> List[str]:
    inputs = data.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        return [f"{label}: inputs missing or empty"]
    errors = []
    for item in inputs:
        if not isinstance(item, str) or not _is_repo_relative(item):
            errors.append(f"{label}: inputs not repo-relative: {item!r}")
    return errors


CHECKS = {
    "metadata_world_id": _check_metadata_world_id,
    "metadata_inputs": _check_metadata_inputs,
    "top_level_world_id": _check_top_level_world_id,
    "inputs_field": _check_inputs_field,
}


def _contract_drift(repo_root: Path, world_id: str) -> List[str]:
    errors: List[str] = []
    expected = bundle.build_contracts(repo_root=repo_root, world_id=world_id)
    for rel_path, doc in expected.items():
        path = path_utils.ensure_absolute(rel_path, repo_root=repo_root)
        if not path.exists():
            errors.append(f"contract missing: {rel_path}")
            continue
        current = _load_json(path)
        if bundle._sha256_canonical_json(current) != bundle._sha256_canonical_json(doc):
            errors.append(f"contract drift: {rel_path} (regenerate contracts)")
    return errors


def _concept_sources_paths_manifested(repo_root: Path, manifest_paths: set[str]) -> List[str]:
    errors: List[str] = []
    concept_path = repo_root / "book/integration/carton/bundle/relationships/concept_sources.json"
    if not concept_path.exists():
        return ["concept_sources.json missing"]
    doc = _load_json(concept_path)
    for entries in (doc.get("concepts") or {}).values():
        for entry in entries:
            path = entry.get("path")
            if not path:
                errors.append("concept_sources entry missing path")
                continue
            if path not in manifest_paths:
                errors.append(f"concept_sources path not in manifest: {path}")
            if not (repo_root / path).exists():
                errors.append(f"concept_sources path missing on disk: {path}")
    return errors


def _fixer_outputs_manifested(repo_root: Path, manifest_paths: set[str]) -> List[str]:
    errors: List[str] = []
    fixers_path = paths.ensure_absolute(paths.FIXERS_SPEC, repo_root_path=repo_root)
    fixers_spec = spec_mod.load_fixers_spec(fixers_path)
    for fixer in fixers_spec.get("fixers") or []:
        fixer_id = fixer.get("id")
        for out in fixer.get("outputs") or []:
            if out not in manifest_paths:
                errors.append(f"fixer output not in manifest: {fixer_id} -> {out}")
    return errors


def _invariant_statuses(repo_root: Path, invariants: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    expected_profiles = invariants.get("canonical_profile_status") or {}
    if expected_profiles:
        digests_path = repo_root / "book/graph/mappings/system_profiles/digests.json"
        digests = _load_json(digests_path)
        canonical = (digests.get("metadata") or {}).get("canonical_profiles") or {}
        for profile_id, expected in expected_profiles.items():
            actual_entry = canonical.get(profile_id)
            actual = actual_entry.get("status") if isinstance(actual_entry, dict) else actual_entry
            if actual != expected:
                errors.append(
                    f"canonical profile status mismatch for {profile_id}: {actual!r} != {expected!r}"
                )
    expected_coverage = invariants.get("coverage_status")
    if expected_coverage:
        coverage_path = repo_root / "book/integration/carton/bundle/relationships/operation_coverage.json"
        coverage = _load_json(coverage_path)
        actual = (coverage.get("metadata") or {}).get("status")
        if actual != expected_coverage:
            errors.append(f"coverage status mismatch: {actual!r} != {expected_coverage!r}")
    return errors


def run_check(*, spec_path: Path, manifest_path: Path, repo_root: Path) -> List[str]:
    errors: List[str] = []
    spec = bundle.load_spec(spec_path)
    manifest = _load_json(manifest_path) if manifest_path.exists() else None
    if manifest is None:
        return [f"missing CARTON manifest: {_repo_rel(manifest_path, repo_root)}"]

    baseline_world_id = _baseline_world_id(repo_root)
    if manifest.get("world_id") != baseline_world_id:
        errors.append(f"manifest world_id mismatch: {manifest.get('world_id')} != {baseline_world_id}")
    spec_world = spec.get("world_id")
    if spec_world and spec_world != baseline_world_id:
        errors.append(f"spec world_id mismatch: {spec_world} != {baseline_world_id}")
    if manifest.get("schema_version") != bundle.MANIFEST_SCHEMA_VERSION:
        errors.append("manifest schema_version mismatch")
    spec_hash = bundle._sha256_canonical_json(spec)
    if manifest.get("spec_sha256") != spec_hash:
        errors.append("manifest spec_sha256 mismatch (regen CARTON.json)")
    if manifest.get("spec_path") != _repo_rel(spec_path, repo_root):
        errors.append("manifest spec_path mismatch")

    spec_entries = {entry["id"]: entry for entry in spec.get("artifacts", [])}
    manifest_entries = {entry.get("id"): entry for entry in manifest.get("artifacts", [])}

    extra = set(manifest_entries.keys()) - set(spec_entries.keys())
    missing = set(spec_entries.keys()) - set(manifest_entries.keys())
    if extra:
        errors.append(f"manifest has extra artifacts: {sorted(extra)}")
    if missing:
        errors.append(f"manifest missing artifacts: {sorted(missing)}")

    for artifact_id, spec_entry in spec_entries.items():
        manifest_entry = manifest_entries.get(artifact_id)
        if not manifest_entry:
            continue
        if manifest_entry.get("path") != spec_entry.get("path"):
            errors.append(
                f"artifact {artifact_id} path mismatch: {manifest_entry.get('path')} != {spec_entry.get('path')}"
            )
        if manifest_entry.get("role") != spec_entry.get("role"):
            errors.append(
                f"artifact {artifact_id} role mismatch: {manifest_entry.get('role')} != {spec_entry.get('role')}"
            )
        if manifest_entry.get("digest_mode") != spec_entry.get("hash_mode"):
            errors.append(
                f"artifact {artifact_id} digest_mode mismatch: {manifest_entry.get('digest_mode')} != {spec_entry.get('hash_mode')}"
            )

        rel_path = spec_entry.get("path")
        abs_path = path_utils.ensure_absolute(rel_path, repo_root=repo_root)
        if not abs_path.exists():
            errors.append(f"artifact missing on disk: {rel_path}")
            continue

        digest_mode = manifest_entry.get("digest_mode")
        if digest_mode == "bytes":
            digest = bundle._sha256_file(abs_path)
            if digest != manifest_entry.get("digest"):
                errors.append(f"digest mismatch for {rel_path}")
        elif digest_mode == "semantic_json":
            data = _load_json(abs_path)
            digest = bundle._sha256_canonical_json(data)
            if digest != manifest_entry.get("digest"):
                errors.append(f"digest mismatch for {rel_path}")
            byte_digest = manifest_entry.get("byte_digest")
            if byte_digest and byte_digest != bundle._sha256_file(abs_path):
                errors.append(f"byte_digest mismatch for {rel_path}")
        elif digest_mode == "presence_only":
            pass
        else:
            errors.append(f"unsupported digest_mode for {rel_path}: {digest_mode}")

        if manifest_entry.get("size_bytes") != abs_path.stat().st_size:
            errors.append(f"size_bytes mismatch for {rel_path}")

        schema_name = spec_entry.get("schema")
        if schema_name:
            schema_path = path_utils.ensure_absolute(SCHEMA_DIR / schema_name, repo_root=repo_root)
            if not schema_path.exists():
                errors.append(f"schema missing for {artifact_id}: {schema_name}")
            else:
                schema = _load_json(schema_path)
                schema_errors = _validate_schema(schema, _load_json(abs_path))
                for err in schema_errors:
                    errors.append(f"{rel_path}: {err}")

        for check_id in spec_entry.get("checks") or []:
            check_fn = CHECKS.get(check_id)
            if not check_fn:
                errors.append(f"unknown check id {check_id} for {artifact_id}")
                continue
            data = _load_json(abs_path)
            if check_id in {"metadata_world_id", "top_level_world_id"}:
                errors.extend(check_fn(data, baseline_world_id, rel_path))
            else:
                errors.extend(check_fn(data, rel_path))

    manifest_paths = {entry.get("path") for entry in manifest.get("artifacts", []) if entry.get("path")}
    errors.extend(_concept_sources_paths_manifested(repo_root, manifest_paths))
    errors.extend(_fixer_outputs_manifested(repo_root, manifest_paths))
    errors.extend(_contract_drift(repo_root, baseline_world_id))

    invariants_path = paths.ensure_absolute(paths.INVARIANTS_SPEC, repo_root_path=repo_root)
    invariants = spec_mod.load_invariants(invariants_path)
    errors.extend(_invariant_statuses(repo_root, invariants))

    return errors


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Verify CARTON manifest + invariants")
    parser.add_argument(
        "--spec",
        default=str(paths.CARTON_SPEC),
        help="path to carton_spec.json (repo-relative)",
    )
    parser.add_argument(
        "--manifest",
        default=str(paths.MANIFEST_PATH),
        help="path to CARTON manifest (repo-relative)",
    )
    args = parser.parse_args(argv)

    repo_root = _repo_root()
    spec_path = path_utils.ensure_absolute(args.spec, repo_root=repo_root)
    manifest_path = path_utils.ensure_absolute(args.manifest, repo_root=repo_root)

    errors = run_check(spec_path=spec_path, manifest_path=manifest_path, repo_root=repo_root)
    if errors:
        print("CARTON check failed:")
        for err in errors:
            print(f"- {err}")
        raise SystemExit(1)
    print("CARTON check OK")


if __name__ == "__main__":
    main()
