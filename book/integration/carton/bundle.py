#!/usr/bin/env python3
"""
CARTON bundle builder: manifest + contract snapshots.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api import path_utils
from book.api import world as world_mod
from book.integration.carton import paths
from book.integration.carton import spec as spec_mod

CONTRACT_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 2


def _repo_root() -> Path:
    return paths.repo_root()


def _sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_canonical_json(obj: Any) -> str:
    return _sha256_bytes(_canonical_json_bytes(obj))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _baseline_world(repo_root: Path) -> Tuple[str, str]:
    data, resolution = world_mod.load_world(repo_root=repo_root)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    world_path = world_mod.world_path_for_metadata(resolution, repo_root=repo_root)
    return world_id, world_path


def _repo_rel(path: Path, repo_root: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=repo_root)


def load_spec(spec_path: Path) -> Dict[str, Any]:
    return spec_mod.load_carton_spec(spec_path)


def build_manifest_doc(*, spec_path: Path, repo_root: Path) -> Dict[str, Any]:
    spec = load_spec(spec_path)
    baseline_world_id, _ = _baseline_world(repo_root)
    spec_world = spec.get("world_id")
    if spec_world and spec_world != baseline_world_id:
        raise ValueError(f"carton_spec.json world_id mismatch: {spec_world} vs {baseline_world_id}")

    artifacts: List[Dict[str, Any]] = []
    for entry in spec["artifacts"]:
        rel_path = entry["path"]
        abs_path = path_utils.ensure_absolute(rel_path, repo_root=repo_root)
        if not abs_path.exists():
            raise FileNotFoundError(f"missing CARTON artifact: {rel_path}")

        digest_mode = entry["hash_mode"]
        digest: Optional[str] = None
        byte_digest: Optional[str] = None
        if digest_mode == "bytes":
            digest = _sha256_file(abs_path)
        elif digest_mode == "semantic_json":
            data = _load_json(abs_path)
            digest = _sha256_canonical_json(data)
            byte_digest = _sha256_file(abs_path)
        elif digest_mode == "presence_only":
            digest = None
        else:
            raise ValueError(f"unsupported hash_mode {digest_mode} for {entry['id']}")

        artifacts.append(
            {
                "id": entry["id"],
                "path": _repo_rel(abs_path, repo_root),
                "role": entry["role"],
                "digest": digest,
                "digest_mode": digest_mode,
                "byte_digest": byte_digest,
                "size_bytes": abs_path.stat().st_size,
            }
        )

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "name": spec.get("name", "CARTON"),
        "world_id": baseline_world_id,
        "spec_path": _repo_rel(spec_path, repo_root),
        "spec_sha256": _sha256_canonical_json(spec),
        "artifacts": artifacts,
    }
    return manifest


def build_vocab_contract(*, repo_root: Path, world_id: str) -> Dict[str, Any]:
    ops_path = repo_root / "book/graph/mappings/vocab/ops.json"
    filters_path = repo_root / "book/graph/mappings/vocab/filters.json"
    ops = _load_json(ops_path).get("ops") or []
    filters = _load_json(filters_path).get("filters") or []

    op_entries = sorted(
        [{"name": entry["name"], "id": entry["id"]} for entry in ops if "name" in entry and "id" in entry],
        key=lambda e: e["name"],
    )
    filter_entries = sorted(
        [
            {"name": entry["name"], "id": entry["id"]}
            for entry in filters
            if "name" in entry and "id" in entry
        ],
        key=lambda e: e["name"],
    )

    op_names = [entry["name"] for entry in op_entries]
    filter_names = [entry["name"] for entry in filter_entries]

    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": [_repo_rel(ops_path, repo_root), _repo_rel(filters_path, repo_root)],
        "ops": {
            "count": len(op_entries),
            "names": op_names,
            "name_digest": _sha256_canonical_json(op_names),
            "id_map_digest": _sha256_canonical_json(op_entries),
        },
        "filters": {
            "count": len(filter_entries),
            "names": filter_names,
            "name_digest": _sha256_canonical_json(filter_names),
            "id_map_digest": _sha256_canonical_json(filter_entries),
        },
    }


def build_profiles_contract(*, repo_root: Path, world_id: str) -> Dict[str, Any]:
    digests_path = repo_root / "book/graph/mappings/system_profiles/digests.json"
    digests = _load_json(digests_path)
    meta = digests.get("metadata") or {}
    canonical = meta.get("canonical_profiles") or {}
    profiles = digests.get("profiles") or {k: v for k, v in digests.items() if k != "metadata"}

    entries: Dict[str, Any] = {}
    for profile_id in sorted(canonical.keys()):
        body = profiles.get(profile_id) or {}
        op_ids = sorted(set(body.get("op_table") or []))
        status = canonical.get(profile_id) or {}
        entries[profile_id] = {
            "profile_id": profile_id,
            "status": status.get("status") if isinstance(status, dict) else status,
            "op_count": len(op_ids),
            "op_table_digest": _sha256_canonical_json(op_ids),
        }

    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": [_repo_rel(digests_path, repo_root)],
        "canonical_profiles": entries,
    }


def build_coverage_contract(*, repo_root: Path, world_id: str) -> Dict[str, Any]:
    coverage_path = repo_root / "book/integration/carton/bundle/relationships/operation_coverage.json"
    coverage = _load_json(coverage_path)
    summary = coverage.get("summary") or {}
    coverage_map = coverage.get("coverage") or {}
    zero_ops = sorted([name for name, entry in coverage_map.items() if not entry.get("system_profiles")])

    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": [_repo_rel(coverage_path, repo_root)],
        "summary": summary,
        "ops_with_no_coverage": zero_ops,
    }


def _relationship_counts(name: str, doc: Dict[str, Any]) -> Dict[str, int]:
    if name == "operation_coverage":
        summary = doc.get("summary") or {}
        return {
            "ops_total": int(summary.get("ops_total", 0)),
            "ops_with_system_profiles": int(summary.get("ops_with_system_profiles", 0)),
            "ops_with_no_coverage": int(summary.get("ops_with_no_coverage", 0)),
        }
    if name == "operation_system_profiles":
        operations = doc.get("operations") or {}
        with_profiles = sum(1 for entry in operations.values() if entry.get("system_profiles"))
        return {
            "ops_total": len(operations),
            "ops_with_system_profiles": with_profiles,
        }
    if name == "profile_layer_ops":
        profiles = doc.get("profiles") or {}
        ops_total = sum(len((entry.get("ops") or [])) for entry in profiles.values())
        return {
            "profiles_total": len(profiles),
            "ops_total": ops_total,
        }
    if name == "filter_usage":
        filters = doc.get("filters") or {}
        return {"filters_total": len(filters)}
    if name == "anchor_field2":
        anchors = doc.get("anchors") or {}
        return {"anchors_total": len(anchors)}
    if name == "concept_sources":
        concepts = doc.get("concepts") or {}
        entries_total = sum(len(entries) for entries in concepts.values())
        return {"concepts_total": len(concepts), "entries_total": entries_total}
    return {}


def build_relationships_contract(*, repo_root: Path, world_id: str) -> Dict[str, Any]:
    rel_paths = {
        "operation_coverage": repo_root / "book/integration/carton/bundle/relationships/operation_coverage.json",
        "operation_system_profiles": repo_root / "book/integration/carton/bundle/relationships/operation_system_profiles.json",
        "profile_layer_ops": repo_root / "book/integration/carton/bundle/relationships/profile_layer_ops.json",
        "filter_usage": repo_root / "book/integration/carton/bundle/relationships/filter_usage.json",
        "anchor_field2": repo_root / "book/integration/carton/bundle/relationships/anchor_field2.json",
        "concept_sources": repo_root / "book/integration/carton/bundle/relationships/concept_sources.json",
    }
    relationships: Dict[str, Any] = {}
    inputs: List[str] = []
    for name, path in rel_paths.items():
        doc = _load_json(path)
        relationships[name] = {
            "path": _repo_rel(path, repo_root),
            "digest": _sha256_canonical_json(doc),
            "counts": _relationship_counts(name, doc),
        }
        inputs.append(_repo_rel(path, repo_root))

    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": inputs,
        "relationships": relationships,
    }


CONTRACT_BUILDERS = {
    "book/integration/carton/bundle/contracts/vocab.contract.json": build_vocab_contract,
    "book/integration/carton/bundle/contracts/profiles.contract.json": build_profiles_contract,
    "book/integration/carton/bundle/contracts/coverage.contract.json": build_coverage_contract,
    "book/integration/carton/bundle/contracts/relationships.contract.json": build_relationships_contract,
}


def build_contracts(*, repo_root: Path, world_id: str) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for rel_path, builder in CONTRACT_BUILDERS.items():
        results[rel_path] = builder(repo_root=repo_root, world_id=world_id)
    return results


def write_contracts(*, spec_path: Path, repo_root: Path) -> List[Path]:
    spec = load_spec(spec_path)
    world_id, _ = _baseline_world(repo_root)
    expected_paths = {
        entry["path"]
        for entry in spec.get("artifacts", [])
        if entry.get("path", "").startswith("book/integration/carton/bundle/contracts/")
    }
    contracts = build_contracts(repo_root=repo_root, world_id=world_id)
    written: List[Path] = []
    for rel_path, doc in contracts.items():
        if rel_path not in expected_paths:
            continue
        path = path_utils.ensure_absolute(rel_path, repo_root=repo_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2))
        written.append(path)
    missing = expected_paths - set(contracts.keys())
    if missing:
        raise ValueError(f"missing contract builders for: {sorted(missing)}")
    return written


def build_manifest(*, spec_path: Path, out_path: Path, repo_root: Path, refresh_contracts: bool) -> None:
    if refresh_contracts:
        written = write_contracts(spec_path=spec_path, repo_root=repo_root)
        for path in written:
            print(f"[+] wrote {path}")

    manifest = build_manifest_doc(spec_path=spec_path, repo_root=repo_root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2))
    print(f"[+] wrote {out_path}")
