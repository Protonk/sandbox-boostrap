#!/usr/bin/env python3
"""Human-focused CARTON drift report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from book.api import path_utils
from book.integration.carton import bundle
from book.integration.carton import paths


def _repo_root() -> Path:
    return paths.repo_root()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _manifest_entries(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {entry.get("id"): entry for entry in manifest.get("artifacts", []) if entry.get("id")}


def _format_list(items: Iterable[str], limit: int = 25) -> str:
    items = list(items)
    if len(items) <= limit:
        return ", ".join(items)
    head = ", ".join(items[:limit])
    return f"{head} ... (+{len(items) - limit} more)"


def _diff_manifest(base: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    base_entries = _manifest_entries(base)
    other_entries = _manifest_entries(other)

    base_ids = set(base_entries.keys())
    other_ids = set(other_entries.keys())

    added = sorted(other_ids - base_ids)
    removed = sorted(base_ids - other_ids)
    if added:
        lines.append(f"added artifacts: {', '.join(added)}")
    if removed:
        lines.append(f"removed artifacts: {', '.join(removed)}")

    for artifact_id in sorted(base_ids & other_ids):
        left = base_entries[artifact_id]
        right = other_entries[artifact_id]
        if left.get("digest") != right.get("digest"):
            lines.append(f"digest changed: {artifact_id}")
        if left.get("digest_mode") != right.get("digest_mode"):
            lines.append(f"digest_mode changed: {artifact_id}")
        if left.get("path") != right.get("path"):
            lines.append(f"path changed: {artifact_id} ({left.get('path')} -> {right.get('path')})")
        if left.get("size_bytes") != right.get("size_bytes"):
            lines.append(f"size changed: {artifact_id} ({left.get('size_bytes')} -> {right.get('size_bytes')})")

    return lines


def _load_contracts_from_manifest(repo_root: Path, manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    contracts: Dict[str, Dict[str, Any]] = {}
    for entry in manifest.get("artifacts", []):
        path = entry.get("path")
        if not path or not path.startswith("book/integration/carton/bundle/contracts/"):
            continue
        abs_path = path_utils.ensure_absolute(path, repo_root=repo_root)
        if abs_path.exists():
            contracts[path] = _load_json(abs_path)
    return contracts


def _diff_vocab_contract(base: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    base_ops = set(base.get("ops", {}).get("names") or [])
    other_ops = set(other.get("ops", {}).get("names") or [])
    base_filters = set(base.get("filters", {}).get("names") or [])
    other_filters = set(other.get("filters", {}).get("names") or [])

    added_ops = sorted(other_ops - base_ops)
    removed_ops = sorted(base_ops - other_ops)
    added_filters = sorted(other_filters - base_filters)
    removed_filters = sorted(base_filters - other_filters)

    if added_ops:
        lines.append(f"ops added: {_format_list(added_ops)}")
    if removed_ops:
        lines.append(f"ops removed: {_format_list(removed_ops)}")
    if added_filters:
        lines.append(f"filters added: {_format_list(added_filters)}")
    if removed_filters:
        lines.append(f"filters removed: {_format_list(removed_filters)}")
    return lines


def _diff_profiles_contract(base: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    base_profiles = base.get("canonical_profiles") or {}
    other_profiles = other.get("canonical_profiles") or {}

    base_ids = set(base_profiles.keys())
    other_ids = set(other_profiles.keys())
    added = sorted(other_ids - base_ids)
    removed = sorted(base_ids - other_ids)
    if added:
        lines.append(f"canonical profiles added: {', '.join(added)}")
    if removed:
        lines.append(f"canonical profiles removed: {', '.join(removed)}")

    for profile_id in sorted(base_ids & other_ids):
        left = base_profiles[profile_id]
        right = other_profiles[profile_id]
        if left.get("status") != right.get("status"):
            lines.append(
                f"canonical status changed: {profile_id} ({left.get('status')} -> {right.get('status')})"
            )
        if left.get("op_table_digest") != right.get("op_table_digest"):
            lines.append(f"op_table_digest changed: {profile_id}")
    return lines


def _diff_coverage_contract(base: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    base_summary = base.get("summary") or {}
    other_summary = other.get("summary") or {}
    for key in ("ops_total", "ops_with_system_profiles", "ops_with_no_coverage"):
        if base_summary.get(key) != other_summary.get(key):
            lines.append(
                f"summary {key} changed: {base_summary.get(key)} -> {other_summary.get(key)}"
            )

    base_zero = set(base.get("ops_with_no_coverage") or [])
    other_zero = set(other.get("ops_with_no_coverage") or [])
    added_zero = sorted(other_zero - base_zero)
    removed_zero = sorted(base_zero - other_zero)
    if added_zero:
        lines.append(f"ops now uncovered: {_format_list(added_zero)}")
    if removed_zero:
        lines.append(f"ops now covered: {_format_list(removed_zero)}")
    return lines


def _diff_relationships_contract(base: Dict[str, Any], other: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    base_rel = base.get("relationships") or {}
    other_rel = other.get("relationships") or {}
    base_ids = set(base_rel.keys())
    other_ids = set(other_rel.keys())

    added = sorted(other_ids - base_ids)
    removed = sorted(base_ids - other_ids)
    if added:
        lines.append(f"relationships added: {', '.join(added)}")
    if removed:
        lines.append(f"relationships removed: {', '.join(removed)}")

    for rel_id in sorted(base_ids & other_ids):
        left = base_rel[rel_id]
        right = other_rel[rel_id]
        if left.get("digest") != right.get("digest"):
            lines.append(f"relationship digest changed: {rel_id}")
    return lines


def _diff_contracts(
    base_contracts: Dict[str, Dict[str, Any]],
    other_contracts: Dict[str, Dict[str, Any]],
) -> List[str]:
    lines: List[str] = []

    vocab_path = "book/integration/carton/bundle/contracts/vocab.contract.json"
    profiles_path = "book/integration/carton/bundle/contracts/profiles.contract.json"
    coverage_path = "book/integration/carton/bundle/contracts/coverage.contract.json"
    relationships_path = "book/integration/carton/bundle/contracts/relationships.contract.json"

    if vocab_path in base_contracts and vocab_path in other_contracts:
        lines.extend(_diff_vocab_contract(base_contracts[vocab_path], other_contracts[vocab_path]))
    if profiles_path in base_contracts and profiles_path in other_contracts:
        lines.extend(_diff_profiles_contract(base_contracts[profiles_path], other_contracts[profiles_path]))
    if coverage_path in base_contracts and coverage_path in other_contracts:
        lines.extend(_diff_coverage_contract(base_contracts[coverage_path], other_contracts[coverage_path]))
    if relationships_path in base_contracts and relationships_path in other_contracts:
        lines.extend(
            _diff_relationships_contract(base_contracts[relationships_path], other_contracts[relationships_path])
        )

    return lines


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Show CARTON drift (manifest + contracts)")
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
    parser.add_argument(
        "--other",
        help="optional second manifest to compare against (repo-relative)",
    )
    args = parser.parse_args(argv)

    repo_root = _repo_root()
    spec_path = path_utils.ensure_absolute(args.spec, repo_root=repo_root)
    manifest_path = path_utils.ensure_absolute(args.manifest, repo_root=repo_root)

    base_manifest = _load_json(manifest_path)
    if args.other:
        other_manifest = _load_json(path_utils.ensure_absolute(args.other, repo_root=repo_root))
        live_contracts = False
    else:
        other_manifest = bundle.build_manifest_doc(spec_path=spec_path, repo_root=repo_root)
        live_contracts = True

    manifest_lines = _diff_manifest(base_manifest, other_manifest)
    if manifest_lines:
        print("Manifest drift:")
        for line in manifest_lines:
            print(f"- {line}")
    else:
        print("Manifest drift: none")

    base_contracts = _load_contracts_from_manifest(repo_root, base_manifest)
    if live_contracts:
        world_id, _ = bundle._baseline_world(repo_root)
        other_contracts = bundle.build_contracts(repo_root=repo_root, world_id=world_id)
    else:
        other_contracts = _load_contracts_from_manifest(repo_root, other_manifest)

    contract_lines = _diff_contracts(base_contracts, other_contracts)
    if contract_lines:
        print("Contract drift:")
        for line in contract_lines:
            print(f"- {line}")
    else:
        print("Contract drift: none")


if __name__ == "__main__":
    main()
