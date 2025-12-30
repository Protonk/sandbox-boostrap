"""Maintenance checks for the Ghidra shape catalog (no test integration).

This tool is intentionally read-only and fast: it inspects fixture metadata and
shape snapshots without running Ghidra. Use it to keep the catalog tidy as
scripts evolve.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from book.api import path_utils


def _load_json(path: Path) -> dict:
    with path.open("r") as f:
        return json.load(f)


def _iter_entries(manifest: dict) -> List[dict]:
    return list(manifest.get("entries", []))


def _load_families(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": "1.0", "mode": "task", "overrides": {}}
    return _load_json(path)


def _assign_family(entry: dict, families: dict) -> str:
    overrides = families.get("overrides") or {}
    name = entry.get("name") or ""
    if name in overrides:
        return overrides[name]

    mode = families.get("mode") or "task"
    if mode == "task":
        # Task-level grouping keeps the default family mapping simple and predictable.
        return entry.get("task") or "unclassified"

    if mode == "prefix":
        for rule in families.get("prefixes") or []:
            prefix = rule.get("prefix")
            family = rule.get("family")
            if prefix and name.startswith(prefix):
                return family or "unclassified"

    return "unclassified"


def _shape_signature(snapshot: dict) -> str:
    shape = snapshot.get("shape")
    return json.dumps(shape, sort_keys=True)


def build_report(
    repo_root: Path,
    manifest_path: Path,
    strict_manifest_path: Optional[Path],
    families_path: Optional[Path],
) -> dict:
    manifest = _load_json(manifest_path)
    entries = _iter_entries(manifest)

    strict_entries = []
    if strict_manifest_path and strict_manifest_path.exists():
        strict_manifest = _load_json(strict_manifest_path)
        strict_entries = _iter_entries(strict_manifest)

    families = _load_families(families_path) if families_path else {"schema_version": "1.0"}

    strict_output_paths = {entry.get("output_path") for entry in strict_entries}
    manifest_output_paths = {entry.get("output_path") for entry in entries}

    missing_snapshots = []
    snapshot_paths = set()
    for entry in entries:
        snap_rel = entry.get("snapshot_path")
        if not snap_rel:
            missing_snapshots.append({"entry": entry.get("name"), "reason": "missing snapshot_path"})
            continue
        snap_path = path_utils.ensure_absolute(snap_rel, repo_root)
        snapshot_paths.add(path_utils.to_repo_relative(snap_path, repo_root))
        if not snap_path.exists() or snap_path.stat().st_size == 0:
            missing_snapshots.append({"entry": entry.get("name"), "snapshot_path": snap_rel})

    strict_missing_from_manifest = []
    for entry in strict_entries:
        if entry.get("output_path") not in manifest_output_paths:
            strict_missing_from_manifest.append(entry.get("name"))

    fixture_dir = repo_root / "book" / "tests" / "planes" / "ghidra" / "fixtures" / "shape_catalog" / "snapshots"
    orphans = []
    for path in fixture_dir.glob("*.shape.json"):
        rel = path_utils.to_repo_relative(path, repo_root)
        if rel not in snapshot_paths:
            orphans.append(rel)

    duplicates = []
    shapes = {}
    for entry in entries:
        snap_rel = entry.get("snapshot_path")
        if not snap_rel:
            continue
        snap_path = path_utils.ensure_absolute(snap_rel, repo_root)
        if not snap_path.exists():
            continue
        snapshot = _load_json(snap_path)
        sig = _shape_signature(snapshot)
        shapes.setdefault(sig, []).append(entry.get("name"))
    for sig, names in shapes.items():
        if len(names) > 1:
            # Duplicate shapes should be pruned to keep the catalog high-signal.
            duplicates.append({"entries": sorted(names), "shape_signature": sig[:64]})

    families_summary: Dict[str, dict] = {}
    for entry in entries:
        family = _assign_family(entry, families)
        record = families_summary.setdefault(family, {"entries": 0, "strict": 0, "required": 0})
        record["entries"] += 1
        if entry.get("required"):
            record["required"] += 1
        if entry.get("output_path") in strict_output_paths:
            record["strict"] += 1

    report = {
        "schema_version": "1.0",
        "summary": {
            "entries": len(entries),
            "strict_entries": len(strict_entries),
            "families": len(families_summary),
            "snapshot_files": len(snapshot_paths),
            "orphans": len(orphans),
            "missing_snapshots": len(missing_snapshots),
            "duplicate_shapes": len(duplicates),
        },
        "issues": {
            "missing_snapshots": missing_snapshots,
            "orphan_snapshots": sorted(orphans),
            "duplicate_shapes": duplicates,
            "strict_missing_from_manifest": sorted(strict_missing_from_manifest),
        },
        "families": {
            "schema_version": families.get("schema_version"),
            "mode": families.get("mode"),
            "summary": dict(sorted(families_summary.items())),
        },
    }
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Ghidra shape catalog hygiene checks")
    parser.add_argument(
        "--manifest",
        default="book/integration/tests/ghidra/fixtures/shape_catalog/manifest.json",
        help="Manifest path",
    )
    parser.add_argument(
        "--strict-manifest",
        default="book/integration/tests/ghidra/fixtures/shape_catalog/manifest.strict.json",
        help="Strict manifest path",
    )
    parser.add_argument(
        "--families",
        default="book/integration/tests/ghidra/fixtures/shape_catalog/families.json",
        help="Family map path",
    )
    parser.add_argument("--report", help="Write JSON report to this path")
    parser.add_argument("--fail-on-issues", action="store_true", help="Exit non-zero if issues are found")
    args = parser.parse_args(argv)

    repo_root = path_utils.find_repo_root()
    report = build_report(
        repo_root,
        path_utils.ensure_absolute(args.manifest, repo_root),
        path_utils.ensure_absolute(args.strict_manifest, repo_root) if args.strict_manifest else None,
        path_utils.ensure_absolute(args.families, repo_root) if args.families else None,
    )

    output = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        report_path = path_utils.ensure_absolute(args.report, repo_root)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(output + "\n")
    else:
        print(output)

    issues = report.get("issues", {})
    has_issues = any(issues.get(key) for key in issues)
    if args.fail_on_issues and has_issues:
        # Fail-on-issues is a maintenance guardrail, not a correctness signal.
        print(
            "catalog issues detected; generate a baseline report with: "
            "python -m book.api.ghidra.shape_catalog_hygiene "
            "--report book/integration/tests/ghidra/fixtures/shape_catalog/reports/catalog_report.json",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
