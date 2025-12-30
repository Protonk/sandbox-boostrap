"""Prune and expand Ghidra shape manifest entries for stable coverage.

This tool keeps the shape catalog small by selecting representative outputs per
task family and mode. It is intentionally conservative: duplicates are pruned
so the manifest stays reviewable and high-signal.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from fnmatch import fnmatch
from typing import Any, Dict, Iterable, List, Tuple

from book.api import path_utils
from book.api.ghidra import shape_snapshot


# Parametric task families share output shapes; we keep one representative per family/mode.
PARAM_FAMILIES = (
    "addr-lookup",
    "adrp-add",
    "kernel-adrp-add-kc",
    "kernel-collection-imm-search",
    "kernel-collection-offset-scan",
    "page-ref",
    "sandbox-kext-offset-scan",
    "x86-page",
)

# Mode keys distinguish scan variants that materially change the output shape.
MODE_KEYS = {
    "kernel-collection-offset-scan": ("write_only", "scan_all_blocks"),
    "sandbox-kext-offset-scan": ("write_only", "scan_all_blocks"),
    "kernel-adrp-ldr-scan": ("target_mode", "scan_all_blocks"),
}

# Some tasks produce multiple outputs that should be kept together.
TASK_PATTERNS = {
    "find-field2-evaluator": (
        "summary.json",
        "field2_evaluator.json",
        "candidates.json",
        "eval_layout.json",
        "eval_layout_match_network.json",
        "node_struct_scan.json",
        "node_struct_candidates.json",
        "FUN_*.json",
    ),
}


@dataclass(frozen=True)
class EntryInfo:
    entry: Dict[str, Any]
    task: str
    family: str
    mode_key: Tuple[Tuple[str, Any], ...]
    shape_hash: str


def _normalize_task(task: str) -> str:
    for base in PARAM_FAMILIES:
        if task.startswith(base + "-"):
            return base
    return task


def _load_json(path: Path) -> Any:
    with path.open("r") as f:
        return json.load(f)


def _output_meta(path: Path) -> Dict[str, Any]:
    data = _load_json(path)
    if isinstance(data, dict) and isinstance(data.get("meta"), dict):
        return data["meta"]
    return {}


def _shape_hash(entry: Dict[str, Any], repo_root: Path) -> str:
    snapshot_path = path_utils.ensure_absolute(entry["snapshot_path"], repo_root)
    if snapshot_path.exists():
        snapshot = _load_json(snapshot_path)
        shape = snapshot.get("shape")
    else:
        output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
        payload = _load_json(output_path)
        shape_options = shape_snapshot.ShapeOptions(**(entry.get("shape") or {}))
        shape = shape_snapshot.build_shape(payload, shape_options)
    return json.dumps(shape, sort_keys=True)


def _mode_key(family: str, meta: Dict[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    keys = MODE_KEYS.get(family)
    if not keys:
        return tuple()
    return tuple((key, meta.get(key)) for key in keys)


def _entry_rank(entry: Dict[str, Any], family: str) -> Tuple[int, int, str]:
    task = entry.get("task") or ""
    output_path = entry.get("output_path") or ""
    is_base = 0 if task == family else 1
    return (is_base, len(output_path), output_path)


def _build_entry_info(entries: Iterable[Dict[str, Any]], repo_root: Path) -> List[EntryInfo]:
    infos = []
    for entry in entries:
        task = entry.get("task") or ""
        family = _normalize_task(task)
        output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
        meta = _output_meta(output_path) if output_path.exists() else {}
        mode_key = _mode_key(family, meta)
        shape_hash = _shape_hash(entry, repo_root)
        infos.append(EntryInfo(entry=entry, task=task, family=family, mode_key=mode_key, shape_hash=shape_hash))
    return infos


def _choose_keepers(infos: List[EntryInfo]) -> Tuple[List[EntryInfo], List[EntryInfo]]:
    grouped: Dict[Tuple[str, str, Tuple[Tuple[str, Any], ...]], List[EntryInfo]] = {}
    for info in infos:
        key = (info.family, info.shape_hash, info.mode_key)
        grouped.setdefault(key, []).append(info)

    keepers: List[EntryInfo] = []
    removed: List[EntryInfo] = []
    for entries in grouped.values():
        entries_sorted = sorted(entries, key=lambda e: _entry_rank(e.entry, e.family))
        # Prefer the shortest, most canonical output path to minimize churn.
        keep = entries_sorted[0]
        keepers.append(keep)
        removed.extend(entries_sorted[1:])
    keepers, extra_removed = _apply_task_patterns(keepers)
    removed.extend(extra_removed)
    return keepers, removed


def _apply_task_patterns(keepers: List[EntryInfo]) -> Tuple[List[EntryInfo], List[EntryInfo]]:
    by_task: Dict[str, List[EntryInfo]] = {}
    for info in keepers:
        by_task.setdefault(info.task, []).append(info)

    kept: List[EntryInfo] = []
    removed: List[EntryInfo] = []
    for task, entries in by_task.items():
        patterns = TASK_PATTERNS.get(task)
        if not patterns:
            kept.extend(entries)
            continue
        entries_sorted = sorted(entries, key=lambda e: _entry_rank(e.entry, e.family))
        used_paths = set()
        for pattern in patterns:
            matched = [e for e in entries_sorted if fnmatch(Path(e.entry["output_path"]).name, pattern)]
            if matched:
                keep = matched[0]
                kept.append(keep)
                used_paths.add(keep.entry["output_path"])
        for entry in entries_sorted:
            if entry.entry["output_path"] not in used_paths:
                removed.append(entry)
    return kept, removed


def _representatives_from_outputs(
    repo_root: Path,
    out_root: Path,
    keepers: List[EntryInfo],
) -> List[Dict[str, Any]]:
    represented = {(info.family, info.mode_key) for info in keepers}
    existing_paths = {info.entry["output_path"] for info in keepers}
    additions: List[Dict[str, Any]] = []

    for path in sorted(out_root.rglob("*.json")):
        rel = path.relative_to(repo_root).as_posix()
        if rel in existing_paths:
            continue
        # The task name is the first directory under book/dumps/ghidra/out/<build>/.
        task = path.parent.relative_to(out_root).parts[0]
        family = _normalize_task(task)
        meta = _output_meta(path)
        mode_key = _mode_key(family, meta)
        if (family, mode_key) in represented:
            continue
        name = path.relative_to(out_root).as_posix().replace("/", "__")
        if name.endswith(".json"):
            name = name[:-5]
        additions.append(
            {
                "name": name,
                "task": task,
                "output_path": rel,
                "snapshot_path": "book/integration/tests/ghidra/fixtures/shape_catalog/snapshots/%s.shape.json" % name,
                "required": False,
                "shape": {"list_length": True},
            }
        )
        represented.add((family, mode_key))
    return additions


def _write_report(report_path: Path, keepers: List[EntryInfo], removed: List[EntryInfo], additions: List[Dict[str, Any]]):
    report = {
        "kept_count": len(keepers),
        "removed_count": len(removed),
        "added_count": len(additions),
        "removed": [
            {
                "name": info.entry.get("name"),
                "task": info.task,
                "family": info.family,
                "output_path": info.entry.get("output_path"),
                "mode_key": list(info.mode_key),
            }
            for info in sorted(removed, key=lambda i: (i.family, i.task, i.entry.get("output_path") or ""))
        ],
        "added": additions,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prune and expand Ghidra shape manifest entries.")
    parser.add_argument("--manifest", required=True, help="Path to manifest.json")
    parser.add_argument("--report", required=True, help="Path to write prune report JSON")
    parser.add_argument("--write", action="store_true", help="Write manifest changes")
    parser.add_argument("--expand", action="store_true", help="Add representative entries for missing families/modes")
    args = parser.parse_args(argv)

    repo_root = path_utils.find_repo_root()
    manifest_path = path_utils.ensure_absolute(args.manifest, repo_root)
    report_path = path_utils.ensure_absolute(args.report, repo_root)

    manifest = _load_json(manifest_path)
    entries = list(manifest.get("entries", []))
    infos = _build_entry_info(entries, repo_root)
    keepers, removed = _choose_keepers(infos)
    additions: List[Dict[str, Any]] = []

    if args.expand:
        out_root = repo_root / "dumps" / "ghidra" / "out" / manifest.get("build_id", "")
        additions = _representatives_from_outputs(repo_root, out_root, keepers)

    kept_entries = [info.entry for info in keepers]
    if additions:
        kept_entries.extend(additions)

    kept_entries = sorted(kept_entries, key=lambda e: (e.get("task") or "", e.get("name") or ""))
    manifest["entries"] = kept_entries

    if args.write:
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    _write_report(report_path, keepers, removed, additions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
