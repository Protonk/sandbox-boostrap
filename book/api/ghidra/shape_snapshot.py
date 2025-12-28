"""Shape snapshots for Ghidra script outputs (host-bound, static JSON only)."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from book.api import path_utils


SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ShapeOptions:
    list_length: bool = True
    max_list_items: int | None = None


def _shape_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return type(value).__name__


def _dedupe_shapes(shapes: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for shape in shapes:
        key = json.dumps(shape, sort_keys=True)
        if key not in seen:
            seen[key] = shape
    return [seen[k] for k in sorted(seen.keys())]


def build_shape(value: Any, options: ShapeOptions) -> Dict[str, Any]:
    value_type = _shape_type(value)
    if value_type == "dict":
        keys = {}
        for key in sorted(value.keys()):
            keys[key] = build_shape(value[key], options)
        return {"type": "dict", "keys": keys}
    if value_type == "list":
        items = value
        length = len(items)
        if options.max_list_items is not None:
            items = items[: options.max_list_items]
        shapes = [build_shape(item, options) for item in items]
        element_shapes = _dedupe_shapes(shapes)
        entry = {
            "type": "list",
            "length": length if options.list_length else None,
            "sampled": len(items),
            "element_shapes": element_shapes,
        }
        return entry
    return {"type": value_type}


def _normalize_shape_options(raw: Dict[str, Any] | None) -> ShapeOptions:
    if not raw:
        return ShapeOptions()
    return ShapeOptions(
        list_length=bool(raw.get("list_length", True)),
        max_list_items=raw.get("max_list_items"),
    )


def _load_json(path: Path) -> Any:
    with path.open("r") as f:
        return json.load(f)


def build_snapshot(entry: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
    shape_options = _normalize_shape_options(entry.get("shape"))
    payload = _load_json(output_path)
    shape = build_shape(payload, shape_options)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "name": entry.get("name"),
            "task": entry.get("task"),
            "output_path": path_utils.to_repo_relative(output_path, repo_root),
            "snapshot_path": entry.get("snapshot_path"),
            "shape_options": {
                "list_length": shape_options.list_length,
                "max_list_items": shape_options.max_list_items,
            },
        },
        "shape": shape,
    }
    return snapshot


def write_snapshot(entry: Dict[str, Any], repo_root: Path) -> Dict[str, Any]:
    snapshot = build_snapshot(entry, repo_root)
    snapshot_path = path_utils.ensure_absolute(entry["snapshot_path"], repo_root)
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    with snapshot_path.open("w") as f:
        json.dump(snapshot, f, indent=2, sort_keys=True)
    return snapshot


def load_manifest(path: Path) -> Dict[str, Any]:
    return _load_json(path)


def _iter_entries(manifest: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for entry in manifest.get("entries", []):
        yield entry


def validate_entry(entry: Dict[str, Any], repo_root: Path) -> Tuple[bool, str | None]:
    output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
    snapshot_path = path_utils.ensure_absolute(entry["snapshot_path"], repo_root)
    if not output_path.exists():
        if entry.get("required"):
            return False, "missing output %s" % path_utils.to_repo_relative(output_path, repo_root)
        return True, None
    if not snapshot_path.exists():
        return False, "missing snapshot %s" % path_utils.to_repo_relative(snapshot_path, repo_root)

    payload = _load_json(output_path)
    shape_options = _normalize_shape_options(entry.get("shape"))
    current = build_shape(payload, shape_options)
    snapshot = _load_json(snapshot_path)
    expected = snapshot.get("shape")
    if current != expected:
        return False, "shape mismatch for %s" % entry.get("name")
    return True, None


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or validate Ghidra output shape snapshots.")
    parser.add_argument("--manifest", required=True, help="Path to manifest.json")
    parser.add_argument("--write", action="store_true", help="Write snapshots for manifest entries")
    parser.add_argument("--validate", action="store_true", help="Validate manifest entries")
    args = parser.parse_args(argv)

    repo_root = path_utils.find_repo_root()
    manifest_path = path_utils.ensure_absolute(args.manifest, repo_root)
    manifest = load_manifest(manifest_path)

    if args.write:
        for entry in _iter_entries(manifest):
            output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
            if not output_path.exists():
                if entry.get("required"):
                    raise SystemExit("missing output %s" % output_path)
                continue
            write_snapshot(entry, repo_root)

    if args.validate:
        failures = []
        for entry in _iter_entries(manifest):
            ok, msg = validate_entry(entry, repo_root)
            if not ok:
                failures.append(msg or "unknown error")
        if failures:
            raise SystemExit("\n".join(failures))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
