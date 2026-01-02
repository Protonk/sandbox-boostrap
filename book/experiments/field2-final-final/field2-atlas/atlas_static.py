"""
Static join helper for the Field2 Atlas experiment.

Builds field2-centric records by joining:
- seed manifest (`field2_seeds.json`)
- anchor → filter map compatibility view (`book/graph/mappings/anchors/anchor_filter_map.json`, derived conservatively from the ctx-indexed canonical map)
- field2 inventory from field2-filters (`book/experiments/field2-final-final/field2-filters/out/field2_inventory.json`)

Output: `out/static/field2_records.jsonl`, one JSON object per field2 seed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())
DEFAULT_SEEDS = Path(__file__).with_name("field2_seeds.json")
# Inputs are anchored in the outputs of sibling experiments/mappings:
# - field2 inventory from field2-filters
# - anchor_filter_map from anchor-filter-map (derived compatibility view; canonical is ctx-indexed)
# - tag layouts are implicit through the inventory/tag_ids
DEFAULT_FIELD2_INVENTORY = (
    REPO_ROOT / "book" / "experiments" / "field2-filters" / "out" / "field2_inventory.json"
)
DEFAULT_ANCHOR_MAP = REPO_ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json"
DEFAULT_OUTPUT = Path(__file__).with_name("out") / "static" / "field2_records.jsonl"


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _iter_field2_entries(field2_inventory: Dict[str, Any], fid: int) -> Iterable[Dict[str, Any]]:
    for profile_id, payload in field2_inventory.items():
        for entry in payload.get("field2", []):
            if entry.get("raw") == fid:
                yield profile_id, entry


def _gather_profiles(field2_inventory: Dict[str, Any], fid: int) -> List[Dict[str, Any]]:
    profiles: List[Dict[str, Any]] = []
    tags: Dict[str, int] = {}
    for profile_id, entry in _iter_field2_entries(field2_inventory, fid):
        tag_counts = entry.get("tags") or {}
        for tag, count in tag_counts.items():
            tags[tag] = tags.get(tag, 0) + count
        profiles.append(
            {
                "profile": profile_id,
                "tags": tag_counts,
                "count": entry.get("count"),
                "name": entry.get("name"),
            }
        )
    return profiles


def _gather_anchor_hits(anchor_map: Dict[str, Any], fid: int) -> List[Dict[str, Any]]:
    anchors: List[Dict[str, Any]] = []
    for anchor, entry in anchor_map.items():
        if anchor == "metadata":
            continue
        if not isinstance(entry, dict):
            continue
        values = set(entry.get("field2_values") or [])
        if fid not in values:
            continue
        anchors.append(
            {
                "anchor": anchor,
                "status": entry.get("status", "partial"),
                "filter_name": entry.get("filter_name"),
                "filter_id": entry.get("filter_id"),
                "sources": entry.get("sources") or [],
                "field2_values": sorted(values),
            }
        )
    return anchors


def _seed_anchor_hits(seed: Dict[str, Any], fid: int, *, existing: set[str]) -> List[Dict[str, Any]]:
    anchors: List[Dict[str, Any]] = []
    for entry in seed.get("anchors") or []:
        anchor = entry.get("anchor")
        if not anchor or anchor in existing:
            continue
        anchors.append(
            {
                "anchor": anchor,
                "status": entry.get("status", "partial"),
                "filter_name": seed.get("filter_name"),
                "filter_id": None,
                "sources": [entry.get("source", "seed_manifest")],
                "field2_values": [fid],
            }
        )
    return anchors


def build_records(
    seeds_path: Path = DEFAULT_SEEDS,
    field2_inventory_path: Path = DEFAULT_FIELD2_INVENTORY,
    anchor_map_path: Path = DEFAULT_ANCHOR_MAP,
) -> Dict[str, Any]:
    seeds_doc = load_json(seeds_path)
    field2_inventory = load_json(field2_inventory_path)
    anchor_map = load_json(anchor_map_path)

    records: List[Dict[str, Any]] = []
    for seed in seeds_doc.get("seeds", []):
        fid = seed["field2"]
        profiles = _gather_profiles(field2_inventory, fid)
        anchors = _gather_anchor_hits(anchor_map, fid)
        anchor_names = {entry.get("anchor") for entry in anchors if entry.get("anchor")}
        anchors += _seed_anchor_hits(seed, fid, existing=anchor_names)
        tag_ids: List[int] = sorted(
            {int(tag) for profile in profiles for tag in (profile.get("tags") or {}).keys()}
        )
        records.append(
            {
                "world_id": seeds_doc.get("world_id"),
                "field2": fid,
                "filter_name": seed.get("filter_name") or (profiles[0].get("name") if profiles else None),
                "target_ops": seed.get("target_ops") or [],
                "seed_anchors": seed.get("anchors") or [],
                "anchor_hits": anchors,
                "profiles": profiles,
                "tag_ids": tag_ids,
                "source_artifacts": {
                    "seeds": path_utils.to_repo_relative(seeds_path, repo_root=REPO_ROOT),
                    "field2_inventory": path_utils.to_repo_relative(field2_inventory_path, repo_root=REPO_ROOT),
                    "anchor_map": path_utils.to_repo_relative(anchor_map_path, repo_root=REPO_ROOT),
                },
                "status": "ok" if profiles else "partial",
                "notes": seed.get("notes", ""),
            }
        )

    seed_ids = {entry["field2"] for entry in seeds_doc.get("seeds", [])}
    record_ids = {entry["field2"] for entry in records}
    if seed_ids != record_ids:
        missing = seed_ids - record_ids
        extra = record_ids - seed_ids
        raise ValueError(f"seed/record mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    for record in records:
        assert "field2" in record, "record missing field2"
        assert isinstance(record.get("tag_ids"), list), "record missing tag_ids list"
        assert isinstance(record.get("target_ops"), list), "record missing target_ops list"
        assert record.get("anchor_hits") or record.get("profiles"), "record missing anchors and profiles"

    return {"world_id": seeds_doc.get("world_id"), "records": records}


def write_records(doc: Dict[str, Any], output_path: Path = DEFAULT_OUTPUT) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for record in doc["records"]:
            fh.write(json.dumps(record, sort_keys=True))
            fh.write("\n")


def main() -> None:
    doc = build_records()
    write_records(doc)


if __name__ == "__main__":
    main()
