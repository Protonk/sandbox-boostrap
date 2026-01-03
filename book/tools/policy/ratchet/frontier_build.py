#!/usr/bin/env python3
"""
Build a field2 frontier from userland-visible sources.

Frontier inputs:
- seed manifest (field2-atlas/field2_seeds.json)
- field2 inventory + unknown census (field2-filters)
- anchor hits (probe-op-structure)
- optional atlas output (field2-atlas out/derived)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import sys

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils

SCHEMA_VERSION = "field2-frontier.v0"

DEFAULT_SEEDS = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-atlas"
    / "field2_seeds.json"
)
DEFAULT_INVENTORY = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-filters"
    / "out"
    / "field2_inventory.json"
)
DEFAULT_UNKNOWN_NODES = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-filters"
    / "out"
    / "unknown_nodes.json"
)
DEFAULT_ANCHOR_HITS = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "probe-op-structure"
    / "out"
    / "anchor_hits.json"
)
DEFAULT_OUT = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "out"
    / "frontier.json"
)
DEFAULT_DECISIONS = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "decisions.jsonl"
)
DEFAULT_RUNTIME_LATEST = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "runtime-adversarial"
    / "out"
    / "LATEST"
)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _default_atlas_path() -> Optional[Path]:
    if not DEFAULT_RUNTIME_LATEST.exists():
        return None
    run_id = DEFAULT_RUNTIME_LATEST.read_text(encoding="utf-8").strip()
    if not run_id:
        return None
    candidate = (
        REPO_ROOT
        / "book"
        / "evidence"
        / "experiments"
        / "field2-final-final"
        / "field2-atlas"
        / "out"
        / "derived"
        / run_id
        / "atlas"
        / "field2_atlas.json"
    )
    return candidate if candidate.exists() else None


def _seed_map(seeds_doc: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    return {entry["field2"]: entry for entry in seeds_doc.get("seeds", [])}


def _inventory_map(inventory: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for profile, rec in inventory.items():
        if not isinstance(rec, dict):
            continue
        for entry in rec.get("field2", []) or []:
            raw = entry.get("raw")
            if not isinstance(raw, int):
                continue
            slot = out.setdefault(
                raw,
                {
                    "raw": raw,
                    "filter_name": entry.get("name"),
                    "hi": entry.get("hi"),
                    "lo": entry.get("lo"),
                    "count": 0,
                    "profiles": set(),
                },
            )
            slot["count"] += entry.get("count", 0) or 0
            slot["profiles"].add(profile)
            if not slot.get("filter_name") and entry.get("name"):
                slot["filter_name"] = entry.get("name")
    return out


def _unknown_map(unknown: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for profile, nodes in unknown.items():
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            raw = node.get("raw") if isinstance(node, dict) else None
            if not isinstance(raw, int):
                continue
            slot = out.setdefault(raw, {"raw": raw, "count": 0, "profiles": set()})
            slot["count"] += 1
            slot["profiles"].add(profile)
    return out


def _anchor_map(anchor_hits: Dict[str, Any]) -> Dict[int, Set[str]]:
    out: Dict[int, Set[str]] = {}
    for rec in anchor_hits.values():
        anchors = (rec or {}).get("anchors") if isinstance(rec, dict) else None
        if not anchors:
            continue
        for anchor in anchors:
            anchor_name = anchor.get("anchor") if isinstance(anchor, dict) else None
            if not anchor_name:
                continue
            for raw in anchor.get("field2_values") or []:
                if not isinstance(raw, int):
                    continue
                out.setdefault(raw, set()).add(anchor_name)
    return out


def _atlas_status(atlas_doc: Dict[str, Any]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for rec in atlas_doc.get("atlas") or []:
        fid = rec.get("field2")
        status = rec.get("status")
        if isinstance(fid, int) and isinstance(status, str):
            out[fid] = status
    return out


def _score_candidate(
    status: str,
    *,
    anchor_count: int,
    has_filter_name: bool,
    unknown_count: int,
    seed_present: bool,
    has_runtime_candidate: bool,
) -> int:
    if status in {"runtime_backed", "runtime_backed_historical"}:
        return -100
    score = 0
    if seed_present:
        score += 4
    if anchor_count:
        score += 5
    if has_filter_name:
        score += 3
    if unknown_count:
        score += 2
    if has_runtime_candidate:
        score += 5
    else:
        score -= 6
    if status in {"runtime_attempted_blocked", "missing_actual", "no_runtime_candidate", "static_only", "seed_only"}:
        score += 2
    return score


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=Path, default=DEFAULT_SEEDS)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--unknown-nodes", type=Path, default=DEFAULT_UNKNOWN_NODES)
    parser.add_argument("--anchor-hits", type=Path, default=DEFAULT_ANCHOR_HITS)
    parser.add_argument("--atlas", type=Path, default=None)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--include-retired", action="store_true")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    seeds_doc = load_json(args.seeds)
    seed_map = _seed_map(seeds_doc)

    inventory = load_json(args.inventory) if args.inventory.exists() else {}
    inventory_map = _inventory_map(inventory)

    unknown = load_json(args.unknown_nodes) if args.unknown_nodes.exists() else {}
    unknown_map = _unknown_map(unknown)

    anchor_hits = load_json(args.anchor_hits) if args.anchor_hits.exists() else {}
    anchor_map = _anchor_map(anchor_hits)

    atlas_path = args.atlas or _default_atlas_path()
    atlas_doc = load_json(atlas_path) if atlas_path and atlas_path.exists() else {}
    atlas_status = _atlas_status(atlas_doc)

    decisions = load_jsonl(args.decisions)
    retired = {
        rec.get("claim_key")
        for rec in decisions
        if rec.get("decision") == "retired" and rec.get("claim_key")
    }

    candidate_ids = set(seed_map)
    candidate_ids.update(inventory_map)
    candidate_ids.update(unknown_map)
    candidate_ids.update(anchor_map)

    candidates: List[Dict[str, Any]] = []
    for fid in sorted(candidate_ids):
        seed = seed_map.get(fid)
        inv = inventory_map.get(fid)
        unknown_entry = unknown_map.get(fid)
        anchors = anchor_map.get(fid) or set()
        filter_name = None
        if seed and seed.get("filter_name"):
            filter_name = seed.get("filter_name")
        elif inv and inv.get("filter_name"):
            filter_name = inv.get("filter_name")

        status = atlas_status.get(fid)
        if not status:
            status = "seed_only" if seed else "inventory_only"
        source_tags = []
        if seed:
            source_tags.append("seed_manifest")
        if inv:
            source_tags.append("inventory")
        if unknown_entry:
            source_tags.append("unknown_nodes")
        if anchors:
            source_tags.append("anchor_hits")

        anchor_list = sorted(anchors)
        unknown_count = unknown_entry.get("count", 0) if unknown_entry else 0
        score = _score_candidate(
            status,
            anchor_count=len(anchors),
            has_filter_name=bool(filter_name),
            unknown_count=unknown_count,
            seed_present=bool(seed),
            has_runtime_candidate=bool(seed and seed.get("runtime_candidate")),
        )
        claim_key = f"field2={fid}"
        if claim_key in retired and not args.include_retired:
            status = "retired"
            score = -1000

        candidate = {
            "field2": fid,
            "filter_name": filter_name,
            "status": status,
            "sources": source_tags,
            "target_ops": seed.get("target_ops") if seed else [],
            "runtime_candidate": seed.get("runtime_candidate") if seed else None,
            "anchor_count": len(anchors),
            "anchors_sample": anchor_list[:6],
            "inventory": {
                "count": inv.get("count", 0) if inv else 0,
                "profiles_sample": sorted(inv.get("profiles", []))[:6] if inv else [],
            },
            "unknown": {
                "count": unknown_count,
                "profiles_sample": sorted(unknown_entry.get("profiles", []))[:6] if unknown_entry else [],
            },
            "score": score,
        }
        candidates.append(candidate)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "world_id": seeds_doc.get("world_id"),
        "sources": {
            "seeds": path_utils.to_repo_relative(args.seeds, repo_root=repo_root),
            "inventory": path_utils.to_repo_relative(args.inventory, repo_root=repo_root)
            if args.inventory.exists()
            else None,
            "unknown_nodes": path_utils.to_repo_relative(args.unknown_nodes, repo_root=repo_root)
            if args.unknown_nodes.exists()
            else None,
            "anchor_hits": path_utils.to_repo_relative(args.anchor_hits, repo_root=repo_root)
            if args.anchor_hits.exists()
            else None,
            "atlas": path_utils.to_repo_relative(atlas_path, repo_root=repo_root) if atlas_path else None,
        },
        "candidates": candidates,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {path_utils.to_repo_relative(args.out, repo_root=repo_root)}")


if __name__ == "__main__":
    main()
