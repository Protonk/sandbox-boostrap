#!/usr/bin/env python3
"""
Generate runtime/runtime_coverage.json from runtime story + promotion packet inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Any, List

import sys

ROOT = Path(__file__).resolve().parents[4]
RUNTIME_STORY = ROOT / "book/graph/mappings/runtime_cuts/runtime_story.json"
OUT = ROOT / "book/graph/mappings/runtime/runtime_coverage.json"

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promotion_packets
from book.api import path_utils
from book.api import evidence_tiers
from book.api import world as world_mod


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline_world() -> str:
    data, resolution = world_mod.load_world(repo_root=ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def allowed_mismatch(expectation_id: str, impact_map: Dict[str, Any]) -> bool:
    allowed_tags = set((impact_map.get("metadata") or {}).get("allowed_tags") or [])
    entry = impact_map.get(expectation_id) or {}
    tags = set(entry.get("tags") or [])
    return bool(allowed_tags and tags and tags.issubset(allowed_tags))


def mismatch_tags(expectation_id: str, impact_map: Dict[str, Any]) -> set[str]:
    entry = impact_map.get(expectation_id) or {}
    return set(entry.get("tags") or [])


def build_coverage(
    story: Dict[str, Any],
    impact_map: Dict[str, Any],
    world_id: str,
    inputs: List[str],
    input_hashes: Dict[str, str] | None,
    source_jobs: List[str],
) -> Dict[str, Any]:
    story_meta = story.get("meta") or {}
    coverage: Dict[str, Any] = {}
    disallowed = []
    global_tag_counts: Dict[str, int] = {}
    global_mismatch_total = 0

    for op_entry in (story.get("ops") or {}).values():
        op_name = op_entry.get("op_name")
        if not op_name:
            continue
        scenarios = [s.get("scenario_id") for s in op_entry.get("scenarios") or [] if s.get("scenario_id")]
        op_disallowed = []
        op_tag_counts: Dict[str, int] = {}
        op_mismatch_total = 0
        for scenario in op_entry.get("scenarios") or []:
            for mismatch in scenario.get("mismatches") or []:
                eid = mismatch.get("expectation_id") or ""
                if not eid:
                    continue
                op_mismatch_total += 1
                tags = mismatch_tags(eid, impact_map)
                for tag in tags:
                    op_tag_counts[tag] = op_tag_counts.get(tag, 0) + 1
                    global_tag_counts[tag] = global_tag_counts.get(tag, 0) + 1
                if not allowed_mismatch(eid, impact_map):
                    op_disallowed.append(eid)
                    disallowed.append({"op_name": op_name, "expectation_id": eid})
        status = "ok" if not op_disallowed else "partial"
        summary = {
            "total_mismatches": op_mismatch_total,
            "total_disallowed_mismatches": len(op_disallowed),
            "tags": op_tag_counts,
        }
        coverage[op_name] = {
            "op_id": op_entry.get("op_id"),
            "runtime_signatures": sorted(scenarios),
            "counts": {"runtime_signatures": len(scenarios)},
            "status": status,
            "mismatches": sorted(set(op_disallowed)),
            "mismatch_summary": summary,
        }
        global_mismatch_total += op_mismatch_total

    overall_status = "ok" if not disallowed else "partial"
    return {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "input_hashes": input_hashes,
            "source_jobs": source_jobs,
            "status": overall_status,
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=path_utils.to_repo_relative(OUT, ROOT),
                tier="mapped",
            ),
            "notes": "Runtime coverage derived from runtime_story; mismatches allowed only when tagged in impact_map.json.",
            "mismatches": disallowed,
            "mismatch_summary": {
                "total_mismatches": global_mismatch_total,
                "total_disallowed_mismatches": len(disallowed),
                "tags": global_tag_counts,
            },
            "provenance": {"runtime_story": story_meta},
        },
        "coverage": coverage,
    }


def generate(packet_paths: List[Path] | None = None, impact_map_path: Path | None = None) -> Path:
    world_id = baseline_world()
    story = load_json(RUNTIME_STORY)
    packets = promotion_packets.load_packets(packet_paths or promotion_packets.DEFAULT_PACKET_PATHS, allow_missing=True)
    for packet in packets:
        promotion_packets.require_clean_manifest(packet, str(packet.packet_path))

    impact_map_path = (
        path_utils.ensure_absolute(impact_map_path, ROOT) if impact_map_path else promotion_packets.select_impact_map(packets)
    )
    impact_map = load_json(impact_map_path) if impact_map_path else {}

    story_meta = story.get("meta") or {}
    story_inputs = story_meta.get("inputs") or ["book/graph/mappings/runtime_cuts/runtime_story.json"]
    inputs = list(story_inputs)
    input_hashes = dict(story_meta.get("input_hashes") or {})
    source_jobs = ["promotion_packet"]
    for packet in packets:
        rel = path_utils.to_repo_relative(packet.packet_path, ROOT)
        inputs.append(rel)
        input_hashes[rel] = sha256_path(packet.packet_path)
    if impact_map_path:
        rel = path_utils.to_repo_relative(impact_map_path, ROOT)
        inputs.append(rel)
        input_hashes[rel] = sha256_path(impact_map_path)

    mapping = build_coverage(
        story=story,
        impact_map=impact_map,
        world_id=world_id,
        inputs=inputs,
        input_hashes=input_hashes or None,
        source_jobs=source_jobs,
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT}")
    return OUT


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate runtime coverage from promotion packets.")
    parser.add_argument("--packets", type=Path, action="append", help="Promotion packet paths")
    parser.add_argument("--impact-map", type=Path, help="Override impact_map.json path")
    args = parser.parse_args()
    generate(packet_paths=args.packets, impact_map_path=args.impact_map)


if __name__ == "__main__":
    main()
