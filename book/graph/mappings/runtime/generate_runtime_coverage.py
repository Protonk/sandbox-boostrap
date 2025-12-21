#!/usr/bin/env python3
"""
Generate runtime/runtime_coverage.json from runtime story.

Inputs:
- book/graph/mappings/runtime_cuts/runtime_story.json
- book/experiments/runtime-adversarial/out/impact_map.json (to allow scoped mismatches)
- world baseline (host/world_id)

Status is downgraded to partial if any op has disallowed mismatches.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[4]
BASELINE = ROOT / "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
RUNTIME_STORY = ROOT / "book/graph/mappings/runtime_cuts/runtime_story.json"
IMPACT_MAP = ROOT / "book/experiments/runtime-adversarial/out/impact_map.json"
OUT = ROOT / "book/graph/mappings/runtime/runtime_coverage.json"


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def baseline_world() -> str:
    data = load_json(BASELINE)
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def allowed_mismatch(expectation_id: str, impact_map: Dict[str, Any]) -> bool:
    allowed_tags = set((impact_map.get("metadata") or {}).get("allowed_tags") or [])
    entry = impact_map.get(expectation_id) or {}
    tags = set(entry.get("tags") or [])
    return bool(allowed_tags and tags and tags.issubset(allowed_tags))


def mismatch_tags(expectation_id: str, impact_map: Dict[str, Any]) -> set[str]:
    entry = impact_map.get(expectation_id) or {}
    return set(entry.get("tags") or [])


def main() -> None:
    world_id = baseline_world()
    story = load_json(RUNTIME_STORY)
    impact_map = load_json(IMPACT_MAP)

    story_meta = story.get("meta") or {}
    story_inputs = story_meta.get("inputs") or ["book/graph/mappings/runtime_cuts/runtime_story.json"]
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
    inputs = story_inputs + ["book/experiments/runtime-adversarial/out/impact_map.json"]
    mapping = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "input_hashes": story_meta.get("input_hashes"),
            "source_jobs": ["experiment:runtime-checks", "experiment:runtime-adversarial"],
            "status": overall_status,
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

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(mapping, indent=2))
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
