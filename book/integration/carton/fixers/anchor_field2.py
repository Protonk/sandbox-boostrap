#!/usr/bin/env python3
"""Generate anchor → field2 relationship mapping for CARTON."""

from __future__ import annotations

from typing import Dict

from book.api import evidence_tiers
from book.integration.carton.fixers import common

ROOT = common.repo_root()
ANCHORS_PATH = ROOT / "book/graph/mappings/anchors/anchor_field2_map.json"
HITS_PATH = ROOT / "book/experiments/probe-op-structure/out/anchor_hits.json"
OUT_PATH = ROOT / "book/integration/carton/bundle/relationships/anchor_field2.json"


def build() -> Dict:
    anchors_doc = common.load_json(ANCHORS_PATH)
    hits_doc = common.load_json(HITS_PATH)
    world_id = common.baseline_world_id(repo_root_path=ROOT)
    common.assert_world_compatible(world_id, anchors_doc.get("metadata"), "anchor_field2_map")

    anchor_hits = {}
    for profile_name, payload in hits_doc.items():
        for anchor_entry in payload.get("anchors") or []:
            name = anchor_entry.get("anchor")
            if not name:
                continue
            anchor_hits.setdefault(name, []).append((profile_name, anchor_entry))

    anchors: Dict[str, Dict] = {}
    for anchor, entry in anchors_doc.items():
        if anchor == "metadata":
            continue
        profiles = entry.get("profiles") or {}
        field2_values = set()
        node_indices = set()
        sources = []
        for profile_name, observations in profiles.items():
            sources.append(profile_name)
            for obs in observations or []:
                field2_values.update(obs.get("field2_values") or [])
                node_indices.update(obs.get("node_indices") or [])
        anchors[anchor] = {
            "field2_values": sorted(field2_values),
            "node_indices": sorted(node_indices),
            "profiles": sorted(set(sources)),
            "status": entry.get("status", "partial"),
            "role": entry.get("role", "exploratory"),
            "sources": sorted(set(sources)),
        }
        if anchor not in anchor_hits:
            anchors[anchor]["warning"] = "anchor not present in anchor_hits; keep partial"

    doc = {
        "metadata": {
            "world_id": world_id,
            "status": anchors_doc.get("metadata", {}).get("status", "partial"),
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=OUT_PATH,
                tier="mapped",
            ),
            "inputs": [
                common.repo_relative(ANCHORS_PATH, repo_root_path=ROOT),
                common.repo_relative(HITS_PATH, repo_root_path=ROOT),
            ],
            "source_jobs": ["experiment:probe-op-structure"],
            "notes": "CARTON-facing anchor → field2 hints. Structural only; roles default to exploratory.",
        },
        "anchors": anchors,
    }
    return doc


def run() -> None:
    doc = build()
    common.write_json(OUT_PATH, doc)
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    run()
