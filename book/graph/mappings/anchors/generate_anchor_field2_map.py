#!/usr/bin/env python3
"""
Regenerate `anchor_field2_map.json` from `probe-op-structure` anchor hits.

This mapping is a structural index (anchor -> per-profile node indices + field2
payloads) and is guarded for coherence against `anchor_hits.json`.

Do not hand-edit `anchor_field2_map.json`; rerun this generator instead.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api import evidence_tiers  # type: ignore
from book.api import world as world_mod  # type: ignore
HITS_PATH = REPO_ROOT / "book/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json"
DELTA_HITS_PATH = REPO_ROOT / "book/experiments/field2-final-final/probe-op-structure/out/anchor_hits_delta.json"
OUT_PATH = REPO_ROOT / "book/graph/mappings/anchors/anchor_field2_map.json"


def load_existing_roles() -> Dict[str, Tuple[str, str]]:
    if not OUT_PATH.exists():
        return {}
    data = json.loads(OUT_PATH.read_text())
    roles: Dict[str, Tuple[str, str]] = {}
    for anchor, entry in data.items():
        if anchor == "metadata" or not isinstance(entry, dict):
            continue
        roles[anchor] = (entry.get("role", "exploratory"), entry.get("status", "partial"))
    return roles


def main() -> None:
    world_doc, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    world_id = world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)
    hits_doc = json.loads(HITS_PATH.read_text())
    delta_doc = json.loads(DELTA_HITS_PATH.read_text()) if DELTA_HITS_PATH.exists() else {}
    delta_targets = set()
    delta_profiles: Dict[str, Any] = {}
    if isinstance(delta_doc, dict):
        meta = delta_doc.get("metadata")
        if isinstance(meta, dict):
            delta_targets.update([a for a in meta.get("anchors", []) if isinstance(a, str)])
        profiles = delta_doc.get("profiles")
        if isinstance(profiles, dict):
            delta_profiles = profiles
    existing_roles = load_existing_roles()

    per_anchor: Dict[str, Dict[str, Any]] = {}
    for profile_name, payload in hits_doc.items():
        for anchor_entry in payload.get("anchors") or []:
            anchor = anchor_entry.get("anchor")
            if not anchor:
                continue
            obs = {
                "node_indices": anchor_entry.get("node_indices") or [],
                "field2_values": anchor_entry.get("field2_values") or [],
                "field2_names": anchor_entry.get("field2_names") or [],
            }
            per_anchor.setdefault(anchor, {}).setdefault("profiles", {}).setdefault(profile_name, []).append(obs)

    if delta_targets and delta_profiles:
        per_anchor_delta: Dict[str, Dict[str, Any]] = {}
        for profile_name, payload in delta_profiles.items():
            if not isinstance(payload, dict):
                continue
            for anchor_entry in payload.get("anchors") or []:
                anchor = anchor_entry.get("anchor")
                if not anchor or anchor not in delta_targets:
                    continue
                obs = {
                    "node_indices": anchor_entry.get("node_indices") or [],
                    "field2_values": anchor_entry.get("field2_values") or [],
                    "field2_names": anchor_entry.get("field2_names") or [],
                }
                per_anchor_delta.setdefault(anchor, {}).setdefault("profiles", {}).setdefault(profile_name, []).append(obs)
        for anchor in delta_targets:
            if anchor in per_anchor_delta:
                per_anchor[anchor] = per_anchor_delta[anchor]

    input_paths = [path_utils.to_repo_relative(HITS_PATH, REPO_ROOT)]
    if delta_targets:
        input_paths.append(path_utils.to_repo_relative(DELTA_HITS_PATH, REPO_ROOT))

    out: Dict[str, Any] = {
        "metadata": {
            "world_id": world_id,
            "status": "partial",
            "tier": evidence_tiers.evidence_tier_for_artifact(
                path=path_utils.to_repo_relative(OUT_PATH, REPO_ROOT),
                tier="mapped",
            ),
            "inputs": input_paths,
            "source_jobs": ["experiment:probe-op-structure"],
            "notes": "Structural anchor -> field2 hints derived from probe-op-structure anchor_hits; exploratory, not semantic bindings.",
        }
    }

    for anchor in sorted(per_anchor.keys()):
        role, status = existing_roles.get(anchor, ("exploratory", "partial"))
        entry = per_anchor[anchor]
        entry["role"] = role
        entry["status"] = status
        out[anchor] = entry

    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {path_utils.to_repo_relative(OUT_PATH, REPO_ROOT)}")


if __name__ == "__main__":
    main()
