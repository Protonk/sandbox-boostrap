#!/usr/bin/env python3
"""
Emit static checks for canonical compiled profiles.

Uses decoder + inspect_profile to record invariants:
- op_count, section sizes
- tag counts, tag_layout hash applied
- op-table signature hash
- anchor hits (reusing attestation generation)

Outputs:
- book/graph/mappings/system_profiles/static_checks.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile import decoder
from book.api.profile import digests as digests_mod
from book.api import evidence_tiers
from book.api import world as world_mod
from book.graph.concepts.validation import profile_ingestion as pi
OUT_PATH = REPO_ROOT / "book/graph/mappings/system_profiles/static_checks.json"


def load_baseline() -> Dict[str, Any]:
    data, _resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return data


def baseline_world_id() -> str:
    data, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return world_mod.require_world_id(data, world_path=resolution.entry.world_path)


def tag_layout_hash(path: Path) -> str:
    payload = json.loads(path.read_text())
    tags = {"tags": payload.get("tags")}
    # Hash only the tag set/order so harmless edits (doc strings, metadata
    # notes, etc.) do not trigger contract drift. Changing the tags themselves
    # will change the hash and force a new contract.
    return hashlib.sha256(json.dumps(tags, sort_keys=True).encode()).hexdigest()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def summarize(path: Path, tag_layout_hash: str) -> Dict[str, Any]:
    blob = path.read_bytes()
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=path.name))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=path.name), header)
    dec = decoder.decode_profile_dict(blob)
    op_table_hash = hashlib.sha256(dec.get("op_table", b"") if isinstance(dec.get("op_table"), (bytes, bytearray)) else json.dumps(dec.get("op_table", [])).encode()).hexdigest()
    return {
        "path": str(path.relative_to(REPO_ROOT)),
        "sha256": sha256(path),
        "format_variant": header.format_variant,
        "op_count_header": header.operation_count,
        "sections": {
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        "tag_counts": dec.get("tag_counts"),
        "op_table_hash": op_table_hash,
        "tag_layout_hash": tag_layout_hash,
    }


def main() -> None:
    world_doc, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    world_id = world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)
    tag_layouts_path = REPO_ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"
    tag_layout_hash_value = tag_layout_hash(tag_layouts_path)
    tag_layouts_file_sha256 = sha256(tag_layouts_path)
    canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
    profiles = [canonical["airlock"], canonical["bsd"], canonical["sample"]]
    checks = [summarize(p, tag_layout_hash_value) for p in profiles if p.exists()]
    OUT_PATH.write_text(
        json.dumps(
            {
                "metadata": {
                    "world_id": world_id,
                    "tag_layout_hash": tag_layout_hash_value,
                    "tag_layout_hash_method": "tag_set",
                    "tag_layouts_file_sha256": tag_layouts_file_sha256,
                    "inputs": [
                        world_mod.world_path_for_metadata(resolution, repo_root=REPO_ROOT),
                        "book/graph/mappings/tag_layouts/tag_layouts.json",
                    ]
                    + [str(p.relative_to(REPO_ROOT)) for p in profiles if p.exists()],
                    "source_jobs": ["generator:system_profiles:static_checks"],
                    "status": "ok",
                    "tier": evidence_tiers.evidence_tier_for_artifact(
                        path=OUT_PATH,
                    ),
                },
                "entries": checks,
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
