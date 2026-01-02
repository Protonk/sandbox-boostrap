#!/usr/bin/env python3
"""
Generate the canonical, context-indexed anchor → filter mapping for this world.

This artifact exists to avoid treating SBPL literal strings as type-safe.
The same literal can legitimately participate in multiple filter families
(and in multiple structural roles), so the canonical mapping surface is a
set of disjoint "anchor contexts" (`anchor_ctx_id`) rather than a single
literal-keyed record.

Outputs:
- `book/evidence/graph/mappings/anchors/anchor_ctx_filter_map.json`

Compatibility:
- `book/evidence/graph/mappings/anchors/anchor_filter_map.json` is a lossy, derived view
  generated from the ctx map by `generate_anchor_filter_map.py`.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api import world as world_mod  # type: ignore
from book.api.profile import decoder  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore

ANCHOR_FIELD2_MAP_PATH = REPO_ROOT / "book/evidence/graph/mappings/anchors/anchor_field2_map.json"
FILTER_VOCAB_PATH = REPO_ROOT / "book/evidence/graph/mappings/vocab/filters.json"
OUT_PATH = REPO_ROOT / "book/evidence/graph/mappings/anchors/anchor_ctx_filter_map.json"

SCHEMA_VERSION = "anchors.anchor_ctx_filter_map.v0.1"


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _baseline_world_id() -> str:
    world_doc, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)


def _filter_id_to_name() -> Dict[int, str]:
    filters = _load_json(FILTER_VOCAB_PATH)
    return {int(e["id"]): str(e["name"]) for e in (filters.get("filters") or []) if isinstance(e, dict)}


def _probe_blob_path(profile_id: str) -> Optional[Path]:
    if not profile_id.startswith("probe:"):
        return None
    name = profile_id.split(":", 1)[1]
    p = (
        REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build"
        / f"{name}.sb.bin"
    )
    return p if p.exists() else None


def _system_blob_path(profile_id: str) -> Optional[Path]:
    if not profile_id.startswith("sys:"):
        return None
    canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
    mapping = {
        "sys:airlock": canonical.get("airlock"),
        "sys:bsd": canonical.get("bsd"),
        "sys:sample": canonical.get("sample"),
    }
    p = mapping.get(profile_id)
    return p if isinstance(p, Path) and p.exists() else None


def _profile_blob_path(profile_id: str) -> Optional[Path]:
    return _probe_blob_path(profile_id) or _system_blob_path(profile_id)


def _stable_ctx_id(
    *,
    literal: str,
    tag: int,
    u16_role: str | None,
    filter_name: str | None,
) -> str:
    payload = json.dumps(
        {
            "literal": literal,
            "tag": tag,
            "u16_role": u16_role,
            "filter_name": filter_name,
        },
        sort_keys=True,
    ).encode("utf-8")
    return "ctx:" + hashlib.sha256(payload).hexdigest()[:16]


def _iter_curated_literals(seed_doc: Dict[str, Any], field2_doc: Dict[str, Any]) -> Iterable[str]:
    """
    Prefer literals already present in the ctx map, but allow new anchors
    from the anchor_field2_map to extend the curated set.
    """

    seen: Set[str] = set()
    if seed_doc:
        for entry in (seed_doc.get("entries") or {}).values():
            if isinstance(entry, dict) and isinstance(entry.get("literal"), str):
                literal = entry["literal"]
                if literal not in seen:
                    seen.add(literal)
                    yield literal

    for literal, entry in field2_doc.items():
        if literal == "metadata" or literal in seen:
            continue
        if isinstance(entry, dict):
            seen.add(literal)
            yield literal


def main() -> None:
    baseline_world_id = _baseline_world_id()
    filter_names = _filter_id_to_name()
    anchor_field2_map = _load_json(ANCHOR_FIELD2_MAP_PATH)
    existing_ctx: Dict[str, Any] = _load_json(OUT_PATH) if OUT_PATH.exists() else {}
    curated_literals = sorted(set(_iter_curated_literals(existing_ctx, anchor_field2_map)))

    # Decode each referenced profile once.
    decode_cache: Dict[str, Dict[str, Any]] = {}

    def decode_for(profile_id: str) -> Dict[str, Any] | None:
        if profile_id in decode_cache:
            return decode_cache[profile_id]
        blob_path = _profile_blob_path(profile_id)
        if not blob_path:
            return None
        dec = decoder.decode_profile_dict(blob_path.read_bytes())
        decode_cache[profile_id] = dec
        return dec

    entries: Dict[str, Any] = {}

    for literal in curated_literals:
        hints = anchor_field2_map.get(literal) or {}
        profiles = hints.get("profiles") or {}
        if not isinstance(profiles, dict):
            continue

        for profile_id, occs in profiles.items():
            if not isinstance(profile_id, str) or not isinstance(occs, list):
                continue
            dec = decode_for(profile_id)
            if not dec:
                continue
            nodes = dec.get("nodes") or []
            if not isinstance(nodes, list):
                continue

            for occ in occs:
                if not isinstance(occ, dict):
                    continue
                node_indices = occ.get("node_indices") or []
                if not isinstance(node_indices, list):
                    continue

                for idx in node_indices:
                    if not isinstance(idx, int) or idx < 0 or idx >= len(nodes):
                        continue
                    node = nodes[idx] or {}
                    if not isinstance(node, dict):
                        continue
                    tag = node.get("tag")
                    if not isinstance(tag, int):
                        continue

                    u16_role = node.get("u16_role") if isinstance(node.get("u16_role"), str) else None
                    filter_name = node.get("filter_vocab_ref") if isinstance(node.get("filter_vocab_ref"), str) else None
                    filter_id = None
                    if u16_role == "filter_vocab_id":
                        raw = node.get("filter_arg_raw")
                        if isinstance(raw, int):
                            filter_id = raw
                            # Prefer decoder's ref for naming; fall back to vocab.
                            if not filter_name:
                                filter_name = filter_names.get(raw)

                    ctx_id = _stable_ctx_id(literal=literal, tag=tag, u16_role=u16_role, filter_name=filter_name)
                    ent = entries.get(ctx_id)
                    if not isinstance(ent, dict):
                        ent = {
                            "literal": literal,
                            "tag": tag,
                            "u16_role": u16_role,
                            "filter_id": filter_id,
                            "filter_name": filter_name,
                            "sources": [],
                            "witnesses": {},
                            "field2_values": [],
                        }
                        entries[ctx_id] = ent

                    ent_sources: Set[str] = set(ent.get("sources") or [])
                    ent_sources.add(profile_id)
                    ent["sources"] = sorted(ent_sources)

                    witnesses = ent.get("witnesses")
                    if not isinstance(witnesses, dict):
                        witnesses = {}
                        ent["witnesses"] = witnesses
                    wl = witnesses.get(profile_id) or []
                    if not isinstance(wl, list):
                        wl = []
                    if idx not in wl:
                        wl.append(idx)
                    witnesses[profile_id] = sorted(set(wl))

                    # Record the observed raw u16 slot ("field2") for this node even when it
                    # is not a filter vocab id; this is useful when debugging collisions.
                    fields = node.get("fields") or []
                    if isinstance(fields, list) and len(fields) > 2 and isinstance(fields[2], int):
                        vals = set(ent.get("field2_values") or [])
                        vals.add(fields[2])
                        ent["field2_values"] = sorted(vals)

    out = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "world_id": baseline_world_id,
            "tier": "mapped",
            "notes": "Canonical anchor_ctx-indexed anchor→filter mapping; do not treat literal strings as type-safe.",
            "inputs": [
                str(path_utils.to_repo_relative(ANCHOR_FIELD2_MAP_PATH, REPO_ROOT)),
                str(path_utils.to_repo_relative(FILTER_VOCAB_PATH, REPO_ROOT)),
            ],
            "source_jobs": ["generator:anchors:anchor_ctx_filter_map"],
        },
        "entries": dict(sorted(entries.items())),
    }

    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {path_utils.to_repo_relative(OUT_PATH, REPO_ROOT)} ({len(entries)} ctx entries)")


if __name__ == "__main__":
    main()
