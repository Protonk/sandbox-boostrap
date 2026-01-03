#!/usr/bin/env python3
"""
Generate the legacy, literal-keyed anchor → filter map as a conservative view.

This mapping is intentionally **lossy**. It exists for compatibility with
consumers that still index anchors by literal string, but it must not assert a
false uniqueness: the same SBPL literal can participate in multiple disjoint
filter contexts across the PolicyGraph.

Canonical source of truth:
- `book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json` (ctx-indexed)

Output:
- `book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json` (legacy compatibility)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api import world as world_mod  # type: ignore

CTX_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json"
OUT_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json"

CTX_SCHEMA_VERSION = "anchors.anchor_ctx_filter_map.v0.1"

_BASELINE_WORLD_ID: str | None = None


def _baseline_world_id() -> str:
    global _BASELINE_WORLD_ID
    if _BASELINE_WORLD_ID is None:
        world_doc, resolution = world_mod.load_world(repo_root=REPO_ROOT)
        _BASELINE_WORLD_ID = world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)
    return _BASELINE_WORLD_ID


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _entries_by_literal(ctx_doc: Dict[str, Any]) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    out: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    entries = ctx_doc.get("entries") or {}
    if not isinstance(entries, dict):
        return out
    for ctx_id, entry in entries.items():
        if not isinstance(ctx_id, str) or not isinstance(entry, dict):
            continue
        literal = entry.get("literal")
        if not isinstance(literal, str):
            continue
        out.setdefault(literal, []).append((ctx_id, entry))
    return out


def build_legacy_anchor_filter_map(ctx_doc: Mapping[str, Any], *, baseline_world_id: str) -> Dict[str, Any]:
    """
    Build the legacy, literal-keyed mapping as a deterministic derived view.

    This must be a pure function of the ctx map content. During migration we keep
    `anchor_filter_map.json` as a compatibility surface, but we do not preserve
    any manual edits or runtime notes here; those belong on the ctx-indexed
    canonical surface (or in runtime bundles/packets).
    """

    meta = ctx_doc.get("metadata") or {}
    if not isinstance(meta, dict) or meta.get("schema_version") != CTX_SCHEMA_VERSION:
        raise ValueError("unsupported ctx map schema_version")
    if meta.get("world_id") != baseline_world_id:
        raise ValueError("ctx map world_id mismatch vs baseline")

    by_literal = _entries_by_literal(dict(ctx_doc))

    out: Dict[str, Any] = {
        "metadata": {
            "world_id": baseline_world_id,
            "notes": "Legacy literal-keyed anchor→filter view derived conservatively from anchor_ctx_filter_map.json; do not treat as a unique binding.",
            "anchor_ctx_map": str(path_utils.to_repo_relative(CTX_PATH, REPO_ROOT)),
            "generated_by": str(path_utils.to_repo_relative(Path(__file__), REPO_ROOT)),
        }
    }

    for literal, ctx_entries in sorted(by_literal.items()):
        ctx_ids = sorted({cid for cid, _ in ctx_entries})
        sources: Set[str] = set()
        field2_values: Set[int] = set()
        candidate_filters: Set[Tuple[int, str]] = set()

        for _cid, ent in ctx_entries:
            sources.update(ent.get("sources") or [])
            field2_values.update(ent.get("field2_values") or [])
            fid = ent.get("filter_id")
            fname = ent.get("filter_name")
            if isinstance(fid, int) and isinstance(fname, str):
                candidate_filters.add((fid, fname))

        # Conservative aggregation rule: pin only when *every* observed context
        # for this literal resolves to the same filter kind. If any context is
        # unresolved (no filter_id/filter_name), or if contexts disagree, the
        # legacy literal-level view must stay blocked.
        all_ctx_resolved = all(
            isinstance(ent.get("filter_id"), int) and isinstance(ent.get("filter_name"), str)
            for _cid, ent in ctx_entries
        )
        if all_ctx_resolved and len(candidate_filters) == 1:
            fid, fname = next(iter(candidate_filters))
            entry: Dict[str, Any] = {
                "filter_id": fid,
                "filter_name": fname,
                "field2_values": sorted(field2_values),
                "sources": sorted(sources),
                "ctx_ids": ctx_ids,
                "status": "partial",
                "notes": "Derived from anchor_ctx_filter_map.json: all observed contexts resolve to a single filter kind.",
            }
        else:
            entry = {
                "filter_id": None,
                "filter_name": None,
                "field2_values": sorted(field2_values),
                "sources": sorted(sources),
                "ctx_ids": ctx_ids,
                "candidates": sorted({name for _fid, name in candidate_filters}),
                "status": "blocked",
                "notes": "Ambiguous across contexts; consult anchor_ctx_filter_map.json via ctx_ids.",
            }

        out[literal] = entry

    return out


def render_json(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True)


def main() -> None:
    if not CTX_PATH.exists():
        raise FileNotFoundError(f"missing ctx map at {CTX_PATH}")
    ctx = _load_json(CTX_PATH)
    out = build_legacy_anchor_filter_map(ctx, baseline_world_id=_baseline_world_id())
    OUT_PATH.write_text(render_json(out))
    print(f"[+] wrote {path_utils.to_repo_relative(OUT_PATH, REPO_ROOT)} (derived from ctx map)")


if __name__ == "__main__":
    main()
