#!/usr/bin/env python3
"""
Delta attribution for IOSurfaceRootUserClient.

Compare a deny-default control blob against a single-rule IOSurface variant and
emit anchor hits restricted to nodes introduced by the variant and tagged as
filter-vocab-bearing nodes. This keeps the structural binding narrow even when
the literal appears in multiple contexts.

Output:
- out/anchor_hits_delta.json
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile import decoder  # type: ignore


CONTROL_PROFILE = "probe:v12_iokit_control"
VARIANT_PROFILE = "probe:v9_iokit_user_client_only"
DELTA_ANCHORS = ["IOSurfaceRootUserClient"]
ANCHOR_FILTER_EXCLUDE = {
    "IOSurfaceRootUserClient": {0},  # exclude generic path filter context
}

CONTROL_PATH = Path("book/experiments/probe-op-structure/sb/build/v12_iokit_control.sb.bin")
VARIANT_PATH = Path("book/experiments/probe-op-structure/sb/build/v9_iokit_user_client_only.sb.bin")
OUT_PATH = Path("book/experiments/probe-op-structure/out/anchor_hits_delta.json")
FILTERS_PATH = Path("book/graph/mappings/vocab/filters.json")


def _node_fingerprint(node: Dict[str, Any]) -> str:
    payload = {
        "tag": node.get("tag"),
        "fields": node.get("fields"),
        "u16_role": node.get("u16_role"),
        "filter_vocab_ref": node.get("filter_vocab_ref"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _delta_indices(control_nodes: List[Dict[str, Any]], variant_nodes: List[Dict[str, Any]]) -> List[int]:
    control_counts = Counter(_node_fingerprint(n) for n in control_nodes)
    delta: List[int] = []
    for idx, node in enumerate(variant_nodes):
        fp = _node_fingerprint(node)
        if control_counts.get(fp, 0) > 0:
            control_counts[fp] -= 1
            continue
        delta.append(idx)
    return delta


def _filter_names() -> Dict[int, str]:
    data = json.loads(FILTERS_PATH.read_text())
    return {e["id"]: e["name"] for e in data.get("filters", []) if isinstance(e, dict)}


def _strip_prefix(s: str) -> str:
    while s and not s[0].isalnum() and s[0] not in ("/", "."):
        s = s[1:]
    return s


def _strip_sbpl_literal_prefix(s: str) -> str:
    if len(s) >= 2 and s[0].isalpha() and s[0].isupper() and (s[1].isalnum() or s[1] in ("/", ".")):
        return s[1:]
    return s


def _matches_anchor(anchor: str, literal: str) -> bool:
    anchor_no_slash = anchor.lstrip("/")
    if anchor in literal:
        return True
    stripped = _strip_sbpl_literal_prefix(_strip_prefix(literal))
    if (anchor in stripped) or (anchor_no_slash and anchor_no_slash in stripped):
        return True
    if anchor.startswith("IO") and anchor[2:] and anchor[2:] in stripped:
        return True
    return False


def _delta_anchor_hits(delta_nodes: List[int], variant_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filter_names = _filter_names()
    out: List[Dict[str, Any]] = []
    delta_set = set(delta_nodes)
    for anchor in DELTA_ANCHORS:
        exclude = ANCHOR_FILTER_EXCLUDE.get(anchor, set())
        node_indices = []
        for idx, node in enumerate(variant_nodes):
            if idx not in delta_set:
                continue
            if node.get("u16_role") != "filter_vocab_id":
                continue
            for ref in node.get("literal_refs", []):
                if _matches_anchor(anchor, ref):
                    fields = node.get("fields", [])
                    if len(fields) > 2 and isinstance(fields[2], int):
                        if fields[2] in exclude:
                            break
                    node_indices.append(idx)
                    break
        field2_vals = []
        for idx in node_indices:
            fields = variant_nodes[idx].get("fields", [])
            if len(fields) > 2 and isinstance(fields[2], int):
                field2_vals.append(fields[2])
        out.append(
            {
                "anchor": anchor,
                "node_indices": sorted(set(node_indices)),
                "field2_values": field2_vals,
                "field2_names": [filter_names.get(v) for v in field2_vals],
                "literal_offsets": [],
                "literal_string_index": None,
                "offsets": [],
            }
        )
    return out


def main() -> None:
    control_blob = CONTROL_PATH.read_bytes()
    variant_blob = VARIANT_PATH.read_bytes()
    control_dec = decoder.decode_profile_dict(control_blob)
    variant_dec = decoder.decode_profile_dict(variant_blob)
    control_nodes = control_dec.get("nodes") or []
    variant_nodes = variant_dec.get("nodes") or []

    delta_nodes = _delta_indices(control_nodes, variant_nodes)

    out = {
        "metadata": {
            "control_profile": CONTROL_PROFILE,
            "variant_profile": VARIANT_PROFILE,
            "anchors": DELTA_ANCHORS,
            "node_filter": "u16_role == filter_vocab_id",
            "filter_exclude": {k: sorted(v) for k, v in ANCHOR_FILTER_EXCLUDE.items()},
            "delta_node_count": len(delta_nodes),
            "control_node_count": len(control_nodes),
            "variant_node_count": len(variant_nodes),
        },
        "profiles": {
            VARIANT_PROFILE: {
                "op_count": variant_dec.get("op_count"),
                "node_count": variant_dec.get("node_count"),
                "anchors": _delta_anchor_hits(delta_nodes, variant_nodes),
            }
        },
    }

    OUT_PATH.write_text(json.dumps(out, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
