#!/usr/bin/env python3
"""
Emit focused details for nodes with high/unknown field2 values, including fan-in/out counts
based on tag layouts (edge fields) and basic literal references.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set

import sys
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from book.api.profile_tools import decoder  # type: ignore
from book.api.profile_tools import digests as digests_mod  # type: ignore

# Field2 payloads that are intentionally characterized elsewhere and should not
# be treated as "unknown" in this inventory.
CHARACTERIZED_FIELD2 = {
    2560,  # flow-divert triple-only token (tag0, literal com.apple.flow-divert)
    2816,  # flow-divert triple-only token (appears alongside 2560 in the matrix)
}


def load_layouts() -> Dict[int, Dict[str, Any]]:
    path = Path("book/graph/mappings/tag_layouts/tag_layouts.json")
    data = json.loads(path.read_text())
    return {rec["tag"]: rec for rec in data.get("tags", [])}


def edge_fields_for(tag: int, layouts: Dict[int, Dict[str, Any]]) -> List[int]:
    rec = layouts.get(tag)
    if not rec:
        return []
    return rec.get("edge_fields", [])


def build_reachability(nodes: List[Dict[str, Any]], layouts: Dict[int, Dict[str, Any]], op_table: List[int]) -> List[Set[int]]:
    adjacency: Dict[int, List[int]] = {}
    for idx, node in enumerate(nodes):
        fields = node.get("fields", [])
        edges = [fields[i] for i in edge_fields_for(node.get("tag", -1), layouts) if i < len(fields)]
        adjacency[idx] = [e for e in edges if isinstance(e, int) and 0 <= e < len(nodes)]

    reach: List[Set[int]] = [set() for _ in nodes]
    for op_id, entry in enumerate(op_table or []):
        if not isinstance(entry, int) or entry < 0 or entry >= len(nodes):
            continue
        stack = [entry]
        seen: Set[int] = set()
        while stack:
            node_idx = stack.pop()
            if node_idx in seen:
                continue
            seen.add(node_idx)
            reach[node_idx].add(op_id)
            stack.extend(adjacency.get(node_idx, []))
    return reach


def summarize_profile(path: Path, filter_names: Dict[int, str], op_names: Dict[int, str], layouts: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    prof = decoder.decode_profile_dict(path.read_bytes())
    nodes = prof.get("nodes") or []
    op_table: List[int] = prof.get("op_table") or []
    # Build fan-in counts
    fan_in: Dict[int, int] = {}
    for idx, node in enumerate(nodes):
        fields = node.get("fields", [])
        edges = [fields[i] for i in edge_fields_for(node.get("tag", -1), layouts) if i < len(fields)]
        for e in edges:
            fan_in[e] = fan_in.get(e, 0) + 1

    reach = build_reachability(nodes, layouts, op_table)

    unknowns: List[Dict[str, Any]] = []
    for idx, node in enumerate(nodes):
        if node.get("u16_role") != "filter_vocab_id":
            continue
        fields = node.get("fields", [])
        if len(fields) < 3:
            continue
        raw = fields[2]
        hi = raw & 0xC000
        lo = raw & 0x3FFF
        name = filter_names.get(lo) if hi == 0 else None
        if node.get("filter_out_of_vocab") or hi != 0 or name is None:
            # Skip payloads we have characterized elsewhere to avoid re-classifying them as unknown.
            if raw in CHARACTERIZED_FIELD2:
                continue
            edges = [fields[i] for i in edge_fields_for(node.get("tag", -1), layouts) if i < len(fields)]
            unknowns.append(
                {
                    "idx": idx,
                    "tag": node.get("tag"),
                    "fields": fields,
                    "edges": edges,
                    "fan_out": len([e for e in edges if 0 <= e < len(nodes)]),
                    "fan_in": fan_in.get(idx, 0),
                    "ops": [
                        {"id": op_id, "name": op_names.get(op_id)}
                        for op_id in sorted(reach[idx])
                    ],
                    "raw": raw,
                    "raw_hex": hex(raw),
                    "hi": hi,
                    "lo": lo,
                    "name_lo": name,
                    "literal_refs": node.get("literal_refs", []),
                }
            )
    return {"path": str(path), "unknown_nodes": unknowns}


def main() -> None:
    filter_names = {entry["id"]: entry["name"] for entry in json.loads(Path("book/graph/mappings/vocab/filters.json").read_text()).get("filters", [])}
    op_names = {entry["id"]: entry["name"] for entry in json.loads(Path("book/graph/mappings/vocab/ops.json").read_text()).get("ops", [])}
    layouts = load_layouts()

    canonical = digests_mod.canonical_system_profile_blobs(ROOT)
    profiles: Dict[str, Path] = {
        "sys:bsd": canonical["bsd"],
        "sys:airlock": canonical["airlock"],
        "sys:sample": canonical["sample"],
    }

    probes_dir = Path("book/experiments/field2-filters/sb/build")
    if probes_dir.exists():
        for p in sorted(probes_dir.glob("*.sb.bin")):
            profiles[f"probe:{p.stem}"] = p

    probe_op_dir = Path("book/experiments/probe-op-structure/sb/build")
    if probe_op_dir.exists():
        for p in sorted(probe_op_dir.glob("*.sb.bin")):
            profiles[f"probe-op:{p.stem}"] = p

    out: Dict[str, Any] = {}
    for name, p in profiles.items():
        if not p.exists():
            continue
        rec = summarize_profile(p, filter_names, op_names, layouts)
        out[name] = rec["unknown_nodes"]
    out_dir = Path("book/experiments/field2-filters/out")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "unknown_nodes.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
