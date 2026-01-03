#!/usr/bin/env python3
"""
Collect field2 inventories for quick comparison.

Outputs per-profile:
- op_count, node_count
- field2 histogram
- optional name mapping via filters.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

import sys
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from book.api.profile import decoder  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore


def load_filters() -> Dict[int, str]:
    path = Path("book/integration/carton/bundle/relationships/mappings/vocab/filters.json")
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {entry["id"]: entry["name"] for entry in data.get("filters", [])}


def summarize_profile(path: Path, filter_names: Dict[int, str], anchors: Dict[str, Any]) -> Dict[str, Any]:
    prof = decoder.decode_profile_dict(path.read_bytes())
    nodes = prof.get("nodes") or []
    hist: Dict[int, Dict[str, Any]] = {}
    unknown_nodes: List[Dict[str, Any]] = []
    for idx, node in enumerate(nodes):
        fields = node.get("fields", [])
        if len(fields) > 2:
            # field2 is the raw filter_arg payload; derive hi/lo views for analysis
            raw = fields[2]
            hi = raw & 0xC000
            lo = raw & 0x3FFF
            entry = hist.setdefault(
                raw,
                {
                    "raw": raw,
                    "raw_hex": hex(raw),
                    "hi": hi,
                    "lo": lo,
                    "name": filter_names.get(lo) if hi == 0 else None,
                    "count": 0,
                    "tags": {},
                },
            )
            entry["count"] += 1
            entry["tags"][node.get("tag")] = entry["tags"].get(node.get("tag"), 0) + 1
            is_known = entry["name"] is not None
            if (entry["hi"] != 0 or not is_known) and raw not in filter_names:
                unknown_nodes.append(
                    {
                        "idx": idx,
                        "tag": node.get("tag"),
                        "fields": fields,
                        "raw": raw,
                        "raw_hex": entry["raw_hex"],
                        "hi": entry["hi"],
                        "lo": entry["lo"],
                        "literal_refs": node.get("literal_refs", []),
                    }
                )
    anchor_hits = anchors if isinstance(anchors, list) else anchors.get(path.stem, [])
    return {
        "op_count": prof.get("op_count"),
        "node_count": prof.get("node_count"),
        "field2": [
            hist[k]
            for k in sorted(hist, key=lambda key: -hist[key]["count"])
        ],
        "unknown_nodes": unknown_nodes,
        "anchors": anchor_hits,
    }


def main() -> None:
    filter_names = load_filters()
    canonical = digests_mod.canonical_system_profile_blobs(ROOT)
    profiles: Dict[str, Path] = {
        "sys:airlock": canonical["airlock"],
        "sys:bsd": canonical["bsd"],
        "sys:sample": canonical["sample"],
    }

    # Pull in the single-filter probes for this experiment
    probes_dir = Path("book/evidence/experiments/field2-final-final/field2-filters/sb/build")
    if probes_dir.exists():
        for p in sorted(probes_dir.glob("*.sb.bin")):
            profiles[f"probe:{p.stem}"] = p

    # Include selected mixed-operation probes from probe-op-structure to capture flow-divert and other
    # richer shapes that surface high/unknown field2 payloads.
    probe_op_dir = Path("book/evidence/experiments/field2-final-final/probe-op-structure/sb/build")
    if probe_op_dir.exists():
        for p in sorted(probe_op_dir.glob("*.sb.bin")):
            profiles[f"probe-op:{p.stem}"] = p

    # Anchor hits (optional): reuse probe-op-structure results where names match stem keys
    anchors_map: Dict[str, Any] = {}
    anchor_hits_path = Path("book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json")
    if anchor_hits_path.exists():
        raw = json.loads(anchor_hits_path.read_text())
        for prof_key, rec in raw.items():
            anchors_map[Path(prof_key).stem] = rec.get("anchors", [])

    out = {
        name: summarize_profile(path, filter_names, anchors_map.get(name, []))
        for name, path in profiles.items()
        if path.exists()
    }

    out_dir = Path("book/evidence/experiments/field2-final-final/field2-filters/out")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "field2_inventory.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
