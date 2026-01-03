#!/usr/bin/env python3
"""
Test simple per-tag layout hypotheses over a small stride set.

For each profile and stride, treat the node region as an array of fixed-size
records. For records whose tag is in the TARGET_TAGS set, interpret the
first two 16-bit fields as edges and the third as a payload (field2),
compute in-bounds edge rates, and emit field2 histograms. This is a coarse
probe to guide per-tag layout choices; it does not claim to be correct.

Output:
- out/tag_layout_hypotheses.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

import sys
REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile import ingestion as pi  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore


TARGET_TAGS = {0, 5, 6, 17, 26, 27}
STRIDES = [12, 16]


def parse_records(nodes: bytes, stride: int) -> List[Dict[str, Any]]:
    recs = []
    count = len(nodes) // stride
    for idx in range(count):
        base = idx * stride
        tag = nodes[base]
        # interpret u16 fields at offsets 2,4,6,8,10 when present
        fields = []
        for off in (2, 4, 6, 8, 10):
            if base + off + 2 <= len(nodes):
                fields.append(int.from_bytes(nodes[base + off : base + off + 2], "little"))
        recs.append({"tag": tag, "fields": fields})
    return recs


def summarize_profile(path: Path) -> Dict[str, Any]:
    blob = path.read_bytes()
    pb = pi.ProfileBlob(bytes=blob, source=path.name)
    header = pi.parse_header(pb)
    sections = pi.slice_sections(pb, header)
    nodes = sections.nodes
    out: Dict[str, Any] = {"node_bytes": len(nodes), "strides": {}}

    for stride in STRIDES:
        recs = parse_records(nodes, stride)
        node_count = len(nodes) // stride
        tag_summ: Dict[str, Any] = {}
        for tag in TARGET_TAGS:
            tagged = [r for r in recs if r["tag"] == tag]
            if not tagged:
                continue
            edges = []
            field2_vals = []
            for r in tagged:
                f = r["fields"]
                if len(f) >= 1:
                    edges.append(f[0])
                if len(f) >= 2:
                    edges.append(f[1])
                if len(f) >= 3:
                    field2_vals.append(f[2])
            in_bounds = sum(1 for e in edges if 0 <= e < node_count)
            tag_summ[str(tag)] = {
                "count": len(tagged),
                "edge_fields_in_bounds": in_bounds,
                "edge_fields_total": len(edges),
                "field2_hist": {str(v): field2_vals.count(v) for v in set(field2_vals)},
            }
        out["strides"][str(stride)] = {
            "node_count": node_count,
            "remainder": len(nodes) % stride,
            "tags": tag_summ,
        }
    return out


def main() -> None:
    canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
    profiles = {
        "probe:v0_file_require_all": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v0_file_require_all.sb.bin",
        "probe:v1_file_require_any": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v1_file_require_any.sb.bin",
        "probe:v2_file_three_filters_any": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v2_file_three_filters_any.sb.bin",
        "probe:v3_mach_global_local": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v3_mach_global_local.sb.bin",
        "probe:v4_network_socket_require_all": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v4_network_socket_require_all.sb.bin",
        "probe:v5_iokit_class_property": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v5_iokit_class_property.sb.bin",
        "probe:v9_iokit_user_client_only": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v9_iokit_user_client_only.sb.bin",
        "probe:v10_iokit_user_client_pair": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v10_iokit_user_client_pair.sb.bin",
        "probe:v11_iokit_user_client_connection": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v11_iokit_user_client_connection.sb.bin",
        "probe:v6_file_mach_combo": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v6_file_mach_combo.sb.bin",
        "probe:v7_file_network_combo": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v7_file_network_combo.sb.bin",
        "probe:v8_all_combo": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build/v8_all_combo.sb.bin",
        "sys:airlock": canonical["airlock"],
        "sys:bsd": canonical["bsd"],
        "sys:sample": canonical["sample"],
    }
    out: Dict[str, Any] = {}
    for name, path in profiles.items():
        if not path.exists():
            continue
        out[name] = summarize_profile(path)

    out_dir = REPO_ROOT / "book/evidence/experiments/field2-final-final/probe-op-structure/out"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "tag_layout_hypotheses.json"
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
