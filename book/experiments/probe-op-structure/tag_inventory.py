#!/usr/bin/env python3
"""
Coarse tag inventory across probe/system profiles.

Treat stride-based parsing as a sanity check: count tags under several
candidate strides and record remainders. This does NOT assert a final
layout; it is intended to highlight where tags change with stride and
where tails/remainders appear.

Output:
- out/tag_inventory.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

import sys
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile_tools import ingestion as pi  # type: ignore


STRIDES = [6, 8, 10, 12, 16]


def count_tags(nodes: bytes, stride: int) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    recs = len(nodes) // stride
    for idx in range(recs):
        tag = nodes[idx * stride]
        counts[str(tag)] = counts.get(str(tag), 0) + 1
    return counts


def summarize(path: Path) -> Dict[str, Any]:
    blob = path.read_bytes()
    pb = pi.ProfileBlob(bytes=blob, source=path.name)
    header = pi.parse_header(pb)
    sections = pi.slice_sections(pb, header)
    nodes = sections.nodes
    per_stride = []
    for stride in STRIDES:
        per_stride.append(
            {
                "stride": stride,
                "remainder": len(nodes) % stride,
                "tag_counts": count_tags(nodes, stride),
            }
        )
    return {
        "node_bytes": len(nodes),
        "per_stride": per_stride,
    }


def main() -> None:
    profiles = {
        "probe:v0_file_require_all": Path("book/experiments/probe-op-structure/sb/build/v0_file_require_all.sb.bin"),
        "probe:v1_file_require_any": Path("book/experiments/probe-op-structure/sb/build/v1_file_require_any.sb.bin"),
        "probe:v2_file_three_filters_any": Path("book/experiments/probe-op-structure/sb/build/v2_file_three_filters_any.sb.bin"),
        "probe:v3_mach_global_local": Path("book/experiments/probe-op-structure/sb/build/v3_mach_global_local.sb.bin"),
        "probe:v4_network_socket_require_all": Path("book/experiments/probe-op-structure/sb/build/v4_network_socket_require_all.sb.bin"),
        "probe:v5_iokit_class_property": Path("book/experiments/probe-op-structure/sb/build/v5_iokit_class_property.sb.bin"),
        "probe:v6_file_mach_combo": Path("book/experiments/probe-op-structure/sb/build/v6_file_mach_combo.sb.bin"),
        "probe:v7_file_network_combo": Path("book/experiments/probe-op-structure/sb/build/v7_file_network_combo.sb.bin"),
        "probe:v8_all_combo": Path("book/experiments/probe-op-structure/sb/build/v8_all_combo.sb.bin"),
        "sys:airlock": Path("book/examples/extract_sbs/build/profiles/airlock.sb.bin"),
        "sys:bsd": Path("book/examples/extract_sbs/build/profiles/bsd.sb.bin"),
        "sys:sample": Path("book/examples/sb/build/sample.sb.bin"),
    }
    out: Dict[str, Any] = {}
    for name, path in profiles.items():
        if not path.exists():
            continue
        out[name] = summarize(path)

    out_dir = Path("book/experiments/probe-op-structure/out")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "tag_inventory.json"
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
