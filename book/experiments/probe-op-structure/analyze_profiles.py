#!/usr/bin/env python3
"""
Analyze probe and system profiles for field2 histograms and literals.

Outputs:
- out/analysis.json with per-profile:
  - op_count (decoded)
  - node_count
  - field2 histogram with filter-name mapping
  - sample literal strings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any

import sys

# Repository root is three levels up: book/experiments/probe-op-structure/…
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from book.api.profile_tools import decoder  # type: ignore
from book.api.profile_tools import digests as digests_mod  # type: ignore


def load_vocab() -> Dict[str, Any]:
    ops = json.loads(Path("book/graph/mappings/vocab/ops.json").read_text())
    filters = json.loads(Path("book/graph/mappings/vocab/filters.json").read_text())
    return {
        "ops": ops,
        "filters": filters,
        "filter_id_to_name": {e["id"]: e["name"] for e in filters.get("filters", [])},
    }


def summarize(path: Path, vocab: Dict[str, Any]) -> Dict[str, Any]:
    data = path.read_bytes()
    dec = decoder.decode_profile_dict(data)
    nodes = dec.get("nodes") or []
    hist: Dict[int, int] = {}
    for node in nodes:
        fields = node.get("fields", [])
        if len(fields) > 2:
            val = fields[2]
            hist[val] = hist.get(val, 0) + 1
    filter_names = {
        v: vocab["filter_id_to_name"].get(v)
        for v in hist
    }
    return {
        "op_count_decoded": dec.get("op_count"),
        "node_count": dec.get("node_count"),
        "field2": [
            {"value": v, "count": c, "name": filter_names.get(v)}
            for v, c in sorted(hist.items(), key=lambda x: -x[1])
        ],
        "literal_strings_sample": (dec.get("literal_strings") or [])[:10],
    }


def main() -> None:
    vocab = load_vocab()
    canonical = digests_mod.canonical_system_profile_blobs(ROOT)
    profiles = {
        "probe:v0_file_require_all": Path("book/experiments/probe-op-structure/sb/build/v0_file_require_all.sb.bin"),
        "probe:v1_file_require_any": Path("book/experiments/probe-op-structure/sb/build/v1_file_require_any.sb.bin"),
        "probe:v2_file_three_filters_any": Path("book/experiments/probe-op-structure/sb/build/v2_file_three_filters_any.sb.bin"),
        "probe:v3_mach_global_local": Path("book/experiments/probe-op-structure/sb/build/v3_mach_global_local.sb.bin"),
        "probe:v4_network_socket_require_all": Path("book/experiments/probe-op-structure/sb/build/v4_network_socket_require_all.sb.bin"),
        "probe:v5_iokit_class_property": Path("book/experiments/probe-op-structure/sb/build/v5_iokit_class_property.sb.bin"),
        "probe:v9_iokit_user_client_only": Path("book/experiments/probe-op-structure/sb/build/v9_iokit_user_client_only.sb.bin"),
        "probe:v6_file_mach_combo": Path("book/experiments/probe-op-structure/sb/build/v6_file_mach_combo.sb.bin"),
        "probe:v7_file_network_combo": Path("book/experiments/probe-op-structure/sb/build/v7_file_network_combo.sb.bin"),
        "probe:v8_all_combo": Path("book/experiments/probe-op-structure/sb/build/v8_all_combo.sb.bin"),
        "sys:airlock": canonical["airlock"],
        "sys:bsd": canonical["bsd"],
        "sys:sample": canonical["sample"],
    }
    out: Dict[str, Any] = {}
    for name, path in profiles.items():
        if not path.exists():
            continue
        out[name] = summarize(path, vocab)

    out_dir = Path("book/experiments/probe-op-structure/out")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "analysis.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
