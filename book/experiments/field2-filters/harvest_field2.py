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
from typing import Dict, Any

import sys
sys.path.append("book/graph/concepts/validation")
import decoder  # type: ignore


def load_filters() -> Dict[int, str]:
    path = Path("book/graph/concepts/validation/out/vocab/filters.json")
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {entry["id"]: entry["name"] for entry in data.get("filters", [])}


def summarize_profile(path: Path, filter_names: Dict[int, str]) -> Dict[str, Any]:
    prof = decoder.decode_profile_dict(path.read_bytes())
    nodes = prof.get("nodes") or []
    hist: Dict[int, int] = {}
    for node in nodes:
        fields = node.get("fields", [])
        if len(fields) > 2:
            val = fields[2]
            hist[val] = hist.get(val, 0) + 1
    return {
        "op_count": prof.get("op_count"),
        "node_count": prof.get("node_count"),
        "field2": [
            {
                "value": v,
                "count": c,
                "name": filter_names.get(v),
            }
            for v, c in sorted(hist.items(), key=lambda x: -x[1])
        ],
    }


def main() -> None:
    filter_names = load_filters()
    profiles = {
        "airlock": Path("book/examples/extract_sbs/build/profiles/airlock.sb.bin"),
        "bsd": Path("book/examples/extract_sbs/build/profiles/bsd.sb.bin"),
        "sample": Path("book/examples/sb/build/sample.sb.bin"),
    }
    out = {
        name: summarize_profile(path, filter_names)
        for name, path in profiles.items()
        if path.exists()
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
