#!/usr/bin/env python3
"""
Histogram slot values for fields[3]/fields[4] (u16 slots beyond edge0/edge1/payload)
in the canonical bsd/airlock blobs under the currently-published 12-byte layout.

This is purely descriptive: it does not assert that these slots are edges/payloads,
only that the decoded 12-byte records carry these values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils  # type: ignore
from book.api.profile import decoder  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore


def _hist_top(counter: Dict[int, int], limit: int = 20) -> List[Dict[str, int]]:
    return [
        {"value": k, "count": v}
        for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    ]


def _histogram_for_profile(path: Path) -> Dict[str, object]:
    d = decoder.decode_profile(path.read_bytes())
    per_tag: Dict[int, Dict[str, Dict[int, int]]] = {}
    for node in d.nodes:
        tag = int(node.get("tag"))
        fields = node.get("fields") or []
        if len(fields) < 5:
            continue
        t = per_tag.setdefault(tag, {"field3": {}, "field4": {}})
        f3 = int(fields[3])
        f4 = int(fields[4])
        t["field3"][f3] = t["field3"].get(f3, 0) + 1
        t["field4"][f4] = t["field4"].get(f4, 0) + 1

    tags_out: Dict[str, object] = {}
    for tag in sorted(per_tag):
        tags_out[str(tag)] = {
            "field3_distinct": len(per_tag[tag]["field3"]),
            "field4_distinct": len(per_tag[tag]["field4"]),
            "field3_top": _hist_top(per_tag[tag]["field3"]),
            "field4_top": _hist_top(per_tag[tag]["field4"]),
        }

    return {
        "source": path_utils.to_repo_relative(path),
        "node_count": d.node_count,
        "tag_counts": d.tag_counts,
        "tags": tags_out,
    }


def main() -> None:
    repo_root = ROOT
    out_dir = repo_root / "book/experiments/field2-final-final/bsd-airlock-highvals/out"
    out_dir.mkdir(exist_ok=True)

    canonical = digests_mod.canonical_system_profile_blobs(repo_root)
    bsd = canonical["bsd"]
    airlock = canonical["airlock"]

    payload = {
        "bsd": _histogram_for_profile(bsd),
        "airlock": _histogram_for_profile(airlock),
    }
    out_path = out_dir / "canonical_slots34_hist.json"
    out_path.write_text(json.dumps(payload, indent=2))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
