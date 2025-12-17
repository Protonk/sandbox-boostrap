#!/usr/bin/env python3
"""
Refresh `anchor_filter_map.json` against current `anchor_hits.json`.

This generator preserves the curated pinned `filter_id` decisions, but updates
each entry's recorded `field2_values` to cover all observed values across the
entry's declared `sources`.

If a pinned `filter_id` is no longer witnessed in its sources, the entry is
conservatively demoted to `status: blocked` (no pinned filter id).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Set

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
HITS_PATH = REPO_ROOT / "book/experiments/probe-op-structure/out/anchor_hits.json"
OUT_PATH = REPO_ROOT / "book/graph/mappings/anchors/anchor_filter_map.json"


def observed_field2(anchor: str, sources: list[str], hits_doc: dict) -> Set[int]:
    observed: Set[int] = set()
    for src in sources:
        profile_hits = hits_doc.get(src)
        if not profile_hits:
            continue
        for ah in profile_hits.get("anchors") or []:
            if ah.get("anchor") != anchor:
                continue
            for val in ah.get("field2_values") or []:
                if isinstance(val, int):
                    observed.add(val)
    return observed


def main() -> None:
    if not OUT_PATH.exists():
        raise FileNotFoundError(f"missing anchor_filter_map at {OUT_PATH}")
    amap = json.loads(OUT_PATH.read_text())
    hits_doc = json.loads(HITS_PATH.read_text())

    out: Dict[str, Any] = {}
    for anchor, entry in amap.items():
        if anchor == "metadata":
            out[anchor] = entry
            continue
        if not isinstance(entry, dict):
            out[anchor] = entry
            continue
        if entry.get("status") == "blocked":
            out[anchor] = entry
            continue

        filter_id = entry.get("filter_id")
        sources = entry.get("sources") or []
        if filter_id is None or not sources:
            out[anchor] = entry
            continue

        observed = observed_field2(anchor, sources, hits_doc)
        if not observed:
            demoted = dict(entry)
            demoted["status"] = "blocked"
            demoted.pop("filter_id", None)
            demoted.pop("filter_name", None)
            demoted["notes"] = (demoted.get("notes") or "") + " (demoted: no anchor_hits observations for sources)"
            out[anchor] = demoted
            continue

        if filter_id not in observed:
            demoted = dict(entry)
            demoted["status"] = "blocked"
            demoted.pop("filter_id", None)
            demoted.pop("filter_name", None)
            demoted["notes"] = (demoted.get("notes") or "") + " (demoted: pinned filter_id not witnessed in anchor_hits)"
            out[anchor] = demoted
            continue

        mapped = set(entry.get("field2_values") or [])
        mapped.update(observed)
        refreshed = dict(entry)
        refreshed["field2_values"] = sorted(mapped)
        out[anchor] = refreshed

    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {path_utils.to_repo_relative(OUT_PATH, REPO_ROOT)}")


if __name__ == "__main__":
    main()
