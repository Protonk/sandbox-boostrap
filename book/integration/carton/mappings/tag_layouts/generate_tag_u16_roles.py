#!/usr/bin/env python3
"""
Regenerate tag_u16_roles.json from canonical corpus evidence.

Role meaning (project-scoped):
- filter_vocab_id: the tag’s u16[2] payload behaves like a Filter vocabulary ID
  often enough to attempt resolution via `book/integration/carton/bundle/relationships/mappings/vocab/filters.json`.
- arg_u16: the tag’s u16[2] payload is a meaningful u16 but does not look like a
  Filter vocabulary ID on this host baseline.

Outputs:
- book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_u16_roles.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile import decoder  # type: ignore
from book.api import world as world_mod  # type: ignore


DIGESTS_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json"
TAG_LAYOUTS_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json"
FILTERS_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json"
OUT_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_u16_roles.json"


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing required input: {path}")
    return json.loads(path.read_text())


def world_id() -> str:
    meta, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return world_mod.require_world_id(meta, world_path=resolution.entry.world_path)


def filter_ids() -> Set[int]:
    data = load_json(FILTERS_PATH)
    return {int(e["id"]) for e in data.get("filters") or [] if "id" in e}


def canonical_sources(digests: Dict[str, Any]) -> List[Tuple[str, Path]]:
    profiles = digests.get("profiles") or {}
    out: List[Tuple[str, Path]] = []
    for pid, rec in sorted(profiles.items()):
        src = (rec or {}).get("source")
        if not src:
            continue
        out.append((pid, REPO_ROOT / src))
    if not out:
        raise RuntimeError("no canonical profile sources found in digests.json")
    return out


def tags_from_layouts() -> List[int]:
    layouts = load_json(TAG_LAYOUTS_PATH)
    tags = []
    for entry in layouts.get("tags") or []:
        try:
            tags.append(int(entry["tag"]))
        except Exception:
            continue
    if not tags:
        raise RuntimeError("tag_layouts.json contained no tags")
    return sorted(set(tags))


def role_for_tag(tag: int, stats: Dict[str, int]) -> str:
    total = stats.get("total", 0)
    hits = stats.get("hits", 0)
    if total >= 5 and (hits / total) >= 0.75:
        return "filter_vocab_id"
    return "arg_u16"


def main() -> None:
    digests = load_json(DIGESTS_PATH)
    sources = canonical_sources(digests)
    vocab_ids = filter_ids()
    tags = tags_from_layouts()

    per_tag: Dict[int, Dict[str, int]] = {t: {"total": 0, "hits": 0} for t in tags}
    for _pid, path in sources:
        if not path.exists():
            raise FileNotFoundError(f"missing canonical blob: {path}")
        prof = decoder.decode_profile_dict(path.read_bytes())
        for node in prof.get("nodes") or []:
            try:
                node_tag = int(node.get("tag"))
            except Exception:
                continue
            if node_tag not in per_tag:
                continue
            fields = node.get("fields") or []
            if len(fields) <= 2:
                continue
            raw = int(fields[2])
            lo = raw & 0x3FFF
            hi = raw & 0xC000
            per_tag[node_tag]["total"] += 1
            if hi == 0 and lo in vocab_ids:
                per_tag[node_tag]["hits"] += 1

    roles = [{"tag": t, "u16_role": role_for_tag(t, per_tag[t])} for t in tags]

    payload = {
        "world_id": world_id(),
        "status": "ok",
        "inputs": [
            str(TAG_LAYOUTS_PATH.relative_to(REPO_ROOT)),
            str(FILTERS_PATH.relative_to(REPO_ROOT)),
        ],
        "source_jobs": [
            "generator:tag_layouts:tag_layouts",
            "generator:tag_layouts:tag_u16_roles",
        ],
        "notes": "Per-tag u16 role for the structural u16[2] slot surfaced as field2 in decoder/experiments; derived from canonical corpus filter-vocab hit ratios on this host baseline.",
        "roles": roles,
    }

    OUT_PATH.write_text(json.dumps(payload, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
