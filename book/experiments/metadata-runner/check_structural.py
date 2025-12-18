#!/usr/bin/env python3
"""
Cross-check anchors/tags/field2 against anchor_filter_map for metadata-runner profiles.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import find_repo_root  # type: ignore
from book.api.profile_tools import decoder  # type: ignore

BASE_DIR = Path(__file__).resolve().parent
SB_BUILD = BASE_DIR / "sb" / "build"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = find_repo_root(Path(__file__)) / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"
ANCHOR_MAP_PATH = REPO_ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json"

# Paths exercised by this experiment
PATH_PAIRS = [
    ("/tmp/foo", "/private/tmp/foo"),
    ("/tmp/bar", "/private/tmp/bar"),
    ("/tmp/nested/child", "/private/tmp/nested/child"),
    ("/var/tmp/canon", "/private/var/tmp/canon"),
]


def _literal_candidates(s: str) -> Set[str]:
    """
    Generate plausible path forms for a decoder literal string.
    Drop the type byte and add variants with/without leading slash.
    """
    out: Set[str] = set()
    if not s:
        return out
    trimmed = s.lstrip()
    if trimmed.startswith("/"):
        out.add(trimmed)
    if trimmed:
        body = trimmed[1:]  # drop type byte
        out.add(body)
        if body and not body.startswith("/"):
            out.add(f"/{body}")
    return out


def anchor_present(anchor: str, literals: Set[str]) -> bool:
    """Heuristic presence check for anchors from normalized literal strings."""
    if anchor in literals:
        return True
    parts = anchor.strip("/").split("/")
    if not parts:
        return False
    first = f"/{parts[0]}/"
    if first not in literals:
        return False
    if len(parts) == 1:
        return True
    tail = "/".join(parts[1:])
    if tail in literals or f"/{tail}" in literals:
        return True
    if len(parts) >= 3:
        mid = f"{parts[1]}/"
        tail_rest = "/".join(parts[2:])
        if ((mid in literals) or (f"/{parts[1]}/" in literals)) and (
            (tail_rest in literals) or (f"/{tail_rest}" in literals)
        ):
            return True
    if all(((seg in literals) or (f"/{seg}" in literals) or (f"{seg}/" in literals)) for seg in parts[1:]):
        return True
    return False


def load_world_id() -> str:
    data = json.loads(WORLD_PATH.read_text())
    return data.get("world_id") or data.get("id", "unknown-world")


def decode_profile(blob_path: Path, anchors: Iterable[str]) -> Dict[str, Any]:
    data = blob_path.read_bytes()
    dec = decoder.decode_profile_dict(data)
    literal_set: Set[str] = set()
    for lit in dec.get("literal_strings") or []:
        literal_set.update(_literal_candidates(lit))
    nodes = dec.get("nodes") or []

    out: Dict[str, Any] = {}
    for anchor in anchors:
        present = anchor_present(anchor, literal_set)
        tag_ids: Set[Any] = set()
        field2_vals: Set[Any] = set()
        for node in nodes:
            ref_candidates: Set[str] = set()
            for ref in (node.get("literal_refs") or []):
                ref_candidates.update(_literal_candidates(ref))
            if anchor_present(anchor, ref_candidates):
                tag_ids.add(node.get("tag"))
                fields = node.get("fields") or []
                if len(fields) > 2:
                    field2_vals.add(fields[2])
        out[anchor] = {
            "present": present,
            "tags": sorted(tag_ids),
            "field2_values": sorted(field2_vals),
        }
    return out


def main() -> int:
    world_id = load_world_id()
    anchor_map = json.loads(ANCHOR_MAP_PATH.read_text())
    anchors_of_interest = []
    for alias, canonical in PATH_PAIRS:
        for p in (alias, canonical):
            if p in anchor_map:
                anchors_of_interest.append(p)
    anchors_of_interest = sorted(set(anchors_of_interest))

    profiles = {}
    for blob_path in sorted(SB_BUILD.glob("*.sb.bin")):
        profile_id = blob_path.stem
        profiles[profile_id] = decode_profile(blob_path, anchors_of_interest)

    comparisons: Dict[str, Any] = {}
    for anchor in anchors_of_interest:
        expected = anchor_map.get(anchor, {})
        comparisons[anchor] = {
            "filter_name": expected.get("filter_name"),
            "filter_id": expected.get("filter_id"),
            "expected_field2": expected.get("field2_values"),
            "status": expected.get("status"),
            "profiles": {},
        }
        for pid, decoded in profiles.items():
            actual = decoded.get(anchor, {"present": False, "tags": [], "field2_values": []})
            comparisons[anchor]["profiles"][pid] = {
                "present": actual["present"],
                "tags": actual["tags"],
                "field2_values": actual["field2_values"],
                "field2_match": set(actual["field2_values"]) == set(expected.get("field2_values") or []),
            }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "anchor_structural_check.json"
    out_path.write_text(json.dumps({"world_id": world_id, "anchors_checked": anchors_of_interest, "comparisons": comparisons}, indent=2))
    print(f"[+] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
