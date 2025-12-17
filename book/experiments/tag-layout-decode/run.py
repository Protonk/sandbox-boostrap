#!/usr/bin/env python3
"""
Regenerate tag-layout decode artifacts for the canonical system blobs.

Outputs:
- out/tag_histogram.json
- out/tag_literal_nodes.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import book.api.decoder as decoder


PROFILES: List[Tuple[str, str]] = [
    ("sys:airlock", "book/examples/extract_sbs/build/profiles/airlock.sb.bin"),
    ("sys:bsd", "book/examples/extract_sbs/build/profiles/bsd.sb.bin"),
    ("sys:sample", "book/examples/sb/build/sample.sb.bin"),
]


def _profile_short_name(profile: str) -> str:
    if profile.startswith("sys:"):
        return profile.split(":", 1)[1]
    return profile


def main() -> None:
    root = Path(__file__).parent
    out_dir = root / "out"
    out_dir.mkdir(exist_ok=True)

    tag_histogram: Dict[str, Any] = {}
    literal_nodes: List[Dict[str, Any]] = []

    for profile, rel_path in PROFILES:
        blob_path = ROOT / rel_path
        data = blob_path.read_bytes()
        decoded = decoder.decode_profile_dict(data)
        validation = decoded.get("validation", {})
        tag_histogram[_profile_short_name(profile)] = {
            "profile": profile,
            "blob_path": rel_path,
            "node_count": decoded.get("node_count"),
            "tag_counts": decoded.get("tag_counts"),
            "literal_count": len(decoded.get("literal_strings_with_offsets") or []),
            "has_literal_offsets": bool(decoded.get("literal_strings_with_offsets")),
            "sections": decoded.get("sections"),
            "node_stride_bytes": validation.get("node_stride_bytes"),
            "node_stride_selection": validation.get("node_stride_selection"),
        }

        nodes = decoded.get("nodes") or []
        for idx, node in enumerate(nodes):
            refs = node.get("literal_refs") or []
            if not refs:
                continue
            literal_nodes.append(
                {
                    "profile": profile,
                    "profile_short": _profile_short_name(profile),
                    "idx": idx,
                    "offset": node.get("offset"),
                    "tag": node.get("tag"),
                    "record_size": node.get("record_size"),
                    "fields": node.get("fields"),
                    "u16_role": node.get("u16_role"),
                    "filter_arg_raw": node.get("filter_arg_raw"),
                    "filter_vocab_ref": node.get("filter_vocab_ref"),
                    "filter_out_of_vocab": node.get("filter_out_of_vocab"),
                    "literal_refs": refs,
                    "hex": node.get("hex"),
                }
            )

    # Group by tag and keep a small, deterministic sample of examples.
    profile_rank = {_profile_short_name(p): i for i, (p, _) in enumerate(PROFILES)}
    by_tag: Dict[str, List[Dict[str, Any]]] = {}
    for rec in literal_nodes:
        tag = rec.get("tag")
        if tag is None:
            continue
        by_tag.setdefault(str(tag), []).append(rec)

    out_tag_nodes: Dict[str, Any] = {}
    for tag, recs in sorted(by_tag.items(), key=lambda kv: int(kv[0])):
        recs.sort(key=lambda r: (profile_rank.get(r.get("profile_short"), 999), int(r.get("idx") or 0)))
        out_tag_nodes[tag] = {"examples": recs[:3]}

    (out_dir / "tag_histogram.json").write_text(json.dumps(tag_histogram, indent=2, sort_keys=True))
    (out_dir / "tag_literal_nodes.json").write_text(json.dumps(out_tag_nodes, indent=2, sort_keys=True))
    print(f"[+] wrote {out_dir / 'tag_histogram.json'}")
    print(f"[+] wrote {out_dir / 'tag_literal_nodes.json'}")


if __name__ == "__main__":
    main()

