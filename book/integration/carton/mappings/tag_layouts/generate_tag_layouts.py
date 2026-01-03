#!/usr/bin/env python3
"""
Regenerate the tag layout mapping for the canonical system-profile corpus.

This generator is intentionally structural and world-scoped:
- It decodes the canonical compiled blobs via `book.api.profile.decoder` (which selects
  the framing for this host baseline).
- It unions all observed tag bytes.
- It emits a conservative per-tag layout record (record size + edge/payload
  field indices) suitable for downstream decoders and experiments.

Outputs:
- book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile import decoder  # type: ignore
from book.integration.carton.mappings.tag_layouts import annotate_metadata  # type: ignore


DIGESTS_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json"
OUT_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json"


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing required input: {path}")
    return json.loads(path.read_text())


def canonical_sources(digests: Dict[str, Any]) -> List[Tuple[str, Path]]:
    profiles = digests.get("profiles") or {}
    out: List[Tuple[str, Path]] = []
    for pid, rec in sorted(profiles.items()):
        src = (rec or {}).get("source")
        if not src:
            continue
        path = REPO_ROOT / src
        out.append((pid, path))
    if not out:
        raise RuntimeError("no canonical profile sources found in digests.json")
    return out


def collect_tags_and_stride(paths: Iterable[Tuple[str, Path]]) -> Tuple[Set[int], Set[int]]:
    tags: Set[int] = set()
    strides: Set[int] = set()
    for pid, path in paths:
        if not path.exists():
            raise FileNotFoundError(f"missing canonical blob for {pid}: {path}")
        prof = decoder.decode_profile_dict(path.read_bytes())
        tag_counts = prof.get("tag_counts") or {}
        for k in tag_counts.keys():
            try:
                tags.add(int(k))
            except Exception:
                continue
        stride = (prof.get("validation") or {}).get("node_stride_bytes")
        if isinstance(stride, int):
            strides.add(stride)
    return tags, strides


def main() -> None:
    digests = load_json(DIGESTS_PATH)
    sources = canonical_sources(digests)
    tags, strides = collect_tags_and_stride(sources)
    if not tags:
        raise RuntimeError("no tags observed in canonical corpus")

    # Canonical corpus should agree on framing; if not, refuse to guess.
    stride = None
    if len(strides) == 1:
        stride = next(iter(strides))
    if stride is None:
        raise RuntimeError(f"canonical corpus did not agree on a single node stride: {sorted(strides)}")

    tag_rows: List[Dict[str, Any]] = []
    for tag in sorted(tags):
        tag_rows.append(
            {
                "tag": tag,
                "record_size_bytes": stride,
                "edge_fields": [0, 1],
                "payload_fields": [2],
            }
        )

    payload: Dict[str, Any] = {
        "notes": "Canonical tag layouts for this world baseline: nodes are parsed as fixed-size records, with two edge fields (u16[0..1]) and a payload slot (u16[2]) used as the project’s `field2` surface.",
        "tags": tag_rows,
    }

    # Preserve existing metadata fields until annotate_metadata refreshes them.
    if OUT_PATH.exists():
        try:
            payload["metadata"] = (json.loads(OUT_PATH.read_text()) or {}).get("metadata") or {}
        except Exception:
            payload["metadata"] = {}

    OUT_PATH.write_text(json.dumps(payload, indent=2))
    annotate_metadata.main()
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
