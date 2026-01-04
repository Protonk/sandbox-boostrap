#!/usr/bin/env python3
"""
Regenerate the canonical node-region remainder contract for this host baseline.

This tool replaces the experiment-local generator.

Output:
- book/evidence/syncretic/validation/out/static/node_remainders.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore
from book.api.profile import ingestion as pi  # type: ignore


_CANONICAL = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
CANONICAL: Dict[str, Path] = {
    "sys:airlock": _CANONICAL["airlock"],
    "sys:bsd": _CANONICAL["bsd"],
    "sys:sample": _CANONICAL["sample"],
}

OUT_PATH = REPO_ROOT / "book/evidence/syncretic/validation/out/static/node_remainders.json"
BASELINE_PATH = REPO_ROOT / "book/world/sonoma-14.4.1-23E224-arm64/world.json"


def compute(path: Path, record_size_bytes: int) -> dict:
    blob = path.read_bytes()
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=to_repo_relative(path, REPO_ROOT)))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=to_repo_relative(path, REPO_ROOT)), header)
    nodes = sections.nodes
    canonical_len = (len(nodes) // record_size_bytes) * record_size_bytes
    remainder = nodes[canonical_len:]
    return {
        "source": to_repo_relative(path, REPO_ROOT),
        "record_size_bytes": record_size_bytes,
        "nodes_length": len(nodes),
        "canonical_nodes_length": canonical_len,
        "remainder_hex": remainder.hex(),
    }


def main() -> None:
    world_id = json.loads(BASELINE_PATH.read_text()).get("world_id")
    if not world_id:
        raise RuntimeError(f"missing world_id in {to_repo_relative(BASELINE_PATH, REPO_ROOT)}")

    record_size_bytes = 8
    profiles = {name: compute(path, record_size_bytes) for name, path in CANONICAL.items()}
    payload = {
        "metadata": {
            "world_id": world_id,
            "status": "ok",
            "notes": "Node-region length and remainder bytes for canonical profiles using modern-heuristic slicing (record_size_bytes=8).",
        },
        "profiles": profiles,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {to_repo_relative(OUT_PATH, REPO_ROOT)}")


if __name__ == "__main__":
    main()
