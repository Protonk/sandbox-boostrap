#!/usr/bin/env python3
"""
Skeleton harness for exercising a future decoder against curated fixtures.
Populate `decode_blob` with real parsing logic and add assertions as needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

# Ensure repo root on path for `book.*` imports.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Best-effort decoder; returns structural fields without guessing semantics.
from book.api.profile import decoder


def main() -> None:
    fixtures = json.loads((HERE / "fixtures.json").read_text())
    for entry in fixtures.get("blobs", []):
        path = ROOT / entry["path"]
        if not path.exists():
            print(f"[!] missing fixture: {path}")
            continue
        data = path.read_bytes()
        # Basic sanity before decoding.
        if len(data) != entry["size"]:
            print(f"[!] size mismatch for {path} (expected {entry['size']}, got {len(data)})")
        decoded = decoder.decode_profile_dict(data)
        # TODO: add structural assertions (invariants) here as decoder matures.
        print(
            f"[+] decoded {path.name}: op_count={decoded.get('op_count')} "
            f"op_table_entries={len(decoded.get('op_table', []))} "
            f"nodes_bytes={decoded['sections'].get('nodes')} "
            f"literal_bytes={decoded['sections'].get('literal_pool')}"
        )


if __name__ == "__main__":
    main()
