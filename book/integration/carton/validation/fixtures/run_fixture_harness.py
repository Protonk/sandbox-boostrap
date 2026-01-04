#!/usr/bin/env python3
"""
Skeleton harness for exercising the decoder against curated fixtures.

Fixture data lives under `book/evidence/syncretic/validation/fixtures/`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from book.api.path_utils import find_repo_root
from book.api.profile import decoder

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES_DIR = ROOT / "book" / "evidence" / "syncretic" / "validation" / "fixtures"


def main() -> None:
    fixtures = json.loads((FIXTURES_DIR / "fixtures.json").read_text())
    for entry in fixtures.get("blobs", []):
        path = ROOT / entry["path"]
        if not path.exists():
            print(f"[!] missing fixture: {path}")
            continue
        data = path.read_bytes()
        if len(data) != entry["size"]:
            print(f"[!] size mismatch for {path} (expected {entry['size']}, got {len(data)})")
        decoded = decoder.decode_profile_dict(data)
        print(
            f"[+] decoded {path.name}: op_count={decoded.get('op_count')} "
            f"op_table_entries={len(decoded.get('op_table', []))} "
            f"nodes_bytes={decoded['sections'].get('nodes')} "
            f"literal_bytes={decoded['sections'].get('literal_pool')}"
        )


if __name__ == "__main__":
    main()

