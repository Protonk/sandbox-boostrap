#!/usr/bin/env python3
"""
CLI wrapper around the heuristic decoder.
Usage: python -m book.graph.concepts.validation.decode_blob <blob> [<blob>...]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Ensure repo root on sys.path for `book.*` imports.
ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile_tools import decoder


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("blobs", nargs="+", help="Paths to compiled sandbox blobs")
    args = ap.parse_args()
    records = []
    for p in args.blobs:
        path = Path(p)
        if not path.exists():
            raise SystemExit(f"missing blob: {path}")
        data = path.read_bytes()
        rec = decoder.decode_profile_dict(data)
        rec["source"] = str(path)
        records.append(rec)
    json.dump(records if len(records) > 1 else records[0], sys.stdout, indent=2)


if __name__ == "__main__":
    main()
