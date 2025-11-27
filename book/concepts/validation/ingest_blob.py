#!/usr/bin/env python3
"""
Ingest one or more compiled sandbox blobs and emit JSON summaries.
Outputs go to stdout; callers can redirect to validation/out/static/.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Ensure repo root on sys.path for namespace imports.
REPO_ROOT = Path(__file__).resolve().parents[3]
import sys

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.concepts.validation import profile_ingestion as ingestion


def ingest_one(path: Path):
    blob = ingestion.ProfileBlob(bytes=path.read_bytes(), source=path.name)
    header = ingestion.parse_header(blob)
    sections = ingestion.slice_sections(blob, header)
    return {
        "source": blob.source,
        "length": header.raw_length,
        "format_variant": header.format_variant,
        "operation_count": header.operation_count,
        "node_count": header.node_count,
        "regex_count": header.regex_count,
        "section_lengths": {
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "regex_literals": len(sections.regex_literals),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blobs", nargs="+", help="Paths to .sb.bin or similar compiled profiles")
    args = ap.parse_args()
    records = [ingest_one(Path(p)) for p in args.blobs]
    json.dump(records if len(records) > 1 else records[0], fp=sys.stdout, indent=2)


if __name__ == "__main__":
    import sys

    main()
