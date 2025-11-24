#!/usr/bin/env python3
"""
Smoke test for Axis 4.1 Profile Ingestion.

Runs both supported formats:
- modern graph-based blob via examples/sb
- synthetic legacy decision-tree blob (sbdis format)
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
EXAMPLE_ROOT = REPO_ROOT / "examples" / "sb"
BLOB_PATH = EXAMPLE_ROOT / "build" / "sample.sb.bin"
LEGACY_BLOB_PATH = REPO_ROOT / "concepts" / "cross" / "profile-ingestion" / "smoke" / "legacy_test.sb.bin"

if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from concepts.cross import profile_ingestion as ingestion  # noqa: E402


def main() -> None:
    # Modern graph-based format
    subprocess.run(["bash", str(EXAMPLE_ROOT / "run-demo.sh")], check=True, cwd=REPO_ROOT)
    blob = ingestion.ProfileBlob.from_path(BLOB_PATH, source="examples-sb")
    header = ingestion.parse_header(blob)
    sections = ingestion.slice_sections(blob, header)
    print(
        f"[ingestion/modern] format={header.format_variant} ops={header.operation_count} "
        f"nodes={header.node_count} op_table_bytes={len(sections.op_table)} "
        f"node_bytes={len(sections.nodes)} regex_literal_bytes={len(sections.regex_literals)}"
    )

    # Legacy decision-tree format (synthetic minimal blob sufficient for parsing)
    legacy_bytes = bytearray()
    re_table_offset_words = 2  # regex table starts at byte 16
    re_table_count = 0
    legacy_bytes += struct.pack("<HH", re_table_offset_words, re_table_count)
    op_count = ((re_table_offset_words * 8) - 4) // 2
    legacy_bytes += struct.pack(f"<{op_count}H", *([re_table_offset_words] * op_count))
    # place a single terminal node at offset word=2 (byte 16)
    legacy_bytes += b"\x01\x00\x00" + b"\x00" * 5
    LEGACY_BLOB_PATH.write_bytes(legacy_bytes)

    legacy_blob = ingestion.ProfileBlob.from_path(LEGACY_BLOB_PATH, source="legacy-synthetic")
    legacy_header = ingestion.parse_header(legacy_blob)
    legacy_sections = ingestion.slice_sections(legacy_blob, legacy_header)
    print(
        f"[ingestion/legacy] format={legacy_header.format_variant} ops={legacy_header.operation_count} "
        f"nodes={legacy_header.node_count} op_table_bytes={len(legacy_sections.op_table)} "
        f"node_bytes={len(legacy_sections.nodes)} regex_literal_bytes={len(legacy_sections.regex_literals)}"
    )


if __name__ == "__main__":
    main()
