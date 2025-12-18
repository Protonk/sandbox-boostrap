#!/usr/bin/env python3
"""
Shim to the canonical compiler in book/api/profile_tools.
"""

import sys

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile_tools import compile_sbpl_file, hex_preview  # noqa: E402
from book.graph.concepts.validation import profile_ingestion as ingestion  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    src = Path(__file__).parent / "sample.sb"
    out = Path(__file__).parent / "build" / "sample.sb.bin"
    res = compile_sbpl_file(src, out)

    print(f"[+] compiled {src} -> {out}")
    print(f"    profile_type={res.profile_type} length={res.length}")
    print(f"    preview: {hex_preview(res.blob)}")

    blob_wrapper = ingestion.ProfileBlob(bytes=res.blob, source="examples-sb")
    header = ingestion.parse_header(blob_wrapper)
    sections = ingestion.slice_sections(blob_wrapper, header)
    print(
        "    header: format={fmt} ops={ops} nodes={nodes} "
        "op_table_bytes={ot} node_bytes={nn} regex_literal_bytes={rl}".format(
            fmt=header.format_variant,
            ops=header.operation_count,
            nodes=header.node_count,
            ot=len(sections.op_table),
            nn=len(sections.nodes),
            rl=len(sections.regex_literals),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
