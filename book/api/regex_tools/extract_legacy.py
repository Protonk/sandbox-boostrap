#!/usr/bin/env python3
"""
Extract compiled AppleMatch regex blobs from legacy (decision-tree) sandbox profiles.

Inputs: legacy .sb.bin profiles with `re_table_offset` (8-byte words) and `re_table_count`
as described in substrate/Appendix.md (“Binary Profile Formats and Policy Graphs”).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def extract_regexes(profile_path: Path, out_dir: Path) -> None:
    data = profile_path.read_bytes()
    if len(data) < 4:
        raise SystemExit("file too small to contain regex table header")

    re_table_offset_words, re_count = struct.unpack_from("<HH", data, 0)
    re_table_offset = re_table_offset_words * 8
    if re_table_offset >= len(data):
        raise SystemExit("re_table_offset outside file; unsupported format?")

    re_offsets = []
    for i in range(re_count):
        off_words = struct.unpack_from("<H", data, re_table_offset + i * 2)[0]
        re_offsets.append(off_words * 8)

    out_dir.mkdir(parents=True, exist_ok=True)
    for idx, offset in enumerate(re_offsets):
        if offset + 4 > len(data):
            print(f"[skip] regex {idx}: offset outside file")
            continue
        length = struct.unpack_from("<I", data, offset)[0]
        start = offset + 4
        end = start + length
        if end > len(data):
            print(f"[skip] regex {idx}: length outside file")
            continue
        blob = data[start:end]
        out_path = out_dir / f"{profile_path.name}.{idx:03d}.re"
        out_path.write_bytes(blob)
        print(f"[+] wrote {out_path} ({len(blob)} bytes)")


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if len(args) != 2:
        print("usage:")
        print("  extract_legacy.py profile.sb.bin output_dir")
        return 64
    profile = Path(args[0])
    out_dir = Path(args[1])
    extract_regexes(profile, out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
