#!/usr/bin/env python3
"""
Extract compiled regex blobs from a sandbox profile.

Supports the early decision-tree format (Blazakis-era) where the header stores
`re_table_offset` (in 8-byte words) and `re_table_count`. Modern bundled/graph
formats require additional parsing and are not handled here.
"""

import struct
import sys
from pathlib import Path


def extract_regexes(profile_path: Path, out_dir: Path):
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


def main():
    if len(sys.argv) != 3:
        print("usage:")
        print("  resnarf.py profile.sb.bin output_dir")
        print()
        print("Extracts regex blobs from early-format sandbox profiles (Appendix.md:")
        print('"Binary Profile Formats and Policy Graphs" §3).')
        sys.exit(1)

    profile = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    extract_regexes(profile, out_dir)


if __name__ == "__main__":
    main()
