#!/usr/bin/env python3
"""
HISTORICAL EXAMPLE (legacy decision-tree profiles)

Extract compiled AppleMatch regex blobs from legacy decision-tree sandbox profiles.

This is a helper for historical inspection of legacy-format blobs. It is not a modern graph-based profile extractor
for this host baseline.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable


def _read_u16_le(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 2], "little")


def _write_blob(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def extract_regexes(profile: Path, out_dir: Path) -> Iterable[Path]:
    data = profile.read_bytes()
    re_table_offset_words = _read_u16_le(data, 0)
    re_count = _read_u16_le(data, 2)
    table_offset = re_table_offset_words * 8
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for idx in range(re_count):
        entry_off = table_offset + idx * 2
        re_offset_words = _read_u16_le(data, entry_off)
        re_offset = re_offset_words * 8
        if re_offset + 4 > len(data):
            continue
        re_len = int.from_bytes(data[re_offset : re_offset + 4], "little")
        blob = data[re_offset + 4 : re_offset + 4 + re_len]
        out_path = out_dir / f"{profile.name}.{idx:03d}.re"
        _write_blob(out_path, blob)
        outputs.append(out_path)
    return outputs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract AppleMatch regex blobs from legacy profiles.")
    ap.add_argument("profile", type=Path, help="Legacy SB binary profile")
    ap.add_argument("out_dir", type=Path, help="Output directory for .re files")
    args = ap.parse_args(argv)
    outputs = extract_regexes(args.profile, args.out_dir)
    if not outputs:
        print("no regexes found")
    else:
        for path in outputs:
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
