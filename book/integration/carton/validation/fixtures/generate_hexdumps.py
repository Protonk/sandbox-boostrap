#!/usr/bin/env python3
"""
Emit small hexdump snapshots for curated blobs to aid decoder authors.
Reads fixtures.json and writes per-blob dumps under fixtures/hexdumps/.

Fixture data lives under `book/evidence/graph/concepts/validation/fixtures/`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from book.api.path_utils import find_repo_root

ROOT = find_repo_root(Path(__file__))
FIXTURES_DIR = ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "fixtures"


def hexdump_region(data: bytes, start: int, length: int) -> str:
    lines = []
    end = min(len(data), start + length)
    for off in range(start, end, 16):
        chunk = data[off : off + 16]
        hexbytes = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{off:08x}: {hexbytes}")
    return "\n".join(lines)


def dump_blob(blob_path: Path, out_dir: Path) -> None:
    data = blob_path.read_bytes()
    prefix = hexdump_region(data, 0, 64)
    suffix = hexdump_region(data, max(0, len(data) - 64), 64)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{blob_path.name}.hexdump.txt"
    header = [
        f"# {blob_path.name}",
        f"# size={len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}",
        "# first 64 bytes:",
        prefix,
        "# last 64 bytes:",
        suffix,
        "",
    ]
    out.write_text("\n".join(header))
    print(f"[+] wrote {out}")


def main() -> None:
    fixtures = json.loads((FIXTURES_DIR / "fixtures.json").read_text())
    out_dir = FIXTURES_DIR / "hexdumps"
    for entry in fixtures.get("blobs", []):
        path = ROOT / entry["path"]
        if not path.exists():
            print(f"[!] missing {path}")
            continue
        dump_blob(path, out_dir)


if __name__ == "__main__":
    main()

