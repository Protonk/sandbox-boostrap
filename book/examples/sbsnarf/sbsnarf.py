#!/usr/bin/env python3
"""
Shim to the canonical compiler in book/api/profile_tools.

Usage remains:
  sbsnarf.py input.sb output.sb.bin
"""

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile_tools import compile_sbpl_file, hex_preview  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if len(args) != 2:
        print("usage: sbsnarf.py input.sb output.sb.bin")
        return 64

    src = Path(args[0])
    dst = Path(args[1])
    res = compile_sbpl_file(src, dst)
    print(f"[+] compiled {src} -> {dst} (len={res.length}, type={res.profile_type}) preview: {hex_preview(res.blob)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
