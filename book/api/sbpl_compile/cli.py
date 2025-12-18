#!/usr/bin/env python3
"""
CLI wrapper for book.api.sbpl_compile.

Usage:
  python -m book.api.sbpl_compile.cli path1.sb [path2.sb ...] [--out OUT] [--out-dir DIR] [--no-preview]

Preferred entrypoint:
  python -m book.api.profile_tools compile path1.sb [path2.sb ...] [--out OUT] [--out-dir DIR] [--no-preview]

Defaults:
- OUT (single input): <input>.sb.bin next to the source.
- OUT-DIR (multiple inputs): writes <stem>.sb.bin under DIR.

Host assumptions: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; libsandbox.dylib present.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from book.api.profile_tools import cli as profile_cli


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compile SBPL to binary blobs using libsandbox (Sonoma baseline).")
    ap.add_argument("paths", nargs="+", type=Path, help="SBPL files to compile")
    ap.add_argument("--out", type=Path, help="Output path (only valid for a single input)")
    ap.add_argument("--out-dir", type=Path, help="Directory for outputs when compiling multiple files")
    ap.add_argument("--no-preview", action="store_true", help="Suppress hex preview")
    args = ap.parse_args(argv)

    return profile_cli.compile_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
