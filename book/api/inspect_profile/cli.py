#!/usr/bin/env python3
"""
CLI for inspecting compiled sandbox profiles on the Sonoma baseline.

Usage:
  python -m book.api.inspect_profile.cli <path> [--compile] [--json OUT] [--stride 8 12 16]

<path> can be a compiled blob (.sb.bin) or SBPL (.sb) when --compile is set.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from book.api.profile_tools import cli as profile_cli


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Inspect a compiled sandbox profile blob.")
    ap.add_argument("path", type=Path, help="Compiled blob (.sb.bin) or SBPL (.sb with --compile).")
    ap.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap.add_argument("--json", type=Path, help="Write summary JSON to this path instead of stdout.")
    ap.add_argument("--stride", type=int, nargs="*", default=[8, 12, 16], help="Stride guesses for node stats.")
    args = ap.parse_args(argv)

    return profile_cli.inspect_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
