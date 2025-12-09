#!/usr/bin/env python3
"""
CLI for op-table centric summaries on the Sonoma baseline.

Usage:
  python -m book.api.op_table.cli <path> [--compile] [--name NAME] [--op-count N]
                                   [--vocab book/graph/mappings/vocab/ops.json]
                                   [--filters book/graph/mappings/vocab/filters.json]
                                   [--json OUT]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from book.api.profile_tools import cli as profile_cli


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Summarize op-table structure for a profile.")
    ap.add_argument("path", type=Path, help="SBPL (.sb) or compiled blob (.sb.bin)")
    ap.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap.add_argument("--name", type=str, help="Name to use in output (default: stem).")
    ap.add_argument("--op-count", type=int, help="Override op_count from header.")
    ap.add_argument("--vocab", type=Path, help="Path to ops.json for alignment.")
    ap.add_argument("--filters", type=Path, help="Path to filters.json for alignment.")
    ap.add_argument("--json", type=Path, help="Write summary JSON to this path (default stdout).")
    args = ap.parse_args(argv)

    return profile_cli.op_table_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
