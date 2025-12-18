#!/usr/bin/env python3
"""
CLI for lifecycle probes (entitlements + extensions) on the Sonoma baseline.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from book.api.path_utils import find_repo_root

from . import runner


def _entitlements_command(args: argparse.Namespace) -> int:
    repo_root = find_repo_root()
    out_path = args.out or repo_root / runner.DEFAULT_ENTITLEMENTS_OUT
    runner.capture_entitlements_evolution(out_path, repo_root=repo_root, build=not args.no_build)
    return 0


def _extensions_command(args: argparse.Namespace) -> int:
    repo_root = find_repo_root()
    out_path = args.out or repo_root / runner.DEFAULT_EXTENSIONS_OUT
    runner.capture_extensions_dynamic(out_path, repo_root=repo_root, build=not args.no_build)
    return 0


def _write_validation_out_command(_args: argparse.Namespace) -> int:
    repo_root = find_repo_root()
    runner.write_validation_out(repo_root=repo_root)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lifecycle probes (validation IR writers) for the Sonoma Seatbelt baseline.")
    sub = ap.add_subparsers(dest="command", required=True)

    p_ent = sub.add_parser("entitlements", help="Run entitlements-evolution and write entitlements.json.")
    p_ent.add_argument("--out", type=Path, help="Output JSON path (default: validation/out/lifecycle/entitlements.json)")
    p_ent.add_argument("--no-build", action="store_true", help="Skip clang build step and run existing binary.")
    p_ent.set_defaults(func=_entitlements_command)

    p_ext = sub.add_parser("extensions", help="Run extensions-dynamic and write extensions_dynamic.md.")
    p_ext.add_argument("--out", type=Path, help="Output Markdown path (default: validation/out/lifecycle/extensions_dynamic.md)")
    p_ext.add_argument("--no-build", action="store_true", help="Skip clang build step and run existing binary.")
    p_ext.set_defaults(func=_extensions_command)

    p_all = sub.add_parser("write-validation-out", help="Write both default lifecycle outputs under validation/out/lifecycle/.")
    p_all.set_defaults(func=_write_validation_out_command)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

