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


def _platform_policy_command(args: argparse.Namespace) -> int:
    repo_root = find_repo_root()
    out_path = args.out or repo_root / runner.DEFAULT_PLATFORM_OUT
    runner.capture_platform_policy(out_path, repo_root=repo_root, build=not args.no_build)
    return 0


def _containers_command(args: argparse.Namespace) -> int:
    repo_root = find_repo_root()
    out_path = args.out or repo_root / runner.DEFAULT_CONTAINERS_OUT
    runner.capture_containers(out_path, repo_root=repo_root, build=not args.no_build)
    return 0


def _apply_attempt_command(args: argparse.Namespace) -> int:
    repo_root = find_repo_root()
    out_path = args.out or repo_root / runner.DEFAULT_APPLY_ATTEMPT_OUT
    runner.capture_apply_attempt(out_path, repo_root=repo_root, sbpl_file=args.sbpl_file, preflight_mode=args.preflight)
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

    p_plat = sub.add_parser("platform-policy", help="Run platform-policy-checks and write platform.jsonl.")
    p_plat.add_argument("--out", type=Path, help="Output JSONL path (default: validation/out/lifecycle/platform.jsonl)")
    p_plat.add_argument("--no-build", action="store_true", help="Skip clang build step and run existing binary.")
    p_plat.set_defaults(func=_platform_policy_command)

    p_cont = sub.add_parser("containers", help="Run containers-and-redirects and write containers.json.")
    p_cont.add_argument("--out", type=Path, help="Output JSON path (default: validation/out/lifecycle/containers.json)")
    p_cont.add_argument("--no-build", action="store_true", help="Skip swiftc build step and run existing binary.")
    p_cont.set_defaults(func=_containers_command)

    p_apply = sub.add_parser("apply-attempt", help="Run apply-attempt and write apply_attempt.json.")
    p_apply.add_argument("--out", type=Path, help="Output JSON path (default: validation/out/lifecycle/apply_attempt.json)")
    p_apply.add_argument("--sbpl-file", type=Path, help="Override SBPL source from a file (repo-relative preferred).")
    p_apply.add_argument(
        "--preflight",
        choices=["enforce", "off", "force"],
        default="enforce",
        help="Wrapper preflight policy (default: enforce).",
    )
    p_apply.set_defaults(func=_apply_attempt_command)

    p_all = sub.add_parser("write-validation-out", help="Write the default lifecycle outputs under validation/out/lifecycle/.")
    p_all.set_defaults(func=_write_validation_out_command)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
