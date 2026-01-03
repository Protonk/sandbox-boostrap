#!/usr/bin/env python3
"""Refresh CARTON bundle via the fixer pipeline."""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import List, Optional

from book.integration.carton import bundle
from book.integration.carton import paths
from book.integration.carton.fixers import registry
from book.integration.carton.tools import check as check_mod

DEFAULT_PROMOTION_GENERATORS = "runtime,system-profiles"


def _parse_ids(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _run(cmd: List[str], *, repo_root, label: str) -> None:
    print(f"[carton] {label}: {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=repo_root)


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Refresh CARTON bundle")
    parser.add_argument(
        "--promotion-generators",
        default=DEFAULT_PROMOTION_GENERATORS,
        help=(
            "comma-separated generators for run_promotion.py "
            f"(default: {DEFAULT_PROMOTION_GENERATORS})"
        ),
    )
    parser.add_argument(
        "--skip-promotion",
        action="store_true",
        help="skip graph mapping promotion",
    )
    parser.add_argument(
        "--fixers",
        help="comma-separated fixer ids to run (default: all)",
    )
    parser.add_argument(
        "--skip-check",
        action="store_true",
        help="skip CARTON check at the end",
    )
    args = parser.parse_args(argv)

    repo_root = paths.repo_root()

    if not args.skip_promotion:
        _run(
            [
                sys.executable,
                "-m",
                "book.integration.carton.mappings.run_promotion",
                "--generators",
                args.promotion_generators,
            ],
            repo_root=repo_root,
            label="run promotion",
        )

    fixer_ids = _parse_ids(args.fixers)
    registry.run_fixers(ids=fixer_ids if fixer_ids else None, repo_root=repo_root)

    spec_path = paths.ensure_absolute(paths.CARTON_SPEC, repo_root_path=repo_root)
    manifest_path = paths.ensure_absolute(paths.MANIFEST_PATH, repo_root_path=repo_root)
    bundle.build_manifest(
        spec_path=spec_path,
        out_path=manifest_path,
        repo_root=repo_root,
        refresh_contracts=True,
    )

    if not args.skip_check:
        errors = check_mod.run_check(
            spec_path=spec_path,
            manifest_path=manifest_path,
            repo_root=repo_root,
        )
        if errors:
            print("CARTON check failed:")
            for err in errors:
                print(f"- {err}")
            raise SystemExit(1)
        print("CARTON check OK")


if __name__ == "__main__":
    main()
