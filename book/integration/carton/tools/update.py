#!/usr/bin/env python3
"""Refresh CARTON bundle via the registry-driven pipeline."""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import List, Optional


DEFAULT_PROMOTION_GENERATORS = "runtime,system-profiles"


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

    cmd = [sys.executable, "-m", "book.integration.carton", "build"]
    if not args.skip_promotion:
        cmd.append("--promote")
    if args.fixers:
        job_ids = ["specs.write", "contracts.manifest"]
        job_ids.extend([item.strip() for item in args.fixers.split(",") if item.strip()])
        cmd.extend(["--jobs", ",".join(job_ids)])
    if args.skip_check:
        cmd.append("--skip-check")
    print(f"[carton] update: {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd)


if __name__ == "__main__":
    main()
