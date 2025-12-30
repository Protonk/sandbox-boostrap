#!/usr/bin/env python3
"""Front door for refreshing the CARTON contract bundle."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from book.api import path_utils

DEFAULT_GENERATORS = "runtime,system-profiles,carton-coverage,carton-indices"


def _repo_root() -> Path:
    return path_utils.find_repo_root(Path(__file__))


def _run(cmd, *, repo_root: Path, label: str) -> None:
    print(f"[carton] {label}: {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=repo_root)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Refresh CARTON bundle via integration-owned workflow")
    parser.add_argument(
        "--generators",
        default=DEFAULT_GENERATORS,
        help=(
            "comma-separated generators for run_promotion.py "
            f"(default: {DEFAULT_GENERATORS})"
        ),
    )
    parser.add_argument(
        "--skip-promotion",
        action="store_true",
        help="skip graph mapping promotion (assumes mappings already up to date)",
    )
    parser.add_argument(
        "--skip-check",
        action="store_true",
        help="skip CARTON check at the end",
    )
    args = parser.parse_args(argv)

    repo_root = _repo_root()

    if not args.skip_promotion:
        _run(
            [
                sys.executable,
                "-m",
                "book.graph.mappings.run_promotion",
                "--generators",
                args.generators,
            ],
            repo_root=repo_root,
            label="run promotion",
        )

    _run(
        [
            sys.executable,
            "-m",
            "book.integration.carton.build_manifest",
            "--refresh-contracts",
            "--skip-manifest",
        ],
        repo_root=repo_root,
        label="refresh contracts",
    )
    _run(
        [sys.executable, "-m", "book.integration.carton.build_manifest"],
        repo_root=repo_root,
        label="build manifest",
    )

    if not args.skip_check:
        _run(
            [sys.executable, "-m", "book.integration.carton.check"],
            repo_root=repo_root,
            label="check",
        )


if __name__ == "__main__":
    main()
