#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from . import run_expected_matrix, DEFAULT_OUT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run golden triple runtime probes (provisional schema).")
    ap.add_argument(
        "--matrix",
        type=Path,
        default=DEFAULT_OUT / "expected_matrix.json",
        help="Path to expected_matrix.json (default: book/profiles/golden-triple/expected_matrix.json)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output directory (default: book/profiles/golden-triple/)",
    )
    args = ap.parse_args(argv)
    out_path = run_expected_matrix(args.matrix, out_dir=args.out)
    print(f"[+] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
