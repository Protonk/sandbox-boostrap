#!/usr/bin/env python3
"""
Thin wrapper to run runtime probes using book.api.golden_runner.
Defaults to writing artifacts into book/profiles/golden-triple/.
"""

from __future__ import annotations

from pathlib import Path

from book.api.golden_runner import run_expected_matrix, DEFAULT_OUT


def main() -> int:
    matrix_path = DEFAULT_OUT / "expected_matrix.json"
    out_path = run_expected_matrix(matrix_path, out_dir=DEFAULT_OUT)
    print(f"[+] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
