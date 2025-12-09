#!/usr/bin/env python3
"""
Thin wrapper to run runtime probes using book.api.golden_runner.
Defaults to writing artifacts into book/profiles/golden-triple/.
"""

from __future__ import annotations

from pathlib import Path

from book.api.runtime_harness.runner import run_expected_matrix


ROOT = Path(__file__).resolve().parent
MATRIX = ROOT / "out" / "expected_matrix.json"
OUT_DIR = ROOT / "out"
RUNTIME_PROFILES = OUT_DIR / "runtime_profiles"
KEY_SPECIFIC_RULES = {
    # /tmp resolves to /private/tmp on this host; add an alias so bucket-5 reads succeed.
    "bucket5:v11_read_subpath": ['(allow file-read* (subpath "/private/tmp/foo"))'],
    # Ensure metafilter_any denies match the /private/tmp symlink target for baz.
    "runtime:metafilter_any": [
        '(deny file-read* (literal "/private/tmp/baz.txt"))',
        '(deny file-write* (literal "/private/tmp/baz.txt"))',
    ],
}


def main() -> int:
    out_path = run_expected_matrix(
        MATRIX,
        out_dir=OUT_DIR,
        runtime_profile_dir=RUNTIME_PROFILES,
        key_specific_rules=KEY_SPECIFIC_RULES,
    )
    print(f"[+] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
