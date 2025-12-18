#!/usr/bin/env python3
"""
Shim to the canonical compiler in book/api/profile_tools.
"""

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile_tools import compile_sbpl_file, hex_preview  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    default_profiles = ["airlock.sb", "bsd.sb"]
    parser = argparse.ArgumentParser(
        description="Compile SBPL profiles to binary blobs using libsandbox (Sonoma baseline)."
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=Path("/System/Library/Sandbox/Profiles"),
        help="Directory containing .sb files (default: system profiles).",
    )
    parser.add_argument(
        "--names",
        nargs="+",
        default=default_profiles,
        help="Profile filenames to compile (default: %(default)s).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("build/profiles"),
        help="Where to write .sb.bin outputs (created if missing).",
    )
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    for name in args.names:
        sb_path = args.profiles_dir / name
        if not sb_path.exists():
            print(f"[skip] {sb_path} (not found)")
            continue

        out_path = args.out_dir / f"{name}.bin"
        res = compile_sbpl_file(sb_path, out_path)
        print(f"[+] compiled {sb_path}")
        print(f"    wrote {out_path} ({res.length} bytes)")
        print(f"    preview: {hex_preview(res.blob)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
