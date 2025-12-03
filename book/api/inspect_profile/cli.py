#!/usr/bin/env python3
"""
CLI for inspecting compiled sandbox profiles on the Sonoma baseline.

Usage:
  python -m book.api.inspect_profile.cli <path> [--compile] [--json OUT] [--stride 8 12 16]

<path> can be a compiled blob (.sb.bin) or SBPL (.sb) when --compile is set.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from book.api import sbpl_compile
from . import summarize_blob


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Inspect a compiled sandbox profile blob.")
    ap.add_argument("path", type=Path, help="Compiled blob (.sb.bin) or SBPL (.sb with --compile).")
    ap.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap.add_argument("--json", type=Path, help="Write summary JSON to this path instead of stdout.")
    ap.add_argument("--stride", type=int, nargs="*", default=[8, 12, 16], help="Stride guesses for node stats.")
    args = ap.parse_args(argv)

    blob_path = args.path
    tmp = None
    if args.compile:
        tmp = tempfile.NamedTemporaryFile(prefix="inspect_profile_", suffix=".sb.bin", delete=False)
        res = sbpl_compile.compile_sbpl_file(blob_path, Path(tmp.name))
        blob_path = Path(tmp.name)
        print(f"[+] compiled {args.path} -> {blob_path} (len={res.length}, type={res.profile_type})")

    summary = summarize_blob(blob_path.read_bytes(), strides=args.stride)
    payload = summary.__dict__
    output = json.dumps(payload, indent=2)
    if args.json:
        args.json.write_text(output)
        print(f"[+] wrote {args.json}")
    else:
        print(output)
    if tmp:
        tmp.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
