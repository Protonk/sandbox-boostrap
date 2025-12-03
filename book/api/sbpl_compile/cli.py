#!/usr/bin/env python3
"""
CLI wrapper for book.api.sbpl_compile.

Usage:
  python -m book.api.sbpl_compile.cli path1.sb [path2.sb ...] [--out OUT] [--out-dir DIR] [--no-preview]

Defaults:
- OUT (single input): <input>.sb.bin next to the source.
- OUT-DIR (multiple inputs): writes <stem>.sb.bin under DIR.

Host assumptions: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; libsandbox.dylib present.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

from . import CompileResult, compile_sbpl_file, hex_preview


def _choose_out(src: Path, out: Path | None, out_dir: Path | None) -> Path:
    if out:
        return out
    if out_dir:
        return out_dir / f"{src.stem}.sb.bin"
    if src.suffix == ".sb":
        return src.with_suffix(".sb.bin")
    return src.with_name(f"{src.name}.sb.bin")


def compile_many(paths: Iterable[Path], out: Path | None = None, out_dir: Path | None = None, preview: bool = True) -> list[tuple[Path, CompileResult]]:
    results: list[tuple[Path, CompileResult]] = []
    for src in paths:
        target = _choose_out(src, out, out_dir)
        res = compile_sbpl_file(src, target)
        results.append((target, res))
        if preview:
            print(f"[+] {src} -> {target} (len={res.length}, type={res.profile_type}) preview: {hex_preview(res.blob)}")
        else:
            print(f"[+] {src} -> {target} (len={res.length}, type={res.profile_type})")
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compile SBPL to binary blobs using libsandbox (Sonoma baseline).")
    ap.add_argument("paths", nargs="+", type=Path, help="SBPL files to compile")
    ap.add_argument("--out", type=Path, help="Output path (only valid for a single input)")
    ap.add_argument("--out-dir", type=Path, help="Directory for outputs when compiling multiple files")
    ap.add_argument("--no-preview", action="store_true", help="Suppress hex preview")
    args = ap.parse_args(argv)

    if args.out and len(args.paths) != 1:
        ap.error("--out is only valid with a single input")
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    compile_many(args.paths, out=args.out, out_dir=args.out_dir, preview=not args.no_preview)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
