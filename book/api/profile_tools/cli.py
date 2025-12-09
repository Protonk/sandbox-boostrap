#!/usr/bin/env python3
"""
Unified CLI for profile tooling (compile, inspect, op-table).
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Iterable

from . import compile as compile_mod
from . import inspect as inspect_mod
from . import op_table as op_table_mod


def _choose_out(src: Path, out: Path | None, out_dir: Path | None) -> Path:
    if out:
        return out
    if out_dir:
        return out_dir / f"{src.stem}.sb.bin"
    if src.suffix == ".sb":
        return src.with_suffix(".sb.bin")
    return src.with_name(f"{src.name}.sb.bin")


def compile_many(paths: Iterable[Path], out: Path | None = None, out_dir: Path | None = None, preview: bool = True) -> list[tuple[Path, compile_mod.CompileResult]]:
    results: list[tuple[Path, compile_mod.CompileResult]] = []
    for src in paths:
        target = _choose_out(src, out, out_dir)
        res = compile_mod.compile_sbpl_file(src, target)
        results.append((target, res))
        if preview:
            print(f"[+] {src} -> {target} (len={res.length}, type={res.profile_type}) preview: {compile_mod.hex_preview(res.blob)}")
        else:
            print(f"[+] {src} -> {target} (len={res.length}, type={res.profile_type})")
    return results


def compile_command(args: argparse.Namespace) -> int:
    if args.out and len(args.paths) != 1:
        raise SystemExit("--out is only valid with a single input")
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    compile_many(args.paths, out=args.out, out_dir=args.out_dir, preview=not args.no_preview)
    return 0


def inspect_command(args: argparse.Namespace) -> int:
    blob_path = args.path
    tmp = None
    if args.compile:
        tmp = tempfile.NamedTemporaryFile(prefix="inspect_profile_", suffix=".sb.bin", delete=False)
        res = compile_mod.compile_sbpl_file(blob_path, Path(tmp.name))
        blob_path = Path(tmp.name)
        print(f"[+] compiled {args.path} -> {blob_path} (len={res.length}, type={res.profile_type})")

    summary = inspect_mod.summarize_blob(blob_path.read_bytes(), strides=args.stride)
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


def op_table_command(args: argparse.Namespace) -> int:
    blob_path = args.path
    tmp = None
    ops_list = []
    filters_list = []
    filter_vocab_names = set()
    if args.compile:
        tmp = tempfile.NamedTemporaryFile(prefix="op_table_", suffix=".sb.bin", delete=False)
        res = compile_mod.compile_sbpl_file(blob_path, Path(tmp.name))
        blob_path = Path(tmp.name)
        print(f"[+] compiled {args.path} -> {blob_path} (len={res.length}, type={res.profile_type})")
        ops_list = op_table_mod.parse_ops(args.path)
        if args.filters and args.filters.exists():
            fv = op_table_mod.load_vocab(args.filters)
            filter_vocab_names = {entry["name"] for entry in fv.get("filters", [])}
            filters_list = op_table_mod.parse_filters(args.path, filter_vocab_names)

    name = args.name or blob_path.stem
    filter_map = None
    if args.filters and args.filters.exists():
        fv = op_table_mod.load_vocab(args.filters)
        filter_map = {entry["name"]: entry["id"] for entry in fv.get("filters", [])}
    summary = op_table_mod.summarize_profile(
        name=name,
        blob=blob_path.read_bytes(),
        ops=ops_list,
        filters=filters_list,
        op_count_override=args.op_count,
        filter_map=filter_map,
    )
    payload = summary.__dict__

    if args.vocab and args.vocab.exists() and args.filters and args.filters.exists():
        ops_vocab = op_table_mod.load_vocab(args.vocab)
        filters_vocab = op_table_mod.load_vocab(args.filters)
        alignment = op_table_mod.build_alignment([summary], ops_vocab, filters_vocab)
        payload["alignment"] = alignment

    output = json.dumps(payload, indent=2)
    if args.json:
        args.json.write_text(output)
        print(f"[+] wrote {args.json}")
    else:
        print(output)
    if tmp:
        tmp.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Unified profile tooling (compile, inspect, op-table) for Sonoma Seatbelt.")
    sub = ap.add_subparsers(dest="command", required=True)

    ap_compile = sub.add_parser("compile", help="Compile SBPL to binary blobs using libsandbox.")
    ap_compile.add_argument("paths", nargs="+", type=Path, help="SBPL files to compile")
    ap_compile.add_argument("--out", type=Path, help="Output path (only valid for a single input)")
    ap_compile.add_argument("--out-dir", type=Path, help="Directory for outputs when compiling multiple files")
    ap_compile.add_argument("--no-preview", action="store_true", help="Suppress hex preview")
    ap_compile.set_defaults(func=compile_command)

    ap_inspect = sub.add_parser("inspect", help="Inspect a compiled blob or SBPL (with --compile).")
    ap_inspect.add_argument("path", type=Path, help="Compiled blob (.sb.bin) or SBPL (.sb with --compile).")
    ap_inspect.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap_inspect.add_argument("--json", type=Path, help="Write summary JSON to this path instead of stdout.")
    ap_inspect.add_argument("--stride", type=int, nargs="*", default=[8, 12, 16], help="Stride guesses for node stats.")
    ap_inspect.set_defaults(func=inspect_command)

    ap_op = sub.add_parser("op-table", help="Summarize op-table structure for a profile.")
    ap_op.add_argument("path", type=Path, help="SBPL (.sb) or compiled blob (.sb.bin)")
    ap_op.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap_op.add_argument("--name", type=str, help="Name to use in output (default: stem).")
    ap_op.add_argument("--op-count", type=int, help="Override op_count from header.")
    ap_op.add_argument("--vocab", type=Path, help="Path to ops.json for alignment.")
    ap_op.add_argument("--filters", type=Path, help="Path to filters.json for alignment.")
    ap_op.add_argument("--json", type=Path, help="Write summary JSON to this path (default stdout).")
    ap_op.set_defaults(func=op_table_command)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
