#!/usr/bin/env python3
"""
CLI for op-table centric summaries on the Sonoma baseline.

Usage:
  python -m book.api.op_table.cli <path> [--compile] [--name NAME] [--op-count N]
                                   [--vocab book/graph/mappings/vocab/ops.json]
                                   [--filters book/graph/mappings/vocab/filters.json]
                                   [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from book.api import sbpl_compile
from . import build_alignment, load_vocab, parse_filters, parse_ops, summarize_profile


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Summarize op-table structure for a profile.")
    ap.add_argument("path", type=Path, help="SBPL (.sb) or compiled blob (.sb.bin)")
    ap.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap.add_argument("--name", type=str, help="Name to use in output (default: stem).")
    ap.add_argument("--op-count", type=int, help="Override op_count from header.")
    ap.add_argument("--vocab", type=Path, help="Path to ops.json for alignment.")
    ap.add_argument("--filters", type=Path, help="Path to filters.json for alignment.")
    ap.add_argument("--json", type=Path, help="Write summary JSON to this path (default stdout).")
    args = ap.parse_args(argv)

    blob_path = args.path
    tmp = None
    ops_list = []
    filters_list = []
    filter_vocab_names = set()
    if args.compile:
        tmp = tempfile.NamedTemporaryFile(prefix="op_table_", suffix=".sb.bin", delete=False)
        res = sbpl_compile.compile_sbpl_file(blob_path, Path(tmp.name))
        blob_path = Path(tmp.name)
        print(f"[+] compiled {args.path} -> {blob_path} (len={res.length}, type={res.profile_type})")
        ops_list = parse_ops(args.path)
        if args.filters and args.filters.exists():
            fv = load_vocab(args.filters)
            filter_vocab_names = {entry["name"] for entry in fv.get("filters", [])}
            filters_list = parse_filters(args.path, filter_vocab_names)

    name = args.name or blob_path.stem
    filter_map = None
    if args.filters and args.filters.exists():
        fv = load_vocab(args.filters)
        filter_map = {entry["name"]: entry["id"] for entry in fv.get("filters", [])}
    summary = summarize_profile(
        name=name,
        blob=blob_path.read_bytes(),
        ops=ops_list,
        filters=filters_list,
        op_count_override=args.op_count,
        filter_map=filter_map,
    )
    payload = summary.__dict__

    if args.vocab and args.vocab.exists() and args.filters and args.filters.exists():
        ops_vocab = load_vocab(args.vocab)
        filters_vocab = load_vocab(args.filters)
        alignment = build_alignment([summary], ops_vocab, filters_vocab)
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


if __name__ == "__main__":
    raise SystemExit(main())
