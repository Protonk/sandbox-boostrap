#!/usr/bin/env python3
"""
`book.api.profile` command-line interface (Sonoma baseline).

This CLI is deliberately *structural* rather than semantic:
- Compile SBPL (`.sb`) to a compiled blob (`.sb.bin`) using libsandbox's private
  compiler entry points (`sandbox_compile_*`).
- Decode and inspect compiled blobs to reason about on-disk layout: header
  words, op-table entries, node stream framing, and literal pool slices.
- Summarize op-table structure (and optionally align against the published
  vocab mappings under `book/integration/carton/bundle/relationships/mappings/vocab/`).
- Emit digests for canonical blobs and run small “structural oracles”.

Non-goals:
- Applying or executing profiles (runtime) — use `book.api.runtime` / the
  runtime harness instead.
- Kernel policy semantics — outputs are best-effort and must be interpreted
  using the repo’s canonical mappings and corroborating artifacts.

This is the entrypoint for `python -m book.api.profile ...` (via `__main__.py`).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from book.api.path_utils import find_repo_root, to_repo_relative

from . import compile as compile_mod
from . import decoder as decoder_mod
from . import digests as digests_mod
from . import inspect as inspect_mod
from . import op_table as op_table_mod
from . import oracles as oracles_mod


def _choose_out(src: Path, out: Path | None, out_dir: Path | None) -> Path:
    """
    Choose an output path for a compiled blob.

    CLI rules:
    - If the caller provided an explicit `--out`, use it.
    - Else if `--out-dir` is set, place `<stem>.sb.bin` under that directory.
    - Else mirror input next to the SBPL file.
    """
    if out:
        return out
    if out_dir:
        return out_dir / f"{src.stem}.sb.bin"
    if src.suffix == ".sb":
        return src.with_suffix(".sb.bin")
    return src.with_name(f"{src.name}.sb.bin")


def _load_params(args: argparse.Namespace) -> dict[str, str] | None:
    """
    Parse compile-time `(param "...")` values from CLI flags.

    Important: these are *compile-time* parameters passed to libsandbox via the
    params-handle interface (`sandbox_create_params` / `sandbox_set_param`), not
    apply-time argv parameterization used by other sandbox entry points.
    """
    params: dict[str, str] = {}
    if getattr(args, "params_json", None):
        doc = json.loads(args.params_json.read_text())
        if not isinstance(doc, dict):
            raise SystemExit("--params-json must be a JSON object mapping KEY -> VALUE")
        params.update({str(k): str(v) for k, v in doc.items()})
    for raw in getattr(args, "param", []) or []:
        if "=" not in raw:
            raise SystemExit(f"--param must be KEY=VALUE (got {raw!r})")
        key, value = raw.split("=", 1)
        if not key:
            raise SystemExit(f"--param key must be non-empty (got {raw!r})")
        params[key] = value
    return params or None


def compile_many(
    paths: Iterable[Path],
    out: Path | None = None,
    out_dir: Path | None = None,
    preview: bool = True,
    params: dict[str, str] | None = None,
) -> list[tuple[Path, compile_mod.CompileResult]]:
    """
    Compile a set of SBPL files and optionally print a short hex preview.

    Returns a list of `(output_path, CompileResult)` for downstream scripting.
    """
    results: list[tuple[Path, compile_mod.CompileResult]] = []
    for src in paths:
        target = _choose_out(src, out, out_dir)
        res = compile_mod.compile_sbpl_file(src, target, params=params)
        results.append((target, res))
        if preview:
            print(f"[+] {src} -> {target} (len={res.length}, type={res.profile_type}) preview: {compile_mod.hex_preview(res.blob)}")
        else:
            print(f"[+] {src} -> {target} (len={res.length}, type={res.profile_type})")
    return results


def compile_command(args: argparse.Namespace) -> int:
    """`profile compile`: SBPL → blob for one or more inputs."""
    if args.out and len(args.paths) != 1:
        raise SystemExit("--out is only valid with a single input")
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    params = _load_params(args)
    compile_many(args.paths, out=args.out, out_dir=args.out_dir, preview=not args.no_preview, params=params)
    return 0


def inspect_command(args: argparse.Namespace) -> int:
    """
    `profile inspect`: summarize a compiled blob (or SBPL with `--compile`).

    When `--compile` is used, we compile to a temporary `.sb.bin` to keep the
    user's working tree clean; the inspection surface consumes blob bytes.
    """
    blob_path = args.path
    tmp_dir = tempfile.TemporaryDirectory(prefix="inspect_profile_") if args.compile else None
    try:
        if args.compile:
            tmp_path = Path(tmp_dir.name) / "compiled.sb.bin"  # type: ignore[union-attr]
            res = compile_mod.compile_sbpl_file(blob_path, tmp_path)
            blob_path = tmp_path
            print(f"[+] compiled {args.path} -> {blob_path} (len={res.length}, type={res.profile_type})")

        summary = inspect_mod.summarize_blob(blob_path.read_bytes(), strides=args.stride)
        payload = summary.__dict__
        output = json.dumps(payload, indent=2)
        if args.out:
            args.out.write_text(output)
            print(f"[+] wrote {args.out}")
        else:
            print(output)
        return 0
    finally:
        if tmp_dir is not None:
            tmp_dir.cleanup()


def op_table_command(args: argparse.Namespace) -> int:
    """
    `profile op-table`: op-table summary and optional alignment.

    Notes:
    - When `--compile` is used, the SBPL file is parsed for operation/filter
      *names* (the blob does not carry SBPL tokens), then compiled for the blob
      bytes that back the op-table.
    - Alignment is an optional join against vocab mappings; it is a “wiring”
      helper, not a semantic claim.
    """
    blob_path = args.path
    tmp_dir = tempfile.TemporaryDirectory(prefix="op_table_") if args.compile else None
    ops_list = []
    filters_list = []
    filter_vocab_names = set()
    try:
        if args.compile:
            tmp_path = Path(tmp_dir.name) / "compiled.sb.bin"  # type: ignore[union-attr]
            res = compile_mod.compile_sbpl_file(blob_path, tmp_path)
            blob_path = tmp_path
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
        if args.out:
            args.out.write_text(output)
            print(f"[+] wrote {args.out}")
        else:
            print(output)
        return 0
    finally:
        if tmp_dir is not None:
            tmp_dir.cleanup()


def decode_dump_command(args: argparse.Namespace) -> int:
    """
    `profile decode dump`: dump header fields and quick heuristics for blobs.

    This is intentionally “low ceremony”: it is a debugging aid for humans and
    experiments. The canonical programmatic surface is `book.api.profile.decoder`.
    """
    paths = [Path(p) for p in args.blobs]
    out: list[dict] = []
    for path in paths:
        data = path.read_bytes()
        prof = decoder_mod.decode_profile(data, header_window=args.bytes, node_stride_bytes=args.node_stride)
        header_bytes = prof.header_bytes.hex()
        entry = {
            "path": str(path),
            "op_count": prof.op_count,
            "sections": prof.sections,
            "preamble_words_full": prof.preamble_words_full,
            "header_bytes_hex": header_bytes,
            "header_fields": prof.header_fields,
        }
        if args.summary:
            entry = {
                "path": str(path),
                "op_count": prof.op_count,
                "maybe_flags": prof.header_fields.get("maybe_flags"),
                "word0": prof.preamble_words_full[0] if prof.preamble_words_full else None,
                "word2": prof.preamble_words_full[2] if len(prof.preamble_words_full) > 2 else None,
                "profile_class": prof.header_fields.get("profile_class"),
                "profile_class_word_index": prof.header_fields.get("profile_class_word_index"),
            }
        out.append(entry)

    serialized = json.dumps(out, indent=None if args.summary else 2)
    if args.out:
        args.out.write_text(serialized)
        print(f"[+] wrote {args.out}")
    else:
        sys.stdout.write(serialized + ("\n" if not serialized.endswith("\n") else ""))
    return 0


def _write_json(path: Path | None, payload: dict) -> None:
    """Write JSON to `path` or stdout (used by oracle subcommands)."""
    text = json.dumps(payload, indent=2, sort_keys=True)
    if path is None:
        print(text)
        return
    path.write_text(text)
    print(f"[+] wrote {path}")


def oracle_network_blob_command(args: argparse.Namespace) -> int:
    """`profile oracle network-blob`: run the socket tuple oracle on one blob."""
    blob = Path(args.blob).read_bytes()
    out = oracles_mod.extract_network_tuple(blob).to_dict()
    _write_json(Path(args.out) if args.out else None, out)
    return 0


def digest_system_profiles_command(args: argparse.Namespace) -> int:
    """`profile digest system-profiles`: digest the canonical system blob set."""
    blobs = digests_mod.canonical_system_profile_blobs()
    payload = digests_mod.digest_named_blobs(blobs)
    if args.out:
        digests_mod.write_digests_json(payload, args.out)
        root = find_repo_root()
        print(f"[+] wrote {to_repo_relative(args.out, root)}")
        return 0
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    """
    Entrypoint for the `python -m book.api.profile` CLI.

    Accepts an optional `argv` for unit tests and embedding.
    """
    ap = argparse.ArgumentParser(
        description="Unified profile tooling (compile, decode, inspect, op-table, digest, oracles) for Sonoma Seatbelt."
    )
    sub = ap.add_subparsers(dest="command", required=True)

    ap_compile = sub.add_parser("compile", help="Compile SBPL to binary blobs using libsandbox.")
    ap_compile.add_argument("paths", nargs="+", type=Path, help="SBPL files to compile")
    ap_compile.add_argument("--out", type=Path, help="Output path (only valid for a single input)")
    ap_compile.add_argument("--out-dir", type=Path, help="Directory for outputs when compiling multiple files")
    ap_compile.add_argument("--param", action="append", default=[], help="Parameter KEY=VALUE (repeatable)")
    ap_compile.add_argument("--params-json", type=Path, help="JSON object mapping params KEY -> VALUE")
    ap_compile.add_argument("--no-preview", action="store_true", help="Suppress hex preview")
    ap_compile.set_defaults(func=compile_command)

    ap_inspect = sub.add_parser("inspect", help="Inspect a compiled blob or SBPL (with --compile).")
    ap_inspect.add_argument("path", type=Path, help="Compiled blob (.sb.bin) or SBPL (.sb with --compile).")
    ap_inspect.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap_inspect.add_argument("--out", "--json", dest="out", type=Path, help="Write summary JSON to this path instead of stdout.")
    ap_inspect.add_argument("--stride", type=int, nargs="*", default=[8, 12, 16], help="Stride guesses for node stats.")
    ap_inspect.set_defaults(func=inspect_command)

    ap_op = sub.add_parser("op-table", help="Summarize op-table structure for a profile.")
    ap_op.add_argument("path", type=Path, help="SBPL (.sb) or compiled blob (.sb.bin)")
    ap_op.add_argument("--compile", action="store_true", help="Treat input as SBPL and compile first.")
    ap_op.add_argument("--name", type=str, help="Name to use in output (default: stem).")
    ap_op.add_argument("--op-count", type=int, help="Override op_count from header.")
    ap_op.add_argument("--vocab", type=Path, help="Path to ops.json for alignment.")
    ap_op.add_argument("--filters", type=Path, help="Path to filters.json for alignment.")
    ap_op.add_argument("--out", "--json", dest="out", type=Path, help="Write summary JSON to this path (default stdout).")
    ap_op.set_defaults(func=op_table_command)

    ap_decode = sub.add_parser("decode", help="Decode compiled blob headers and section boundaries.")
    decode_sub = ap_decode.add_subparsers(dest="decode_cmd", required=True)

    dump_p = decode_sub.add_parser("dump", help="Dump header fields for one or more blobs")
    dump_p.add_argument("blobs", nargs="+", help="Paths to .sb.bin blobs")
    dump_p.add_argument("--bytes", type=int, default=128, help="Header byte window to capture (default 128)")
    dump_p.add_argument("--summary", action="store_true", help="Emit a compact summary instead of full header dump")
    dump_p.add_argument("--out", type=Path, help="Write JSON to this path instead of stdout")
    dump_p.add_argument(
        "--node-stride",
        type=int,
        choices=[8, 12, 16],
        help="Force a fixed node record stride (expert / cross-check use)",
    )
    dump_p.set_defaults(func=decode_dump_command)

    ap_digest = sub.add_parser("digest", help="Generate decoder-backed digests for curated blobs.")
    digest_sub = ap_digest.add_subparsers(dest="digest_cmd", required=True)

    p_sys = digest_sub.add_parser("system-profiles", help="Digest the canonical system profile blobs for this world.")
    p_sys.add_argument("--out", type=Path, help="Write JSON to this path (default stdout).")
    p_sys.set_defaults(func=digest_system_profiles_command)

    ap_oracle = sub.add_parser("oracle", help="Run structural oracles over compiled blobs.")
    oracle_sub = ap_oracle.add_subparsers(dest="oracle_cmd", required=True)

    p_blob = oracle_sub.add_parser("network-blob", help="Extract (domain,type,proto) from a single compiled blob.")
    p_blob.add_argument("--blob", required=True, help="Path to a compiled profile blob (.sb.bin).")
    p_blob.add_argument("--out", help="Write JSON to this path (defaults to stdout).")
    p_blob.set_defaults(func=oracle_network_blob_command)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
