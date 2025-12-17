#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .network import extract_network_tuple, run_network_matrix


def _write_json(path: Path | None, payload: dict) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if path is None:
        print(text)
        return
    path.write_text(text)
    print(f"[+] wrote {path}")


def cmd_network_blob(args: argparse.Namespace) -> int:
    blob = Path(args.blob).read_bytes()
    out = extract_network_tuple(blob).to_dict()
    _write_json(Path(args.out) if args.out else None, out)
    return 0


def cmd_network_matrix(args: argparse.Namespace) -> int:
    manifest = Path(args.manifest)
    blob_dir = Path(args.blob_dir)
    out = run_network_matrix(manifest, blob_dir)
    _write_json(Path(args.out) if args.out else None, out)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="book.api.sbpl_oracle", description="Structural SBPL↔compiled-profile oracles (Sonoma baseline).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_blob = sub.add_parser("network-blob", help="Extract (domain,type,proto) from a single compiled blob.")
    p_blob.add_argument("--blob", required=True, help="Path to a compiled profile blob (.sb.bin).")
    p_blob.add_argument("--out", help="Write JSON to this path (defaults to stdout).")
    p_blob.set_defaults(fn=cmd_network_blob)

    p_matrix = sub.add_parser("network-matrix", help="Run the oracle over an experiment-style network matrix manifest + blob dir.")
    p_matrix.add_argument("--manifest", required=True, help="Path to MANIFEST.json.")
    p_matrix.add_argument("--blob-dir", required=True, help="Directory containing <spec_id>.sb.bin blobs.")
    p_matrix.add_argument("--out", help="Write JSON to this path (defaults to stdout).")
    p_matrix.set_defaults(fn=cmd_network_matrix)

    args = parser.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())

