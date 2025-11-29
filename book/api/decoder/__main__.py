"""
CLI helper to dump header fields and raw bytes from compiled sandbox profile blobs.

Usage:
  python -m book.api.decoder dump <blob1> [blob2 ...] [--bytes N] [--summary] [--out path]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from book.api import decoder


def dump_blobs(paths: list[Path], byte_window: int, summary: bool) -> list[dict]:
    out: list[dict] = []
    for path in paths:
        data = path.read_bytes()
        prof = decoder.decode_profile(data)
        header_bytes = prof.header_bytes.hex()
        entry = {
            "path": str(path),
            "op_count": prof.op_count,
            "sections": prof.sections,
            "preamble_words_full": prof.preamble_words_full,
            "header_bytes_hex": header_bytes,
            "header_fields": prof.header_fields,
        }
        if summary:
            entry = {
                "path": str(path),
                "op_count": prof.op_count,
                "maybe_flags": prof.header_fields.get("maybe_flags"),
                "word0": prof.preamble_words_full[0] if prof.preamble_words_full else None,
                "word2": prof.preamble_words_full[2] if len(prof.preamble_words_full) > 2 else None,
            }
        out.append(entry)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode sandbox profile blob headers.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    dump_p = sub.add_parser("dump", help="Dump header fields for blobs")
    dump_p.add_argument("blobs", nargs="+", help="Paths to .sb.bin blobs")
    dump_p.add_argument("--bytes", type=int, default=128, help="Header byte window to capture (default 128)")
    dump_p.add_argument("--summary", action="store_true", help="Emit a compact summary instead of full header dump")
    dump_p.add_argument("--out", type=Path, help="Write JSON to this path instead of stdout")

    args = parser.parse_args(argv)

    if args.cmd == "dump":
        paths = [Path(p) for p in args.blobs]
        results = dump_blobs(paths, args.bytes, args.summary)
        serialized = json.dumps(results, indent=None if args.summary else 2)

        if args.out:
            args.out.write_text(serialized)
        else:
            sys.stdout.write(serialized + ("\n" if not serialized.endswith("\n") else ""))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
