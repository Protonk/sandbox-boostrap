#!/usr/bin/env python3
"""
Extract SBPL Scheme-related strings from libsandbox and search for unknown field2 values.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Dict, Any

import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils

SCHEMA_VERSION = "field2-filters.libsandbox_scheme_extract.v0"
DEFAULT_LIBSANDBOX = (
    REPO_ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "dyld-libs" / "usr" / "lib" / "libsandbox.1.dylib"
)
DEFAULT_UNKNOWN_NODES = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-filters"
    / "out"
    / "unknown_nodes.json"
)
DEFAULT_OUT_DIR = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "field2-final-final"
    / "field2-filters"
    / "out"
    / "libsandbox_scheme"
)


def extract_strings(data: bytes, *, min_len: int = 4) -> List[str]:
    out: List[str] = []
    buf: List[int] = []
    for byte in data:
        if 32 <= byte <= 126:
            buf.append(byte)
            continue
        if len(buf) >= min_len:
            out.append(bytes(buf).decode("ascii", errors="ignore"))
        buf = []
    if len(buf) >= min_len:
        out.append(bytes(buf).decode("ascii", errors="ignore"))
    return out


def load_unknown_values(path: Path) -> List[int]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    values = set()
    for nodes in data.values():
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            raw = node.get("raw") if isinstance(node, dict) else None
            if isinstance(raw, int):
                values.add(raw)
    return sorted(values)


def scheme_candidates(strings: Iterable[str]) -> List[str]:
    candidates = []
    for s in strings:
        if "sbpl" in s or "scheme" in s or s.startswith("("):
            candidates.append(s)
    return candidates


def find_value_hits(strings: Iterable[str], values: Iterable[int], *, max_hits: int = 12) -> List[Dict[str, Any]]:
    str_list = list(strings)
    hits = []
    for raw in values:
        dec = str(raw)
        hex_lower = hex(raw)
        matched = [s for s in str_list if dec in s or hex_lower in s]
        hits.append(
            {
                "raw": raw,
                "raw_hex": hex_lower,
                "hit_count": len(matched),
                "sample_hits": matched[:max_hits],
            }
        )
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libsandbox", type=Path, default=DEFAULT_LIBSANDBOX)
    parser.add_argument("--unknown-nodes", type=Path, default=DEFAULT_UNKNOWN_NODES)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--min-len", type=int, default=4)
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    libsandbox_path = args.libsandbox
    data = libsandbox_path.read_bytes()
    strings = extract_strings(data, min_len=args.min_len)
    candidates = scheme_candidates(strings)
    unknown_values = load_unknown_values(args.unknown_nodes)
    hits = find_value_hits(strings, unknown_values)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = args.out_dir / "scheme_candidates.txt"
    candidates_path.write_text("\n".join(candidates) + "\n")

    hits_path = args.out_dir / "unknown_value_hits.json"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "world_id": "sonoma-14.4.1-23E224-arm64-dyld-a3a840f9",
        "libsandbox": path_utils.to_repo_relative(libsandbox_path, repo_root=repo_root),
        "unknown_nodes": path_utils.to_repo_relative(args.unknown_nodes, repo_root=repo_root),
        "min_len": args.min_len,
        "candidate_count": len(candidates),
        "string_count": len(strings),
        "unknown_values": hits,
    }
    hits_path.write_text(json.dumps(payload, indent=2))

    summary_path = args.out_dir / "extract_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "world_id": "sonoma-14.4.1-23E224-arm64-dyld-a3a840f9",
                "libsandbox": payload["libsandbox"],
                "unknown_nodes": payload["unknown_nodes"],
                "string_count": payload["string_count"],
                "candidate_count": payload["candidate_count"],
                "unknown_value_count": len(unknown_values),
                "unknown_value_hits": path_utils.to_repo_relative(hits_path, repo_root=repo_root),
                "scheme_candidates": path_utils.to_repo_relative(candidates_path, repo_root=repo_root),
            },
            indent=2,
        )
    )

    print(f"[+] wrote {path_utils.to_repo_relative(candidates_path, repo_root=repo_root)}")
    print(f"[+] wrote {path_utils.to_repo_relative(hits_path, repo_root=repo_root)}")
    print(f"[+] wrote {path_utils.to_repo_relative(summary_path, repo_root=repo_root)}")


if __name__ == "__main__":
    main()
