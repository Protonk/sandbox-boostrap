#!/usr/bin/env python3
"""
SBPL oracle dataset runner: network tuple matrix (Sonoma baseline).

This is a *tool-shaped* wrapper around the library oracle:
- Library: `book.api.profile.oracles.extract_network_tuple(blob_bytes)`
- Tool: run that extractor over an experiment-style MANIFEST + blob directory,
  emitting a single JSON report for inspection, check-in, or downstream joins.

Why this lives under `book/tools/sbpl/`:
- It is a one-shot/batch runner that reads and writes files.
- Keeping it out of `book/api/profile` helps the API surface stay “library-like”
  (bytes in → result out), while still providing a canonical runner for the
  `libsandbox-encoder` network matrix corpus.

Expected inputs:
- `manifest_path` follows the shape used by:
  `book/experiments/field2-final-final/libsandbox-encoder/sb/network_matrix/MANIFEST.json`
- `blob_dir` contains `spec_id.sb.bin` for each manifest case.

Output schema:
- `book/tools/sbpl/oracles/schemas/network_matrix_oracle.v1.schema.json`
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile.oracles import WORLD_ID, extract_network_tuple


def run_network_matrix(manifest_path: Path, blob_dir: Path) -> Dict[str, Any]:
    """
    Run the network tuple oracle over a MANIFEST + prebuilt blobs.

    Returns a report-shaped dict suitable for JSON serialization.
    """
    root = find_repo_root(manifest_path)
    data = json.loads(manifest_path.read_text())
    cases = data.get("cases", [])

    entries: List[Dict[str, Any]] = []
    for case in cases:
        spec_id = case["spec_id"]
        blob_path = blob_dir / f"{spec_id}.sb.bin"
        result = extract_network_tuple(blob_path.read_bytes()).to_dict()
        result["spec_id"] = spec_id
        result["blob"] = to_repo_relative(blob_path, root)
        entries.append(result)

    return {
        "world_id": WORLD_ID,
        "oracle_id": "sbpl_oracle.network_tuple.v1",
        "purpose": "Extract (domain,type,proto) tuples from compiled blobs using structural witnesses only.",
        "inputs": {
            "manifest": to_repo_relative(manifest_path, root),
            "blob_dir": to_repo_relative(blob_dir, root),
        },
        "entries": entries,
    }


def _write_json(out_path: Path | None, payload: Dict[str, Any]) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out_path is None:
        print(text)
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    # `out_path` may be outside the repo (e.g. `/tmp/...`), so find the repo
    # root from this checkout rather than walking up from `out_path`.
    root = find_repo_root()
    print(f"[+] wrote {to_repo_relative(out_path, root)}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run the network tuple oracle over a MANIFEST + blob directory (Sonoma baseline)."
    )
    ap.add_argument("--manifest", required=True, type=Path, help="Path to MANIFEST.json.")
    ap.add_argument("--blob-dir", required=True, type=Path, help="Directory containing <spec_id>.sb.bin blobs.")
    ap.add_argument("--out", type=Path, help="Write JSON output to this path (default stdout).")

    args = ap.parse_args(argv)
    payload = run_network_matrix(args.manifest, args.blob_dir)
    _write_json(args.out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
