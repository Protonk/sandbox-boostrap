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
  `book/evidence/experiments/field2-final-final/libsandbox-encoder/sb/network_matrix/MANIFEST.json`
- `blob_dir` contains `spec_id.sb.bin` for each manifest case.

Output schema:
- `book/tools/sbpl/oracles/schemas/network_matrix_oracle.v1.schema.json`

Optional:
- `--trace-analysis` overlays encoder-write-trace join windows per spec.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative
from book.api.profile.oracles import WORLD_ID, extract_network_tuple
from book.api.profile._shared import encoder_trace as trace_mod


def run_network_matrix(
    manifest_path: Path,
    blob_dir: Path,
    trace_analysis: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Run the network tuple oracle over a MANIFEST + prebuilt blobs.

    Returns a report-shaped dict suitable for JSON serialization.
    """
    root = find_repo_root(manifest_path)
    data = json.loads(manifest_path.read_text())
    cases = data.get("cases", [])

    trace_map: Optional[Dict[str, Dict[str, Any]]] = None
    trace_analysis_rel = None
    if trace_analysis is not None:
        analysis_path = ensure_absolute(trace_analysis, root)
        analysis = json.loads(analysis_path.read_text())
        trace_map = trace_mod.best_trace_map(analysis)
        trace_analysis_rel = to_repo_relative(analysis_path, root)

    entries: List[Dict[str, Any]] = []
    for case in cases:
        spec_id = case["spec_id"]
        blob_path = blob_dir / f"{spec_id}.sb.bin"
        result = extract_network_tuple(blob_path.read_bytes()).to_dict()
        result["spec_id"] = spec_id
        result["blob"] = to_repo_relative(blob_path, root)
        if trace_map is not None:
            result["trace_window"] = trace_map.get(spec_id)
        entries.append(result)

    inputs = {
        "manifest": to_repo_relative(manifest_path, root),
        "blob_dir": to_repo_relative(blob_dir, root),
    }
    if trace_analysis_rel:
        inputs["trace_analysis"] = trace_analysis_rel

    return {
        "world_id": WORLD_ID,
        "oracle_id": "sbpl_oracle.network_tuple.v1",
        "purpose": "Extract (domain,type,proto) tuples from compiled blobs using structural witnesses only.",
        "inputs": inputs,
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
    ap.add_argument(
        "--trace-analysis",
        type=Path,
        help="Optional encoder-write-trace analysis JSON to overlay trace windows.",
    )

    args = ap.parse_args(argv)
    payload = run_network_matrix(args.manifest, args.blob_dir, trace_analysis=args.trace_analysis)
    _write_json(args.out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
