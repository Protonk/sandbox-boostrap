#!/usr/bin/env python3
"""
Regenerate node-layout experiment outputs (Sonoma baseline).

This runner replaces the experiment-local analyzer by using shared profile APIs.
Outputs (unchanged schema + paths):
- book/evidence/experiments/profile-pipeline/node-layout/out/summary.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.profile import compile as compile_mod
from book.api.profile import ingestion as ingestion_mod
from book.api.profile import inspect as inspect_mod
from book.api.profile._shared import bytes_util as bu


ROOT = path_utils.find_repo_root(Path(__file__))
EXP_ROOT = ROOT / "book/evidence/experiments/profile-pipeline/node-layout"
SB_DIR = EXP_ROOT / "sb"
BUILD_DIR = SB_DIR / "build"
OUT_PATH = EXP_ROOT / "out/summary.json"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {path_utils.to_repo_relative(path, ROOT)}")


def _summarize_variant(sb_path: Path) -> Dict[str, Any]:
    blob = compile_mod.compile_sbpl_file(sb_path, BUILD_DIR / f"{sb_path.stem}.sb.bin").blob
    prof = ingestion_mod.ProfileBlob(bytes=blob, source=sb_path.stem)
    header = ingestion_mod.parse_header(prof)
    sections = ingestion_mod.slice_sections(prof, header)
    op_count = header.operation_count or 0
    op_entries = bu.op_entries(blob, op_count) if op_count else []

    inspect_summary = inspect_mod.summarize_blob(blob, strides=(8, 12, 16))
    records8 = bu.record_dump(sections.nodes, stride=8)
    records12 = bu.record_dump(sections.nodes, stride=12)
    tail8 = bu.tail_records(sections.nodes, stride=8)
    tail12 = bu.tail_records(sections.nodes, stride=12)
    tag_counts_stride8 = {str(k): v for k, v in bu.tag_counts(sections.nodes, stride=8).items()}
    tag_counts_stride12 = {str(k): v for k, v in bu.tag_counts(sections.nodes, stride=12).items()}

    return {
        "name": sb_path.stem,
        "length": len(blob),
        "format_variant": inspect_summary.format_variant,
        "op_count": op_count,
        "op_entries": op_entries,
        "section_lengths": inspect_summary.section_lengths,
        "stride_stats": inspect_summary.stride_stats,
        "records_stride8": records8["records"],
        "records_stride12": records12["records"],
        "tag_counts_stride8": tag_counts_stride8,
        "tag_counts_stride12": tag_counts_stride12,
        "remainder_stride8_hex": records8["remainder_hex"],
        "remainder_stride12_hex": records12["remainder_hex"],
        "literal_strings": bu.ascii_strings(sections.regex_literals),
        "tail_stride8": tail8,
        "tail_stride12": tail12,
        "decoder": inspect_summary.decoder,
    }


def main() -> int:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    summaries: List[Dict[str, Any]] = []
    for sb_path in sorted(SB_DIR.glob("*.sb")):
        summaries.append(_summarize_variant(sb_path))
    _write_json(OUT_PATH, summaries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
