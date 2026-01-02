#!/usr/bin/env python3
"""Audit KC fixups decode by sampling raw records and chain behavior."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from book.api import path_utils


def _load_fixups(path: Path) -> List[dict]:
    fixups: List[dict] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                fixups.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return fixups


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit chained-fixups decode consistency.")
    parser.add_argument("--fixups", required=True, help="kc_fixups.jsonl path")
    parser.add_argument("--fileset-index", required=True, help="kc_fileset_index.json path")
    parser.add_argument("--summary", required=True, help="kc_fixups_summary.json path")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument("--sample-per-level", type=int, default=8, help="Sample records per cache_level")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    fixups_path = Path(args.fixups)
    fileset_index_path = Path(args.fileset_index)
    summary_path = Path(args.summary)
    out_path = Path(args.out)

    fixups = _load_fixups(fixups_path)
    if not fixups:
        raise SystemExit("No fixups records found")
    required_keys = {"segment_index", "page_index", "next_offset", "segment_name"}
    missing = [key for key in required_keys if key not in fixups[0]]
    if missing:
        raise SystemExit(
            "Fixups file is missing full-record fields (%s). Re-run kc_truth_layer.py with --fixups-mode full."
            % ", ".join(missing)
        )
    fileset_index = json.loads(fileset_index_path.read_text())
    summary = json.loads(summary_path.read_text())

    segments = fileset_index.get("segments") or []
    page_coverage = (summary.get("fixup_counts") or {}).get("page_coverage") or {}
    page_sizes = {name: data.get("page_size") for name, data in page_coverage.items()}

    level_counts: Dict[str, int] = defaultdict(int)
    level_by_segment: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    target_ranges: Dict[str, Dict[str, int]] = {}
    next_out_of_page: Dict[str, int] = defaultdict(int)
    next_total: Dict[str, int] = defaultdict(int)
    samples: Dict[str, List[dict]] = defaultdict(list)

    for rec in fixups:
        if rec.get("pointer_format") != 8:
            continue
        decoded = rec.get("decoded") or {}
        cache_level = decoded.get("cache_level")
        target = decoded.get("target")
        if cache_level is None:
            continue
        level_key = str(cache_level)
        level_counts[level_key] += 1

        seg_name = rec.get("segment_name") or "unknown"
        level_by_segment[seg_name][level_key] += 1

        if target is not None:
            bucket = target_ranges.setdefault(level_key, {"min": int(target), "max": int(target)})
            bucket["min"] = min(bucket["min"], int(target))
            bucket["max"] = max(bucket["max"], int(target))

        next_offset = rec.get("next_offset") or 0
        if next_offset > 0:
            next_total[level_key] += 1
            seg_index = rec.get("segment_index")
            page_index = rec.get("page_index")
            vmaddr = rec.get("vmaddr")
            page_size = page_sizes.get(seg_name)
            in_page = None
            if (
                seg_index is not None
                and page_index is not None
                and vmaddr is not None
                and page_size is not None
                and seg_index < len(segments)
            ):
                seg_vmaddr = segments[seg_index].get("vmaddr")
                if seg_vmaddr is not None:
                    page_base = int(seg_vmaddr) + int(page_index) * int(page_size)
                    next_vmaddr = int(vmaddr) + int(next_offset)
                    in_page = page_base <= next_vmaddr < page_base + int(page_size)
                    if not in_page:
                        next_out_of_page[level_key] += 1

            if len(samples[level_key]) < args.sample_per_level:
                samples[level_key].append(
                    {
                        "vmaddr": rec.get("vmaddr"),
                        "segment_name": seg_name,
                        "segment_index": rec.get("segment_index"),
                        "page_index": page_index,
                        "page_start": rec.get("page_start"),
                        "page_chain_start": rec.get("page_chain_start"),
                        "raw": rec.get("raw"),
                        "decoded": decoded,
                        "next_offset": next_offset,
                        "next_in_page": in_page,
                    }
                )

    next_out_fraction = {}
    for level_key, total in next_total.items():
        if total:
            next_out_fraction[level_key] = float(next_out_of_page.get(level_key, 0)) / total
        else:
            next_out_fraction[level_key] = 0.0

    output = {
        "meta": {
            "fixups": path_utils.to_repo_relative(fixups_path, repo_root),
            "fileset_index": path_utils.to_repo_relative(fileset_index_path, repo_root),
            "summary": path_utils.to_repo_relative(summary_path, repo_root),
        },
        "cache_level_counts": dict(level_counts),
        "cache_level_by_segment": {k: dict(v) for k, v in level_by_segment.items()},
        "target_ranges": target_ranges,
        "next_total": dict(next_total),
        "next_out_of_page": dict(next_out_of_page),
        "next_out_of_page_fraction": next_out_fraction,
        "samples": dict(samples),
    }
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True))
    print("Wrote", path_utils.to_repo_relative(out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
