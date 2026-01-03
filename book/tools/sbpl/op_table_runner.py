#!/usr/bin/env python3
"""
Regenerate op-table experiment outputs (Sonoma baseline).

This runner replaces the experiment-local analyze/build scripts by using
`book.api.profile.op_table` as the single source of op-table logic.

Outputs (unchanged schema + paths):
- book/evidence/experiments/profile-pipeline/op-table-operation/out/summary.json
- book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_map.json
- book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_signatures.json
- book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_catalog_v1.json
- book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.profile import compile as compile_mod
from book.api.profile import ingestion as ingestion_mod
from book.api.profile import op_table as op_table_mod
from book.api.profile._shared import bytes_util as bu


ROOT = path_utils.find_repo_root(Path(__file__))

EXP_ROOT = ROOT / "book/evidence/experiments/profile-pipeline"
OP_ROOT = EXP_ROOT / "op-table-operation"
ALIGN_ROOT = EXP_ROOT / "op-table-vocab-alignment"
VOCAB_ROOT = ROOT / "book/integration/carton/bundle/relationships/mappings/vocab"

OPS_VOCAB_PATH = VOCAB_ROOT / "ops.json"
FILTERS_VOCAB_PATH = VOCAB_ROOT / "filters.json"

SUMMARY_PATH = OP_ROOT / "out/summary.json"
OP_MAP_PATH = OP_ROOT / "out/op_table_map.json"
OP_SIG_PATH = OP_ROOT / "out/op_table_signatures.json"
CATALOG_PATH = OP_ROOT / "out/op_table_catalog_v1.json"
ALIGN_PATH = ALIGN_ROOT / "out/op_table_vocab_alignment.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[+] wrote {path_utils.to_repo_relative(path, ROOT)}")


def _load_vocab_map(path: Path, key: str) -> Tuple[Dict[str, int], set[str], Dict[str, Any]]:
    data = _load_json(path) or {}
    entries = data.get(key) or []
    mapping = {entry["name"]: entry["id"] for entry in entries if isinstance(entry, dict)}
    names = set(mapping.keys())
    return mapping, names, data


def _summarize_profiles() -> Tuple[List[op_table_mod.Summary], List[Dict[str, Any]]]:
    sb_dir = OP_ROOT / "sb"
    build_dir = sb_dir / "build"
    build_dir.mkdir(parents=True, exist_ok=True)

    filter_map, filter_names, _filters_vocab = _load_vocab_map(FILTERS_VOCAB_PATH, "filters")

    summaries: List[op_table_mod.Summary] = []
    summary_rows: List[Dict[str, Any]] = []
    for sb_path in sorted(sb_dir.glob("*.sb")):
        blob = compile_mod.compile_sbpl_file(sb_path, build_dir / f"{sb_path.stem}.sb.bin").blob
        ops = op_table_mod.parse_ops(sb_path)
        filters = op_table_mod.parse_filters(sb_path, filter_names)
        summary = op_table_mod.summarize_profile(
            name=sb_path.stem,
            blob=blob,
            ops=ops,
            filters=filters,
            filter_map=filter_map,
        )

        prof = ingestion_mod.ProfileBlob(bytes=blob, source=sb_path.stem)
        header = ingestion_mod.parse_header(prof)
        sections = ingestion_mod.slice_sections(prof, header)
        tag_counts_stride8 = {
            str(k): v for k, v in bu.tag_counts(sections.nodes, stride=8).items()
        }
        rem8 = sections.nodes[(len(sections.nodes) // 8) * 8 :].hex()

        summaries.append(summary)
        summary_rows.append(
            {
                "name": summary.name,
                "ops": summary.ops,
                "filters": summary.filters,
                "filter_ids": summary.filter_ids,
                "length": summary.length,
                "format_variant": summary.format_variant,
                "op_count": summary.op_count,
                "op_count_source": summary.op_count_source,
                "op_entries": summary.op_entries,
                "section_lengths": summary.section_lengths,
                "tag_counts_stride8": tag_counts_stride8,
                "remainder_stride8_hex": rem8,
                "tag_counts_stride12": summary.tag_counts_stride12,
                "remainder_stride12_hex": summary.remainder_stride12_hex,
                "literal_strings": summary.literal_strings,
                "decoder": summary.decoder,
                "entry_signatures": summary.entry_signatures,
            }
        )

    return summaries, summary_rows


def _build_op_table_map(summary_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    single_op_entries: Dict[str, List[int]] = {}
    for entry in summary_rows:
        ops = entry.get("ops") or []
        if len(ops) == 1:
            single_op_entries[ops[0]] = entry.get("op_entries") or []
    profiles = {
        entry["name"]: {
            "ops": entry.get("ops") or [],
            "op_entries": entry.get("op_entries") or [],
            "unique_entries": sorted(set(entry.get("op_entries") or [])),
        }
        for entry in summary_rows
    }
    return {"single_op_entries": single_op_entries, "profiles": profiles}


def _build_signatures(summary_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {"name": entry["name"], "entry_signatures": entry.get("entry_signatures") or {}}
        for entry in summary_rows
    ]


def _build_catalog() -> Dict[str, Any]:
    summary = _load_json(SUMMARY_PATH) or []
    op_map = _load_json(OP_MAP_PATH) or {}
    sig_list = _load_json(OP_SIG_PATH) or []
    runtime = _load_json(OP_ROOT / "out/runtime_signatures.json") or {}
    vocab_ops = _load_json(OPS_VOCAB_PATH) or {}
    ops_index = {
        entry["name"]: entry["id"]
        for entry in vocab_ops.get("ops", [])
        if isinstance(entry, dict)
    }

    map_profiles = op_map.get("profiles", {})
    runtime_profiles = runtime.get("profiles", {}) if isinstance(runtime, dict) else {}
    sig_map = {
        entry.get("name"): entry.get("entry_signatures")
        for entry in sig_list
        if isinstance(entry, dict)
    }

    records = []
    for rec in summary:
        name = rec.get("name")
        if not name:
            continue
        map_rec = map_profiles.get(name, {})
        unique_entries = sorted(set(map_rec.get("unique_entries") or []))
        op_entries = map_rec.get("op_entries") or rec.get("op_entries") or []
        decoder_signatures = sig_map.get(name)
        runtime_entry = runtime_profiles.get(name)
        op_ids = [ops_index.get(op) for op in rec.get("ops") or []]

        record = {
            "profile_id": name,
            "bucket_pattern": unique_entries,
            "op_count": rec.get("op_count"),
            "op_entries": op_entries,
            "sbpl_ops": rec.get("ops") or [],
            "op_ids": op_ids,
            "filters": rec.get("filters") or [],
            "decoder_signatures": decoder_signatures,
            "profile_path": f"sb/{name}.sb",
        }
        if runtime_entry:
            record["runtime_signature"] = runtime_entry.get("runtime_signature")
            record["runtime_provisional"] = True
        records.append(record)

    return {"schema": "op_table_catalog_v1", "records": records}


def _build_alignment(summaries: List[op_table_mod.Summary]) -> Dict[str, Any]:
    _ops_map, _ops_names, ops_vocab = _load_vocab_map(OPS_VOCAB_PATH, "ops")
    _filters_map, _filters_names, filters_vocab = _load_vocab_map(FILTERS_VOCAB_PATH, "filters")
    alignment = op_table_mod.build_alignment(summaries, ops_vocab, filters_vocab)
    alignment["source_summary"] = path_utils.to_repo_relative(SUMMARY_PATH, ROOT)
    return alignment


def main() -> int:
    summaries, summary_rows = _summarize_profiles()
    _write_json(SUMMARY_PATH, summary_rows)
    _write_json(OP_MAP_PATH, _build_op_table_map(summary_rows))
    _write_json(OP_SIG_PATH, _build_signatures(summary_rows))
    _write_json(CATALOG_PATH, _build_catalog())
    _write_json(ALIGN_PATH, _build_alignment(summaries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
