#!/usr/bin/env python3
"""
Compile+ingest the libsandbox-encoder Phase A network specimen set.

This script exists to create byte-level witnesses for how libsandbox emits network
argument bytes (domain/type/proto) into a compiled profile blob, without making
kernel-semantic claims.

Outputs (under `out/network_matrix/`):
- `index.json`: per-spec metadata and section boundaries.
- `node_records.jsonl`: joinable per-record node stream samples keyed by `spec_id`.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile import compile_sbpl_file
from book.api.profile import ingestion as pi


@dataclass(frozen=True)
class SpecCase:
    spec_id: str
    sbpl_file: Path


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def load_manifest(path: Path) -> Tuple[str, List[SpecCase], List[Dict[str, Any]]]:
    data = json.loads(path.read_text())
    world_id = data.get("world_id")
    cases: List[SpecCase] = []
    for entry in data.get("cases", []):
        spec_id = entry["spec_id"]
        sbpl_file = path.parent / entry["sbpl_file"]
        cases.append(SpecCase(spec_id=spec_id, sbpl_file=sbpl_file))
    return world_id, cases, data.get("diff_pairs", [])


def load_tag_layouts() -> Dict[int, Dict[str, Any]]:
    """
    Merge world-scoped tag layouts with experiment-local overrides.

    Shape mirrors `decoder.DEFAULT_TAG_LAYOUTS`:
    tag -> {record_size_bytes, edge_fields, payload_fields, filter_id_field?}
    """
    layouts: Dict[int, Dict[str, Any]] = {}
    base = ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"
    overrides = ROOT / "book/experiments/libsandbox-encoder/out/tag_layout_overrides.json"
    for src in [base, overrides]:
        if not src.exists():
            continue
        data = json.loads(src.read_text())
        for entry in data.get("tags", []):
            try:
                tag = int(entry["tag"])
            except Exception:
                continue
            layouts[tag] = {
                "record_size_bytes": int(entry.get("record_size_bytes", 8)),
                "edge_fields": tuple(entry.get("edge_fields", [])),
                "payload_fields": tuple(entry.get("payload_fields", [])),
                "filter_id_field": entry.get("filter_id_field"),
            }
    return layouts


def parse_nodes(nodes_bytes: bytes, layouts: Dict[int, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[int, int], int]:
    nodes: List[Dict[str, Any]] = []
    tag_counts: Dict[int, int] = {}
    offset = 0
    while offset + 1 <= len(nodes_bytes):
        tag = nodes_bytes[offset]
        kind = nodes_bytes[offset + 1] if offset + 2 <= len(nodes_bytes) else None
        rec_size = int(layouts.get(tag, {}).get("record_size_bytes", 8))
        chunk = nodes_bytes[offset : offset + rec_size]
        if len(chunk) < rec_size:
            break
        fields = [int.from_bytes(chunk[i : i + 2], "little") for i in range(2, rec_size, 2)]
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        nodes.append(
            {
                "node_offset": offset,
                "tag": tag,
                "kind": kind,
                "record_size": rec_size,
                "fields": fields,
                "raw_bytes_hex": chunk.hex(),
            }
        )
        offset += rec_size
    remainder = len(nodes_bytes) - offset
    return nodes, tag_counts, remainder


def u16_list(buf: bytes) -> List[int]:
    return [int.from_bytes(buf[i : i + 2], "little") for i in range(0, len(buf), 2)]


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def main() -> None:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    manifest_path = ROOT / "book/experiments/libsandbox-encoder/sb/network_matrix/MANIFEST.json"
    world_id, cases, diff_pairs = load_manifest(manifest_path)
    layouts = load_tag_layouts()

    out_dir = ROOT / "book/experiments/libsandbox-encoder/out/network_matrix"
    out_dir.mkdir(parents=True, exist_ok=True)

    node_records_path = out_dir / "node_records.jsonl"
    index_path = out_dir / "index.json"

    all_node_rows: List[Dict[str, Any]] = []
    index_cases: List[Dict[str, Any]] = []

    for case in cases:
        out_blob = out_dir / f"{case.spec_id}.sb.bin"
        res = compile_sbpl_file(case.sbpl_file, out_blob)

        blob = pi.ProfileBlob(bytes=out_blob.read_bytes(), source=case.sbpl_file.name)
        header = pi.parse_header(blob)
        sections = pi.slice_sections(blob, header)

        op_entries = u16_list(sections.op_table)
        nodes_start = 16 + len(sections.op_table)
        literal_start = len(blob.bytes) - len(sections.regex_literals)

        nodes, tag_counts, remainder = parse_nodes(sections.nodes, layouts)

        # index entry
        header_words = [int.from_bytes(blob.bytes[i : i + 2], "little") for i in range(0, 16, 2)] if len(blob.bytes) >= 16 else []
        index_cases.append(
            {
                "spec_id": case.spec_id,
                "sbpl": rel(case.sbpl_file),
                "blob": rel(out_blob),
                "compile": {"length": res.length, "profile_type": res.profile_type},
                "header": {
                    "format_variant": header.format_variant,
                    "op_count": header.operation_count,
                    "words16_u16le": header_words,
                },
                "sections": {
                    "preamble_len": 16,
                    "op_table": {"start": 16, "len": len(sections.op_table), "end": nodes_start},
                    "nodes": {"start": nodes_start, "len": len(sections.nodes), "end": literal_start, "remainder_after_parse": remainder},
                    "literal_pool": {"start": literal_start, "len": len(sections.regex_literals), "end": len(blob.bytes)},
                },
                "op_entries_u16": op_entries,
                "tag_counts": {str(k): v for k, v in sorted(tag_counts.items())},
                "record_count": len(nodes),
            }
        )

        # node record rows
        for idx, node in enumerate(nodes):
            tag = node["tag"]
            layout = layouts.get(tag, {})
            all_node_rows.append(
                {
                    "spec_id": case.spec_id,
                    "node_index": idx,
                    "node_offset": node["node_offset"],
                    "blob_offset": nodes_start + node["node_offset"],
                    "tag": tag,
                    "kind": node["kind"],
                    "record_size": node["record_size"],
                    "fields_u16": node["fields"],
                    "layout": {
                        "edge_fields": list(layout.get("edge_fields", ())),
                        "payload_fields": list(layout.get("payload_fields", ())),
                        "filter_id_field": layout.get("filter_id_field"),
                    },
                    "raw_bytes_hex": node["raw_bytes_hex"],
                }
            )

    write_jsonl(node_records_path, all_node_rows)
    index = {
        "world_id": world_id,
        "manifest": rel(manifest_path),
        "outputs": {"index": rel(index_path), "node_records": rel(node_records_path)},
        "diff_pairs": diff_pairs,
        "cases": index_cases,
    }
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True))

    print(f"[+] wrote {index_path}")
    print(f"[+] wrote {node_records_path} ({len(all_node_rows)} rows)")


if __name__ == "__main__":
    main()
