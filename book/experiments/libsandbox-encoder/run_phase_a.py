#!/usr/bin/env python3
"""
Phase A helper for libsandbox-encoder: compile/ingest matrix_v1 and emit a field2 table.

- Uses `book.api.profile` + profile_ingestion to stay aligned with existing API surfaces.
- Parses nodes directly from the sliced node region (stride=8 for this world baseline) to avoid the literal-start
  heuristic that can collapse nodes when literals look printable.
- Emits rows with op hints, filter names/IDs, tags, field2 raw/hi/lo, and literal_refs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any, Tuple

import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile import decoder
from book.api import profile as profile_tools
from book.api.profile import ingestion as pi


def load_filters() -> Dict[int, str]:
    path = ROOT / "book/graph/mappings/vocab/filters.json"
    data = json.loads(path.read_text())
    return {entry["id"]: entry["name"] for entry in data.get("filters", [])}

def load_tag_layouts() -> Dict[int, Dict[str, Any]]:
    """
    Merge base tag layouts with local overrides. Shapes mirror decoder.DEFAULT_TAG_LAYOUTS:
    tag -> {record_size_bytes, edge_fields, payload_fields, filter_id_field?}
    """
    layouts: Dict[int, Dict[str, Any]] = {}
    # base mapping from published tag_layouts.json
    base = ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json"
    for path in [base, ROOT / "book/experiments/libsandbox-encoder/out/tag_layout_overrides.json"]:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        for entry in data.get("tags", []):
            try:
                tag = int(entry["tag"])
            except Exception:
                continue
            rec_size = int(entry.get("record_size_bytes", 8))
            edges = tuple(entry.get("edge_fields", []))
            payloads = tuple(entry.get("payload_fields", []))
            filter_id_field = entry.get("filter_id_field")
            layouts[tag] = {
                "record_size_bytes": rec_size,
                "edge_fields": edges,
                "payload_fields": payloads,
                "filter_id_field": filter_id_field,
            }
    return layouts


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def op_hint_for_filter(filter_name: str | None) -> str | None:
    if not filter_name:
        return None
    if filter_name in {"path", "mount-relative-path"}:
        return "file-read* (hint)"
    if filter_name in {"global-name", "local-name"}:
        return "mach-lookup (hint)"
    if filter_name.startswith("socket") or filter_name in {"control-name", "remote"}:
        return "network-outbound (hint)"
    if filter_name.startswith("iokit-"):
        return "iokit-open (hint)"
    return None


def parse_literals(literal_pool: bytes, literal_start: int) -> List[tuple[int, str, List[bytes]]]:
    literal_strings_with_offsets = decoder._extract_strings_with_offsets(literal_pool)
    literal_candidates: List[tuple[int, str, List[bytes]]] = []
    for idx, (off, val) in enumerate(literal_strings_with_offsets):
        abs_off = literal_start + off
        patterns = [
            off.to_bytes(2, "little"),
            abs_off.to_bytes(2, "little"),
            off.to_bytes(4, "little"),
            abs_off.to_bytes(4, "little"),
            idx.to_bytes(2, "little"),
            idx.to_bytes(4, "little"),
        ]
        literal_candidates.append((off, val, patterns))
    return literal_candidates


def attach_literal_refs(nodes: List[Dict[str, Any]], nodes_bytes: bytes, literal_pool: bytes, literal_start: int) -> None:
    literal_strings_with_offsets = decoder._extract_strings_with_offsets(literal_pool)
    literal_candidates = parse_literals(literal_pool, literal_start)
    for node in nodes:
        matches: List[str] = []
        fields = node.get("fields", [])
        rec_size = node.get("record_size", 0) or 0
        chunk = nodes_bytes[node["offset"] : node["offset"] + rec_size]
        # direct field matches against offsets/absolute offsets
        for off, val in literal_strings_with_offsets:
            abs_off = literal_start + off
            if any((f == off or f == abs_off) for f in fields):
                matches.append(val)
        # byte-scan inside the record
        for off, val, pats in literal_candidates:
            if any(pat in chunk for pat in pats):
                matches.append(val)
                continue
        node["literal_refs"] = sorted(set(matches))


def parse_nodes_with_layout(nodes_bytes: bytes, layouts: Dict[int, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[int, int], int]:
    """
    Parse nodes using per-tag record sizes when available (override if present),
    defaulting to 8-byte records. Returns (nodes, tag_counts, remainder_bytes).
    """
    nodes: List[Dict[str, Any]] = []
    tag_counts: Dict[int, int] = {}
    offset = 0
    while offset + 1 <= len(nodes_bytes):
        tag = nodes_bytes[offset]
        layout = layouts.get(tag, {})
        rec_size = layout.get("record_size_bytes", 8)
        chunk = nodes_bytes[offset : offset + rec_size]
        if len(chunk) < rec_size:
            break
        fields = [int.from_bytes(chunk[i : i + 2], "little") for i in range(2, rec_size, 2)]
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        nodes.append(
            {
                "offset": offset,
                "tag": tag,
                "fields": fields,
                "record_size": rec_size,
                "hex": chunk.hex(),
            }
        )
        offset += rec_size
    remainder = len(nodes_bytes) - offset
    return nodes, tag_counts, remainder


def build_matrix(sb_path: Path, out_blob: Path, out_json: Path) -> None:
    # Compile SBPL to blob
    res = profile_tools.compile_sbpl_file(sb_path, out_blob)
    print(f"[+] compiled {sb_path} -> {out_blob} (len={res.length}, type={res.profile_type})")

    # Slice sections conservatively
    blob = pi.ProfileBlob(bytes=out_blob.read_bytes(), source=sb_path.name)
    header = pi.parse_header(blob)
    sections = pi.slice_sections(blob, header)

    # Parse nodes directly from the sliced node region with merged tag layouts
    layouts = load_tag_layouts()
    nodes, tag_counts, rem = parse_nodes_with_layout(sections.nodes, layouts)

    literal_start = len(blob.bytes) - len(sections.regex_literals)
    attach_literal_refs(nodes, sections.nodes, sections.regex_literals, literal_start)

    filters = load_filters()
    rows: List[Dict[str, Any]] = []
    for node in nodes:
        fields = node.get("fields", [])
        if len(fields) < 3:
            continue
        tag = node.get("tag")
        layout = layouts.get(tag, {})
        rec_size = layout.get("record_size_bytes", 12)
        edge_idx = tuple(layout.get("edge_fields", (0, 1)))
        payload_idx = tuple(layout.get("payload_fields", ()))
        filter_id_field = layout.get("filter_id_field")
        # skip meta/header nodes (no payload and no filter id)
        if not payload_idx and filter_id_field is None:
            continue
        # For now, assume single payload slot; if multiple, take first
        payload_field_index = payload_idx[0] if payload_idx else None
        if payload_field_index is None or payload_field_index >= len(fields):
            field2_raw = None
            field2_hi = field2_lo = None
        else:
            field2_raw = fields[payload_field_index]
            field2_hi = field2_raw & 0xC000
            field2_lo = field2_raw & 0x3FFF
        # filter_id may come from a dedicated field or from payload_lo if no hi bits
        fid_idx = filter_id_field if filter_id_field is not None else payload_field_index
        filter_id_raw = fields[fid_idx] if fid_idx is not None and fid_idx < len(fields) else None
        filter_id_lo = filter_id_raw & 0x3FFF if filter_id_raw is not None else None
        filter_name = filters.get(filter_id_lo) if filter_id_lo is not None else None
        rows.append(
            {
                "node_offset": node.get("offset"),
                "tag": tag,
                "record_size": rec_size,
                "fields": fields,
                "op_hint": op_hint_for_filter(filter_name),
                "filter_id_raw": filter_id_raw,
                "filter_id": filter_id_lo if (filter_id_raw is not None) else None,
                "filter_name": filter_name,
                "field2_raw": field2_raw,
                "field2_hi": field2_hi,
                "field2_lo": field2_lo,
                "literal_refs": node.get("literal_refs", []),
            }
        )

    out = {
        "source": sb_path.name,
        "blob": rel(out_blob),
        "host": {
            "product": "macOS",
            "version": "14.4.1",
            "build": "23E224",
            "machine": "arm64",
        },
        "counts": {"op_count_header": header.operation_count, "node_count": len(nodes), "tag_counts": tag_counts, "remainder": rem},
        "rows": rows,
    }
    out_json.write_text(json.dumps(out, indent=2))
    print(f"[+] wrote {out_json}")


def main() -> None:
    for stem in ["matrix_v1", "matrix_v2"]:
        sb_path = ROOT / f"book/experiments/libsandbox-encoder/sb/{stem}.sb"
        if not sb_path.exists():
            continue
        out_blob = ROOT / f"book/experiments/libsandbox-encoder/out/{stem}.sb.bin"
        out_json = ROOT / f"book/experiments/libsandbox-encoder/out/{stem}_field2_encoder_matrix.json"
        build_matrix(sb_path, out_blob, out_json)


if __name__ == "__main__":
    main()
