"""
Op-table and entry-signature helpers for compiled sandbox profiles.

Scope:
- Parse op-table entries, tags, literals, and entry signatures from blobs on the Sonoma baseline.
- Optional SBPL parsing (allow ops/filters) to tie summaries back to source.
- Optional vocab alignment using book/graph/mappings/vocab/{ops,filters}.json.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import book.api.decoder as decoder
from book.graph.concepts.validation import profile_ingestion as pi


ALLOW_RE = re.compile(r"^\(allow\s+([^\s)]+)")
TOKEN_RE = re.compile(r"\(([\w*-]+)")
SKIP_TOKENS = {"allow", "deny", "version", "default", "param", "require-any", "require-all", "require-not"}


def parse_ops(sb_path: Path) -> List[str]:
    """Extract allowed operation names from a tiny SBPL file."""
    ops: List[str] = []
    for line in sb_path.read_text().splitlines():
        m = ALLOW_RE.match(line.strip())
        if m:
            ops.append(m.group(1))
    return ops


def parse_filters(sb_path: Path, filter_names: set[str]) -> List[str]:
    """
    Extract filter symbols present in SBPL by tokenizing paren-delimited atoms
    and intersecting with the known filter vocabulary. Simple but sufficient
    for small synthetic variants.
    """
    tokens = set()
    for line in sb_path.read_text().splitlines():
        for token in TOKEN_RE.findall(line):
            if token in SKIP_TOKENS:
                continue
            if token in filter_names:
                tokens.add(token)
    return sorted(tokens)


def op_entries(blob: bytes, op_count: int) -> List[int]:
    ops = blob[16 : 16 + op_count * 2]
    return [int.from_bytes(ops[i : i + 2], "little") for i in range(0, len(ops), 2)]


def tag_counts(nodes: bytes, stride: int = 12) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    recs = len(nodes) // stride
    for idx in range(recs):
        rec = nodes[idx * stride : (idx + 1) * stride]
        tag = rec[0]
        counts[tag] = counts.get(tag, 0) + 1
    return counts


def ascii_strings(buf: bytes, min_len: int = 4) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    start = None
    current: List[str] = []
    for idx, byte in enumerate(buf):
        if 0x20 <= byte < 0x7F:
            if start is None:
                start = idx
            current.append(chr(byte))
        else:
            if current and len(current) >= min_len and start is not None:
                runs.append({"offset": start, "string": "".join(current)})
            start = None
            current = []
    if current and len(current) >= min_len and start is not None:
        runs.append({"offset": start, "string": "".join(current)})
    return runs


def entry_signature(decoded: Dict[str, Any], entry: int, max_visits: int = 256) -> Dict[str, Any]:
    """
    Walk the graph from a given op-table entry index and collect a small
    structural signature (tags, literal-ish field values, visited count).
    Edges are interpreted as the first two fields in each 12-byte node record.
    """
    nodes = decoded.get("nodes") or []
    if entry >= len(nodes):
        return {"entry": entry, "error": "out_of_range", "reachable": 0}

    visited = set()
    stack = [entry]
    tags = set()
    literals = set()
    truncated = False

    while stack:
        idx = stack.pop()
        if idx in visited or idx >= len(nodes):
            continue
        visited.add(idx)
        node = nodes[idx]
        fields = node.get("fields", [])
        tags.add(node.get("tag"))
        if len(fields) > 2:
            literals.add(fields[2])
        for edge in fields[:2]:
            if 0 <= edge < len(nodes) and edge not in visited:
                stack.append(edge)
        if len(visited) >= max_visits:
            truncated = True
            break

    return {
        "entry": entry,
        "reachable": len(visited),
        "tags": sorted(t for t in tags if t is not None),
        "literals": sorted(literals),
        "truncated": truncated,
    }


@dataclass
class Summary:
    name: str
    ops: List[str]
    filters: List[str]
    filter_ids: List[int]
    length: int
    format_variant: str | None
    op_count: int
    op_count_source: str
    op_entries: List[int]
    section_lengths: Dict[str, int]
    tag_counts_stride12: Dict[str, int]
    remainder_stride12_hex: str
    literal_strings: List[Dict[str, Any]]
    decoder: Dict[str, Any]
    entry_signatures: Dict[str, Any]


def summarize_profile(
    name: str,
    blob: bytes,
    ops: List[str],
    filters: List[str],
    op_count_override: Optional[int] = None,
    filter_map: Optional[Dict[str, int]] = None,
) -> Summary:
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=name))
    if op_count_override:
        header.operation_count = op_count_override
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=name), header)
    op_count = header.operation_count or 0
    entries = op_entries(blob, op_count) if op_count else []
    decoded = decoder.decode_profile_dict(blob)
    entry_sigs = {str(e): entry_signature(decoded, e) for e in sorted(set(entries))}
    return Summary(
        name=name,
        ops=ops,
        filters=filters,
        filter_ids=[filter_map.get(f) for f in filters] if filter_map else [],
        length=len(blob),
        format_variant=header.format_variant,
        op_count=op_count,
        op_count_source="override" if op_count_override else "header",
        op_entries=entries,
        section_lengths={
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        tag_counts_stride12={str(k): v for k, v in tag_counts(sections.nodes).items()},
        remainder_stride12_hex=sections.nodes[(len(sections.nodes) // 12) * 12 :].hex(),
        literal_strings=ascii_strings(sections.regex_literals),
        decoder={
            "format_variant": decoded.get("format_variant"),
            "op_count": decoded.get("op_count"),
            "op_table_offset": decoded.get("op_table_offset"),
            "node_count": decoded.get("node_count"),
            "tag_counts": decoded.get("tag_counts"),
            "literal_strings": decoded.get("literal_strings"),
            "sections": decoded.get("sections"),
        },
        entry_signatures=entry_sigs,
    )


def build_alignment(
    summaries: Sequence[Summary],
    ops_vocab: Dict[str, Any],
    filters_vocab: Dict[str, Any],
) -> Dict[str, Any]:
    ops_map = {entry["name"]: entry["id"] for entry in ops_vocab.get("ops", [])}
    filters_map = {entry["name"]: entry["id"] for entry in filters_vocab.get("filters", [])}
    vocab_version = ops_vocab.get("generated_at")
    records = []
    for s in summaries:
        op_ids = [ops_map.get(op) for op in s.ops]
        filter_ids = [filters_map.get(f) for f in s.filters]
        records.append(
            {
                "profile": s.name,
                "ops": s.ops,
                "filters": s.filters,
                "operation_ids": op_ids,
                "filter_ids": filter_ids,
                "op_entries": s.op_entries,
                "op_count": len(s.op_entries),
                "vocab_version": vocab_version,
            }
        )

    return {
        "records": records,
        "vocab_present": bool(ops_map),
        "vocab_status": "ok" if ops_map else "missing",
        "vocab_version": vocab_version,
        "filter_vocab_present": bool(filters_map),
    }


def load_vocab(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())
