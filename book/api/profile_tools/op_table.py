"""
Op-table centric helpers (Sonoma baseline).

Consolidated home for the former `op_table` module.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import bytes_util as bu
from . import decoder as decoder
from . import ingestion as pi


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
    tokens = set()
    for line in sb_path.read_text().splitlines():
        for token in TOKEN_RE.findall(line):
            if token in SKIP_TOKENS:
                continue
            if token in filter_names:
                tokens.add(token)
    return sorted(tokens)


op_entries = bu.op_entries
tag_counts = bu.tag_counts
ascii_strings = bu.ascii_strings


def entry_signature(decoded: Dict[str, Any], entry: int, max_visits: int = 256) -> Dict[str, Any]:
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
    header_words: List[int] | None
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
    entries = bu.op_entries(blob, op_count) if op_count else []
    decoded = decoder.decode_profile_dict(blob)
    header_words = [int.from_bytes(blob[i : i + 2], "little") for i in range(0, min(len(blob), 16), 2)]
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
        header_words=header_words if header_words else None,
        op_entries=entries,
        section_lengths={
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        tag_counts_stride12={str(k): v for k, v in bu.tag_counts(sections.nodes).items()},
        remainder_stride12_hex=sections.nodes[(len(sections.nodes) // 12) * 12 :].hex(),
        literal_strings=bu.ascii_strings(sections.regex_literals),
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
    vocab_version = None
    if ops_map:
        payload = json.dumps(ops_vocab.get("ops", []), sort_keys=True).encode()
        vocab_version = hashlib.sha256(payload).hexdigest()
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
