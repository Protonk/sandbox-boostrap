"""
Best-effort decoder for modern sandbox profile blobs (Sonoma baseline).

Formerly exposed as `book.api.decoder`; promoted into `book.api.profile`.

Focuses on structure: header preamble, op-table entries, node chunks (auto-selected
framing on this host baseline), and literal/regex pool slices. This is heuristic
and intended to be version-tolerant.

How to read this module:
- `book.api.profile.ingestion` owns the *slice contract* (where op-table/nodes/literals live).
- This decoder builds on that slicing to annotate the node stream with:
  - record sizes (either forced, inferred, or tag-layout-driven),
  - tag counts and simple edge sanity checks,
  - “literal reference” hints by matching node fields against the literal pool.

Evidence tiering (important):
- The goal is to expose *structural evidence* from bytes, not kernel semantics.
- When this decoder uses published mappings (e.g. `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`,
  `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_u16_roles.json`, `book/integration/carton/bundle/relationships/mappings/vocab/filters.json`),
  treat those annotations as “mapped” evidence.
- When it falls back to built-in defaults or heuristics (stride selection, literal refs),
  treat output as “hypothesis” and corroborate with experiments / validation fixtures.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Sequence

from book.api.path_utils import find_repo_root

from .. import ingestion as pi

PRINTABLE = set(bytes(string.printable, "ascii"))
# `PRINTABLE` is used for *heuristic* string extraction only. The literal pool
# contains binary regex programs as well as C-string-like tokens; we use
# printable runs to help humans orient themselves.

# Heuristic: op_table and branch offsets are stored as u16 word offsets
# (8-byte units) into the node stream on this host baseline. This is treated
# as format evidence, not a cross-version guarantee.
WORD_OFFSET_BYTES = 8
# Built-in fallback tag layout hints.
#
# The authoritative tag layouts for this world live under:
# `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`.
# These defaults exist to keep the decoder usable when mappings are absent or
# when you're decoding a blob in isolation.
#
# Shape: tag -> (record_size_bytes, edge_field_indices, payload_field_indices)
DEFAULT_TAG_LAYOUTS: Dict[int, Tuple[int, Tuple[int, ...], Tuple[int, ...]]] = {
    # Tentative assumptions; a richer decoder should update these.
    5: (12, (0, 1), (2,)),
    6: (12, (0, 1), (2,)),
}

ROLE_UNKNOWN = "unknown_role"


def _ascii_byte(b: int) -> bool:
    return 32 <= b <= 126


def _score_scaled_targets_as_headers(
    data: bytes,
    nodes_start: int,
    u16_values: Sequence[int],
    *,
    scale_bytes: int,
    known_tags: set[int],
) -> Dict[str, Any]:
    """
    Score u16 values as potential offsets into the node stream.

    This is format-heuristic evidence, not a proof: it is intended to catch
    obvious mis-scaling (e.g., treating u16 offsets as 12-byte record indices,
    leading to ASCII-looking starts like 'lt').
    """
    total = 0
    in_range = 0
    ascii_pairs = 0
    kind0 = 0
    plausible_non_ascii_kind0 = 0
    plausible_known_kind0 = 0
    pair_hist: Dict[str, int] = {}

    for v in u16_values:
        total += 1
        abs_off = nodes_start + int(v) * scale_bytes
        if abs_off + 2 > len(data):
            continue
        in_range += 1
        tag = data[abs_off]
        kind = data[abs_off + 1]
        pair_hist[str((tag, kind))] = pair_hist.get(str((tag, kind)), 0) + 1
        ascii_tag = _ascii_byte(tag)
        ascii_kind = _ascii_byte(kind)
        if ascii_tag and ascii_kind:
            ascii_pairs += 1
        if kind == 0:
            kind0 += 1
            if not ascii_tag:
                plausible_non_ascii_kind0 += 1
            if tag in known_tags:
                plausible_known_kind0 += 1

    top_pairs = [
        {"key": k, "count": v}
        for k, v in sorted(pair_hist.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
    ]
    return {
        "scale_bytes": scale_bytes,
        "total": total,
        "in_range": in_range,
        "ascii_pair_count": ascii_pairs,
        "kind0_count": kind0,
        "plausible_non_ascii_kind0_count": plausible_non_ascii_kind0,
        "plausible_known_kind0_count": plausible_known_kind0,
        "top_tag_kind_pairs": top_pairs,
    }


def _load_filter_vocab() -> Dict[int, str]:
    """Load filter vocabulary id->name from the published mapping if present."""
    try:
        root = find_repo_root(Path(__file__))
    except Exception:
        return {}
    path = root / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "filters.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    out: Dict[int, str] = {}
    entries = data.get("filters", []) if isinstance(data, dict) else data
    for entry in entries or []:
        try:
            out[int(entry["id"])] = str(entry["name"])
        except Exception:
            continue
    return out


def _load_tag_u16_roles() -> Dict[int, str]:
    """Load per-tag u16 role mapping if available."""
    try:
        root = find_repo_root(Path(__file__))
    except Exception:
        return {}
    path = root / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "tag_layouts" / "tag_u16_roles.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    out: Dict[int, str] = {}
    for entry in data.get("roles", []):
        try:
            out[int(entry["tag"])] = str(entry["u16_role"])
        except Exception:
            continue
    return out


@dataclass
class DecodedProfile:
    """
    Best-effort decoded view of a compiled sandbox profile blob.

    This object is intentionally “wide”:
    - Some fields are direct byte-derived facts (e.g. `preamble_words_full`, `op_table`).
    - Some fields are annotations derived from heuristics or mappings (e.g. per-node `u16_role`,
      `literal_refs`, stride selection metadata).

    If you need a JSON-only structure (for logs, IR, digests), use
    `decode_profile_dict`.
    """

    format_variant: str
    preamble_words: List[int]
    preamble_words_full: List[int]
    header_bytes: bytes
    op_count: Optional[int]
    op_table_offset: int
    op_table: List[int]
    nodes: List[Dict[str, Any]]
    node_count: int
    tag_counts: Dict[str, int]
    literal_pool: bytes
    literal_strings: List[str]
    literal_strings_with_offsets: List[Tuple[int, str]]
    sections: Dict[str, int]
    validation: Dict[str, Any]
    header_fields: Dict[str, Any]


def _read_words(data: bytes, byte_len: int) -> List[int]:
    """Read little-endian u16 words from the start of `data` up to `byte_len`."""
    words = []
    for i in range(0, min(len(data), byte_len), 2):
        words.append(int.from_bytes(data[i : i + 2], "little"))
    return words


def _guess_op_count(words: List[int]) -> Optional[int]:
    """
    Guess operation count from preamble words.

    On this world baseline, the second u16 of the 16-byte preamble frequently
    matches the op-table entry count.
    """
    if len(words) < 2:
        return None
    maybe = words[1]
    if 0 < maybe < 4096:
        return maybe
    return None


def _node_stride_alignment_metrics(op_table: Sequence[int], stride_bytes: int) -> Dict[str, Any]:
    """
    Score whether op_table targets (treated as WORD_OFFSET_BYTES offsets) align
    to candidate node record boundaries.
    """
    total = len(op_table)
    misaligned = 0
    for v in op_table:
        try:
            off = int(v) * WORD_OFFSET_BYTES
        except Exception:
            continue
        if stride_bytes <= 0:
            misaligned += 1
            continue
        if off % stride_bytes != 0:
            misaligned += 1
    return {"stride_bytes": stride_bytes, "op_table_entries": total, "misaligned_targets": misaligned}


def _select_node_stride_bytes(op_table: Sequence[int]) -> Tuple[Optional[int], Dict[str, Any]]:
    """
    Select a node record stride for this blob from format-local evidence.

    The primary witness is op-table alignment under the assumption that op_table
    entries are WORD_OFFSET_BYTES word offsets into the node stream. For this
    Sonoma world, stride=8 is the best-supported framing; when evidence is
    ambiguous, we fall back to the historical tag-layout-driven parse.
    """
    if not op_table:
        return None, {"mode": "tag-layout", "reason": "empty op_table"}

    candidates = [8, 12]
    metrics = {str(s): _node_stride_alignment_metrics(op_table, s) for s in candidates}
    best = min(candidates, key=lambda s: (metrics[str(s)]["misaligned_targets"], s))
    if metrics[str(best)]["misaligned_targets"] == 0:
        return best, {"mode": "auto", "selected": best, "metrics": metrics}
    # If nothing aligns cleanly, do not guess: keep the historical path.
    return None, {"mode": "tag-layout", "reason": "no clean alignment", "metrics": metrics}


def _parse_op_table(data: bytes) -> List[int]:
    """Parse a u16 op-table byte region into integer entries."""
    return [int.from_bytes(data[i : i + 2], "little") for i in range(0, len(data), 2)]


def _load_external_tag_layouts() -> Dict[int, Tuple[int, Tuple[int, ...], Tuple[int, ...]]]:
    """
    Optionally merge in tag layout hints from stable mappings or experiments.

    Priority: published mapping under book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json,
    then experimental assumptions under probe-op-structure. If none found, fall
    back to the built-in defaults. Keys are tag ints; values mirror DEFAULT_TAG_LAYOUTS.
    """
    try:
        root = find_repo_root(Path(__file__))
    except Exception:
        return {}
    candidates = [
        root / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "tag_layouts" / "tag_layouts.json",
        root / "book" / "evidence" / "experiments" / "probe-op-structure" / "out" / "tag_layout_assumptions.json",
    ]
    data = None
    for path in candidates:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
            break
        except Exception:
            continue
    if not data:
        return {}
    out: Dict[int, Tuple[int, Tuple[int, ...], Tuple[int, ...]]] = {}
    for entry in data.get("tags", []):
        try:
            tag = int(entry["tag"])
        except Exception:
            continue
        rec_size = int(entry.get("record_size_bytes", 12))
        edges = tuple(entry.get("edge_fields", []))
        payloads = tuple(entry.get("payload_fields", []))
        out[tag] = (rec_size, edges, payloads)
    return out


def _parse_nodes_tagged(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[int, int], int]:
    """
    Parse nodes using per-tag record sizes when available, defaulting to 12-byte
    records. Returns (nodes, tag_counts, remainder_bytes).
    """
    tag_layouts = {**DEFAULT_TAG_LAYOUTS, **_load_external_tag_layouts()}
    tag_roles = _load_tag_u16_roles()
    filter_vocab = _load_filter_vocab()
    nodes: List[Dict[str, Any]] = []
    tag_counts: Dict[int, int] = {}

    offset = 0
    while offset + 2 <= len(data):
        tag = data[offset]
        layout_source = "mapping" if tag in tag_layouts else "default"
        rec_size, edge_idx, payload_idx = tag_layouts.get(tag, (12, (0, 1), (2,)))
        chunk = data[offset : offset + rec_size]
        if len(chunk) < rec_size:
            break
        fields = [int.from_bytes(chunk[i : i + 2], "little") for i in range(2, rec_size, 2)]
        tag_counts[tag] = tag_counts.get(tag, 0) + 1

        payload_values = [fields[i] for i in payload_idx if i < len(fields)] if payload_idx else []
        filter_arg_raw: Optional[int | List[int]] = None
        if payload_values:
            filter_arg_raw = payload_values[0] if len(payload_values) == 1 else payload_values

        u16_role = tag_roles.get(tag, ROLE_UNKNOWN)
        filter_vocab_ref: Optional[str] = None
        out_of_vocab = False
        if u16_role == "filter_vocab_id" and payload_values:
            val = payload_values[0]
            if val in filter_vocab:
                filter_vocab_ref = filter_vocab[val]
            else:
                out_of_vocab = True

        nodes.append(
            {
                "offset": offset,
                "tag": tag,
                "fields": fields,
                "record_size": rec_size,
                "hex": chunk.hex(),
                "layout_provenance": layout_source,
                "payload_indices": payload_idx,
                "filter_arg_raw": filter_arg_raw,
                "u16_role": u16_role,
                "filter_vocab_ref": filter_vocab_ref,
                "filter_out_of_vocab": out_of_vocab,
            }
        )
        offset += rec_size

    remainder = len(data) - offset
    return nodes, tag_counts, remainder


def _parse_nodes_fixed_stride(
    data: bytes, stride_bytes: int
) -> Tuple[List[Dict[str, Any]], Dict[int, int], int]:
    """
    Parse nodes as fixed-size records (e.g., 8-byte records: tag,u8 + 3*u16).

    This mode ignores per-tag record_size_bytes from mappings; it still consumes
    edge/payload indices from the tag-layout mapping when available so that
    payload/u16-role annotations remain consistent.
    """
    if stride_bytes < 4 or stride_bytes % 2 != 0:
        raise ValueError(f"invalid node stride {stride_bytes} (expected even >=4)")

    tag_layouts = {**DEFAULT_TAG_LAYOUTS, **_load_external_tag_layouts()}
    tag_roles = _load_tag_u16_roles()
    filter_vocab = _load_filter_vocab()
    nodes: List[Dict[str, Any]] = []
    tag_counts: Dict[int, int] = {}

    offset = 0
    while offset + stride_bytes <= len(data):
        tag = data[offset]
        layout_source = "mapping" if tag in tag_layouts else "default"
        _mapped_size, edge_idx, payload_idx = tag_layouts.get(tag, (stride_bytes, (0, 1), (2,)))
        chunk = data[offset : offset + stride_bytes]
        fields = [
            int.from_bytes(chunk[i : i + 2], "little") for i in range(2, stride_bytes, 2)
        ]
        tag_counts[tag] = tag_counts.get(tag, 0) + 1

        payload_values = [fields[i] for i in payload_idx if i < len(fields)] if payload_idx else []
        filter_arg_raw: Optional[int | List[int]] = None
        if payload_values:
            filter_arg_raw = payload_values[0] if len(payload_values) == 1 else payload_values

        u16_role = tag_roles.get(tag, ROLE_UNKNOWN)
        filter_vocab_ref: Optional[str] = None
        out_of_vocab = False
        if u16_role == "filter_vocab_id" and payload_values:
            val = payload_values[0]
            if val in filter_vocab:
                filter_vocab_ref = filter_vocab[val]
            else:
                out_of_vocab = True

        nodes.append(
            {
                "offset": offset,
                "tag": tag,
                "fields": fields,
                "record_size": stride_bytes,
                "hex": chunk.hex(),
                "layout_provenance": layout_source,
                "payload_indices": payload_idx,
                "filter_arg_raw": filter_arg_raw,
                "u16_role": u16_role,
                "filter_vocab_ref": filter_vocab_ref,
                "filter_out_of_vocab": out_of_vocab,
            }
        )
        offset += stride_bytes

    remainder = len(data) - offset
    return nodes, tag_counts, remainder


def _extract_strings_with_offsets(buf: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """Pull out printable runs with offsets; simple heuristic to aid orientation."""
    out: List[Tuple[int, str]] = []
    cur: List[int] = []
    start = None
    for idx, b in enumerate(buf):
        if b in PRINTABLE and b != 0x00:
            if start is None:
                start = idx
            cur.append(b)
        else:
            if len(cur) >= min_len and start is not None:
                out.append((start, bytes(cur).decode("ascii", errors="ignore")))
            cur = []
            start = None
    if len(cur) >= min_len and start is not None:
        out.append((start, bytes(cur).decode("ascii", errors="ignore")))
    return out


def decode_profile(
    data: bytes, header_window: int = 128, node_stride_bytes: Optional[int] = None
) -> DecodedProfile:
    """
    Heuristic decoder for modern compiled sandbox blobs: slices the preamble,
    op-table, node region, and literal pool, then annotates nodes using any
    known tag layouts (mappings/experiments) to give a PolicyGraph-shaped view.

    Args:
        data: Compiled blob bytes (typically `.sb.bin`).
        header_window: Number of bytes to capture as "header bytes" for debugging.
        node_stride_bytes: Optional forced node record stride. When omitted, the
            decoder will attempt to infer a stride from op-table alignment and
            otherwise fall back to tag-layout parsing.

    Returns:
        A `DecodedProfile` that mirrors the substrate story (preamble fields,
        op_table entries, node tags/edges/payloads, literal pool slices) without
        asserting correctness beyond the light validation included here.
    """
    preamble = _read_words(data, 16)
    preamble_full = _read_words(data, header_window)
    header_bytes = data[:header_window]
    op_count = _guess_op_count(preamble)

    profile = pi.ProfileBlob(bytes=data, source="decoder")
    header = pi.parse_header(profile)
    if header.format_variant != "legacy-decision-tree":
        # For modern blobs, prefer the op_count guessed from the 16-byte preamble.
        # This keeps decoder behavior consistent even when ingestion heuristics
        # are conservative (e.g., when op_count is absent or implausible).
        header.operation_count = op_count
    sections, offsets = pi.slice_sections_with_offsets(profile, header)

    op_table_bytes = sections.op_table
    op_table = _parse_op_table(op_table_bytes)

    nodes_start = offsets.nodes_start
    stride_selection: Dict[str, Any] = {}
    selected_stride = node_stride_bytes
    if selected_stride is None:
        selected_stride, stride_selection = _select_node_stride_bytes(op_table)
    else:
        # Caller-forced stride is primarily used for cross-checking and when
        # debugging framing mismatches between experiments and mappings.
        stride_selection = {"mode": "forced", "selected": selected_stride}

    literal_start = offsets.literal_start
    nodes_bytes = sections.nodes
    literal_pool = sections.regex_literals

    merged_layouts = {**DEFAULT_TAG_LAYOUTS, **_load_external_tag_layouts()}
    known_tags = set(merged_layouts.keys())
    op_table_scaling_witness = {
        "scale8": _score_scaled_targets_as_headers(
            data, nodes_start, op_table, scale_bytes=8, known_tags=known_tags
        ),
        "scale12": _score_scaled_targets_as_headers(
            data, nodes_start, op_table, scale_bytes=12, known_tags=known_tags
        ),
        "notes": "Scores op_table entries as offsets into the node stream under different scale factors; ASCII-heavy scale12 is a strong sign of mis-scaling.",
    }

    if selected_stride is None:
        # Tag-layout-driven parse: supports heterogeneous record sizes per tag.
        nodes, tag_counts, node_remainder = _parse_nodes_tagged(nodes_bytes)
    else:
        # Fixed-stride parse: treat nodes as uniform record sizes. This is
        # useful when we believe the blob is uniformly packed (common for
        # record8-heavy specimens).
        nodes, tag_counts, node_remainder = _parse_nodes_fixed_stride(nodes_bytes, selected_stride)

    # Sanity: treat first two fields as edges and count in-bounds hits.
    edge_total = 0
    edge_in_bounds = 0
    for node in nodes:
        edges = node.get("fields", [])[:2]
        edge_total += len(edges)
        edge_in_bounds += sum(1 for e in edges if 0 <= e < len(nodes))

    # Tag-aware validation: check candidate layouts for selected tags.
    literal_strings_with_offsets = _extract_strings_with_offsets(literal_pool)
    literal_count = len(literal_strings_with_offsets)
    tag_validation: Dict[str, Any] = {}
    # Tag-aware validation based on merged layouts
    for node in nodes:
        tag = node.get("tag")
        if tag not in merged_layouts:
            continue
        rec_size, edge_idx, payload_idx = merged_layouts[tag]
        if node.get("record_size") != rec_size:
            continue
        fields = node.get("fields", [])
        edges = [fields[i] for i in edge_idx if i < len(fields)]
        payloads = [fields[i] for i in payload_idx if i < len(fields)]
        tv = tag_validation.setdefault(
            str(tag), {"edge_in_bounds": 0, "edge_total": 0, "payloads": {}, "record_size": rec_size}
        )
        tv["edge_total"] += len(edges)
        tv["edge_in_bounds"] += sum(1 for e in edges if 0 <= e < len(nodes))
        for p in payloads:
            tv["payloads"][str(p)] = tv["payloads"].get(str(p), 0) + 1

    # Heuristic literal references: match node fields to literal offsets, absolute offsets, or string indices.
    #
    # This is intentionally a “hint” layer. Many values in the node stream are
    # small integers that can coincide with literal offsets by accident; treat
    # results as hypothesis unless corroborated by an experiment that shows the
    # same value influencing a literal under controlled SBPL variation.
    literal_refs_per_node: List[List[str]] = []
    literal_candidates: List[Tuple[str, List[bytes]]] = []
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
        literal_candidates.append((val, patterns))
    for node in nodes:
        matches: List[str] = []
        fields = node.get("fields", [])
        # field-based matching (u16 payloads)
        for off, val in literal_strings_with_offsets:
            abs_off = literal_start + off
            if any((f == off or f == abs_off) for f in fields):
                matches.append(val)
        # byte-scan matching inside the record
        try:
            rec_size = node.get("record_size", 0) or 0
            chunk = nodes_bytes[node["offset"] : node["offset"] + rec_size]
        except Exception:
            chunk = b""
        if chunk:
            for val, pats in literal_candidates:
                for pat in pats:
                    if pat in chunk:
                        matches.append(val)
                        break
        literal_refs_per_node.append(sorted(set(matches)))
    for node, refs in zip(nodes, literal_refs_per_node):
        node["literal_refs"] = refs
        node["literal_refs_provenance"] = "heuristic" if refs else "none"

    header_fields: Dict[str, Any] = {}
    try:
        # Basic header fields
        header_fields = {
            "magic": preamble_full[2] if len(preamble_full) > 2 else None,
            "op_count_word": preamble_full[1] if len(preamble_full) > 1 else None,
            "maybe_flags": preamble_full[0] if preamble_full else None,
            "unknown_words": [
                {"index": i, "value": w} for i, w in enumerate(preamble_full[3:], start=3)
            ]
            if len(preamble_full) > 3
            else [],
        }
        # Heuristic profile_class: look for small ints near the start of the header and within the first header_window.
        profile_class = None
        for idx in range(0, min(len(preamble_full), header_window // 2)):
            val = preamble_full[idx]
            if val in (0, 1, 2, 3):
                profile_class = val
                header_fields["profile_class_word_index"] = idx
                break
        header_fields["profile_class"] = profile_class
    except Exception:
        header_fields = {}

    decoded = DecodedProfile(
        format_variant=header.format_variant,
        preamble_words=preamble,
        preamble_words_full=preamble_full,
        header_bytes=header_bytes,
        op_count=op_count,
        op_table_offset=offsets.op_table_start,
        op_table=op_table,
        nodes=nodes,
        node_count=len(nodes),
        tag_counts={str(k): v for k, v in tag_counts.items()},
        literal_pool=literal_pool,
        literal_strings=[s for _, s in literal_strings_with_offsets],
        literal_strings_with_offsets=literal_strings_with_offsets,
        sections={
            "op_table": len(op_table_bytes),
            "nodes": len(nodes_bytes),
            "literal_pool": len(literal_pool),
            "nodes_start": offsets.nodes_start,
            "literal_start": offsets.literal_start,
        },
        validation={
            "node_remainder_bytes": node_remainder,
            "edge_fields_in_bounds": edge_in_bounds,
            "edge_fields_total": edge_total,
            "nodes_start": offsets.nodes_start,
            "literal_start": offsets.literal_start,
            "node_stride_bytes": selected_stride,
            "node_stride_selection": stride_selection,
            "tag_validation": tag_validation,
            "op_table_scaling_witness": op_table_scaling_witness,
        },
        header_fields=header_fields,
    )
    return decoded


def decode_profile_dict(data: bytes, node_stride_bytes: Optional[int] = None) -> Dict[str, Any]:
    """
    JSON-safe wrapper around `decode_profile`.

    This function intentionally mirrors the historical `book.api.decoder` output
    shape used by experiments and validation jobs:
    - bytes are serialized as hex strings,
    - dataclass objects are flattened to dicts/lists,
    - only “portable” fields are included.

    If you are building new code and do not need JSON, prefer `decode_profile`
    and the `DecodedProfile` dataclass.
    """
    d = decode_profile(data, node_stride_bytes=node_stride_bytes)
    return {
        "format_variant": d.format_variant,
        "preamble_words": d.preamble_words,
        "preamble_words_full": d.preamble_words_full,
        "header_bytes": d.header_bytes.hex(),
        "op_count": d.op_count,
        "op_table_offset": d.op_table_offset,
        "op_table": d.op_table,
        "nodes": d.nodes,
        "node_count": d.node_count,
        "tag_counts": d.tag_counts,
        "literal_strings": d.literal_strings,
        "literal_strings_with_offsets": d.literal_strings_with_offsets,
        "sections": d.sections,
        "validation": getattr(d, "validation", {}),
        "header_fields": getattr(d, "header_fields", {}),
    }
