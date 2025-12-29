#!/usr/bin/env python3
"""
Compile SBPL variants under sb/ and emit op-table centric summaries.

Outputs:
- sb/build/*.sb.bin (compiled blobs via libsandbox)
- out/summary.json (per-profile metadata: ops, op_count, op_entries, section lengths, tag counts, literals)
- out/op_table_map.json (single-op entry hints + per-profile op_entries)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile import decoder
from book.api.profile import compile as profile_compile
from book.api.profile import ingestion as pi


def compile_sbpl(src: Path, out: Path) -> bytes:
    """Compile SBPL via libsandbox and write the blob."""
    return profile_compile.compile_sbpl_file(src, dst=out).blob


def parse_ops(src: Path) -> List[str]:
    """Extract allowed operation names from a tiny SBPL file."""
    ops: List[str] = []
    allow_re = re.compile(r"^\(allow\s+([^\s)]+)")
    for line in src.read_text().splitlines():
        m = allow_re.match(line.strip())
        if m:
            ops.append(m.group(1))
    return ops


def parse_filters(src: Path, filter_names: set[str]) -> List[str]:
    """
    Extract filter symbols present in SBPL by tokenizing paren-delimited atoms
    and intersecting with the known filter vocabulary. This is deliberately
    simple; it is sufficient for the small synthetic variants in this experiment.
    """
    tokens = set()
    token_re = re.compile(r"\(([\w*-]+)")
    skip = {"allow", "deny", "version", "default", "param", "require-any", "require-all", "require-not"}
    for line in src.read_text().splitlines():
        for token in token_re.findall(line):
            if token in skip:
                continue
            if token in filter_names:
                tokens.add(token)
    return sorted(tokens)


def op_entries(blob: bytes, op_count: int) -> List[int]:
    ops = blob[16 : 16 + op_count * 2]
    return [int.from_bytes(ops[i : i + 2], "little") for i in range(0, len(ops), 2)]


def tag_counts(nodes: bytes, stride: int) -> Dict[int, int]:
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
    Edges are interpreted as the first two u16 fields (`fields[0..1]`) in each
    decoded node record (decoder-selected stride for this world).
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


def summarize_variant(
    src: Path,
    blob: bytes,
    filter_map: Dict[str, int] | None = None,
) -> Dict[str, Any]:
    ops = parse_ops(src)
    filters = parse_filters(src, set(filter_map.keys()) if filter_map else set())
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=src.stem))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=src.stem), header)
    op_count = header.operation_count or 0
    entries = op_entries(blob, op_count)
    decoded = decoder.decode_profile_dict(blob)
    entry_sigs = {
        str(e): entry_signature(decoded, e) for e in sorted(set(entries))
    }
    records8 = len(sections.nodes) // 8
    records12 = len(sections.nodes) // 12
    summary = {
        "name": src.stem,
        "ops": ops,
        "filters": filters,
        "filter_ids": [filter_map.get(f) for f in filters] if filter_map else [],
        "length": len(blob),
        "format_variant": header.format_variant,
        "op_count": op_count,
        "op_count_source": "header",
        "op_entries": entries,
        "section_lengths": {
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        "tag_counts_stride8": {str(k): v for k, v in tag_counts(sections.nodes, 8).items()},
        "remainder_stride8_hex": sections.nodes[records8 * 8 :].hex(),
        "tag_counts_stride12": {str(k): v for k, v in tag_counts(sections.nodes, 12).items()},
        "remainder_stride12_hex": sections.nodes[records12 * 12 :].hex(),
        "literal_strings": ascii_strings(sections.regex_literals),
        "decoder": {
            "format_variant": decoded["format_variant"],
            "op_count": decoded["op_count"],
            "op_table_offset": decoded["op_table_offset"],
            "node_count": decoded["node_count"],
            "tag_counts": decoded["tag_counts"],
            "literal_strings": decoded["literal_strings"],
            "sections": decoded["sections"],
            "validation": decoded.get("validation", {}),
        },
        "entry_signatures": entry_sigs,
    }
    return summary


def build_op_table_map(summaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    single_op_entries: Dict[str, List[int]] = {}
    for s in summaries:
        if len(s["ops"]) == 1:
            single_op_entries[s["ops"][0]] = s["op_entries"]
    per_profile = {
        s["name"]: {
            "ops": s["ops"],
            "op_entries": s["op_entries"],
            "unique_entries": sorted(set(s["op_entries"])),
        }
        for s in summaries
    }
    return {"single_op_entries": single_op_entries, "profiles": per_profile}


def main() -> None:
    root = Path(__file__).parent
    sb_dir = root / "sb"
    build_dir = sb_dir / "build"
    out_dir = root / "out"
    out_dir.mkdir(exist_ok=True)

    filter_vocab_path = ROOT / "book/graph/mappings/vocab/filters.json"
    filter_map: Dict[str, int] = {}
    if filter_vocab_path.exists():
        try:
            filter_vocab = json.loads(filter_vocab_path.read_text())
            filter_map = {entry["name"]: entry["id"] for entry in filter_vocab.get("filters") or []}
        except Exception:
            filter_map = {}

    summaries: List[Dict[str, Any]] = []
    for sb in sorted(sb_dir.glob("*.sb")):
        blob = compile_sbpl(sb, build_dir / f"{sb.stem}.sb.bin")
        summaries.append(
            summarize_variant(
                sb,
                blob,
                filter_map=filter_map,
            )
        )

    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summaries, indent=2, sort_keys=True))
    op_map_path = out_dir / "op_table_map.json"
    op_map_path.write_text(json.dumps(build_op_table_map(summaries), indent=2, sort_keys=True))
    sig_path = out_dir / "op_table_signatures.json"
    sig_path.write_text(
        json.dumps(
            [
                {"name": s["name"], "entry_signatures": s["entry_signatures"]}
                for s in summaries
            ],
            indent=2,
            sort_keys=True,
        )
    )
    print(f"[+] wrote {summary_path}")
    print(f"[+] wrote {op_map_path}")
    print(f"[+] wrote {sig_path}")


if __name__ == "__main__":
    main()
