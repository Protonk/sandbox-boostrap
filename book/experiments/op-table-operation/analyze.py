#!/usr/bin/env python3
"""
Compile SBPL variants under sb/ and emit op-table centric summaries.

Outputs:
- sb/build/*.sb.bin (compiled blobs via libsandbox)
- out/summary.json (per-profile metadata: ops, op_count, op_entries, section lengths, tag counts, literals)
- out/op_table_map.json (single-op entry hints + per-profile op_entries)
"""

from __future__ import annotations

import ctypes
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any

from book.graph.concepts.validation import decoder
from book.graph.concepts.validation import profile_ingestion as pi


@dataclass
class SandboxProfile(ctypes.Structure):
    _fields_ = [
        ("profile_type", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("bytecode", ctypes.c_void_p),
        ("bytecode_length", ctypes.c_size_t),
    ]


def compile_sbpl(src: Path, out: Path) -> bytes:
    """Compile SBPL via libsandbox and write the blob."""
    lib = ctypes.CDLL("libsandbox.dylib")
    lib.sandbox_compile_string.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    lib.sandbox_compile_string.restype = ctypes.POINTER(SandboxProfile)
    lib.sandbox_free_profile.argtypes = [ctypes.POINTER(SandboxProfile)]

    text = src.read_text().encode()
    err = ctypes.c_char_p()
    prof = lib.sandbox_compile_string(text, 0, ctypes.byref(err))
    if not prof:
        detail = err.value.decode() if err.value else "unknown"
        raise RuntimeError(f"compile failed for {src}: {detail}")

    blob = ctypes.string_at(prof.contents.bytecode, prof.contents.bytecode_length)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)

    lib.sandbox_free_profile(prof)
    if err:
        ctypes.CDLL(None).free(err)
    return blob


def parse_ops(src: Path) -> List[str]:
    """Extract allowed operation names from a tiny SBPL file."""
    ops: List[str] = []
    allow_re = re.compile(r"^\(allow\s+([^\s)]+)")
    for line in src.read_text().splitlines():
        m = allow_re.match(line.strip())
        if m:
            ops.append(m.group(1))
    return ops


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


def summarize_variant(src: Path, blob: bytes, op_count_override: int | None = None) -> Dict[str, Any]:
    ops = parse_ops(src)
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=src.stem))
    if op_count_override:
        header.operation_count = op_count_override
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=src.stem), header)
    op_count = header.operation_count or 0
    entries = op_entries(blob, op_count)
    decoded = decoder.decode_profile_dict(blob)
    entry_sigs = {
        str(e): entry_signature(decoded, e) for e in sorted(set(entries))
    }
    summary = {
        "name": src.stem,
        "ops": ops,
        "length": len(blob),
        "format_variant": header.format_variant,
        "op_count": op_count,
        "op_count_source": "override" if op_count_override else "header",
        "op_entries": entries,
        "section_lengths": {
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        "tag_counts_stride12": {str(k): v for k, v in tag_counts(sections.nodes).items()},
        "remainder_stride12_hex": sections.nodes[(len(sections.nodes) // 12) * 12 :].hex(),
        "literal_strings": ascii_strings(sections.regex_literals),
        "decoder": {
            "format_variant": decoded["format_variant"],
            "op_count": decoded["op_count"],
            "op_table_offset": decoded["op_table_offset"],
            "node_count": decoded["node_count"],
            "tag_counts": decoded["tag_counts"],
            "literal_strings": decoded["literal_strings"],
            "sections": decoded["sections"],
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

    vocab_path = Path("book/graph/concepts/validation/out/vocab/ops.json")
    vocab_len = None
    if vocab_path.exists():
        try:
            vocab = json.loads(vocab_path.read_text())
            vocab_len = len(vocab.get("ops") or [])
        except Exception:
            vocab_len = None

    summaries: List[Dict[str, Any]] = []
    for sb in sorted(sb_dir.glob("*.sb")):
        blob = compile_sbpl(sb, build_dir / f"{sb.stem}.sb.bin")
        summaries.append(summarize_variant(sb, blob, op_count_override=vocab_len))

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
