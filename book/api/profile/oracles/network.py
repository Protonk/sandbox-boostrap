"""
Structural oracle: extract the socket tuple (domain/type/proto) from a blob.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api.path_utils import find_repo_root, to_repo_relative
from .. import ingestion as pi

from .model import Conflict, NetworkTupleResult, Record8, WORLD_ID, Witness


def _u16le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "little")


def _iter_record8(nodes: bytes, nodes_start: int) -> Iterable[Record8]:
    for node_offset in range(0, len(nodes) - (len(nodes) % 8), 8):
        chunk = nodes[node_offset : node_offset + 8]
        yield Record8(
            blob_offset=nodes_start + node_offset,
            tag=chunk[0],
            kind=chunk[1],
            u16=(_u16le(chunk, 2), _u16le(chunk, 4), _u16le(chunk, 6)),
        )


def _precedence(source: str) -> Tuple[int, int]:
    if source.startswith("triple:"):
        return (0, 0)
    if source.startswith("pairwise:"):
        return (1, 0)
    if source.startswith("single:"):
        return (2, 0)
    return (99, 0)


def extract_network_tuple(blob: bytes) -> NetworkTupleResult:
    """
    Extract (domain,type,proto) from a compiled profile blob (structural oracle).

    This is world-scoped to `WORLD_ID` and returns byte-level witnesses under
    the witness rules established by the libsandbox-encoder network matrix.
    """
    profile = pi.ProfileBlob(bytes=blob, source="blob")
    header = pi.parse_header(profile)
    sections = pi.slice_sections(profile, header)

    nodes = sections.nodes
    nodes_start = 16 + len(sections.op_table)

    sources: Dict[str, List[Dict[str, Any]]] = {}
    witnesses: Dict[str, List[Witness]] = {}

    def add_witness(dim: str, source: str, value: int, record: Record8) -> None:
        w = Witness(dim=dim, source=source, value=value, record=record)  # type: ignore[arg-type]
        witnesses.setdefault(dim, []).append(w)
        sources.setdefault(dim, []).append(w.to_dict())

    triple_first: Dict[int, Record8] = {}
    for rec in _iter_record8(nodes, nodes_start):
        if rec.tag == 1 and rec.kind == 0 and rec.u16[0] in (0x0B00, 0x0C00, 0x0D00):
            if rec.u16[0] == 0x0B00:
                add_witness("domain", "single:u16[0]=0x0B00,u16[1]", rec.u16[1], rec)
            elif rec.u16[0] == 0x0C00:
                add_witness("type", "single:u16[0]=0x0C00,u16[1]", rec.u16[1], rec)
            elif rec.u16[0] == 0x0D00:
                add_witness("proto", "single:u16[0]=0x0D00,u16[1]", rec.u16[1], rec)

        if rec.tag == 0 and rec.kind in (11, 12, 13):
            if rec.kind == 11:
                add_witness("domain", "pairwise:tag0,kind11,u16[0]", rec.u16[0], rec)
            elif rec.kind == 12:
                add_witness("type", "pairwise:tag0,kind12,u16[0]", rec.u16[0], rec)
            elif rec.kind == 13:
                add_witness("proto", "pairwise:tag0,kind13,u16[0]", rec.u16[0], rec)

        if rec.u16[2] in (0x0C00, 0x0D00, 0x0E00):
            marker = rec.u16[2]
            if marker not in triple_first or rec.blob_offset < triple_first[marker].blob_offset:
                triple_first[marker] = rec

    for marker, dim in [(0x0C00, "domain"), (0x0D00, "type"), (0x0E00, "proto")]:
        rec = triple_first.get(marker)
        if rec is None:
            continue
        value = rec.tag + (rec.kind << 8)
        add_witness(dim, f"triple:u16[2]=0x{marker:04x},u16(tag|kind)", value, rec)

    resolved: Dict[str, Optional[int]] = {"domain": None, "type": None, "proto": None}
    conflicts: List[Dict[str, Any]] = []

    for dim in ["domain", "type", "proto"]:
        cand = witnesses.get(dim, [])
        if not cand:
            continue
        cand_sorted = sorted(cand, key=lambda w: (_precedence(w.source), w.record.blob_offset))
        primary = cand_sorted[0]
        resolved[dim] = int(primary.value)
        for other in cand_sorted[1:]:
            if int(other.value) != int(primary.value):
                conflicts.append(Conflict(dim=dim, primary=primary, other=other).to_dict())  # type: ignore[arg-type]

    return NetworkTupleResult(
        header={"format_variant": header.format_variant, "op_count": header.operation_count},
        domain=resolved["domain"],
        type=resolved["type"],
        proto=resolved["proto"],
        sources=sources,
        conflicts=conflicts,
    )


def run_network_matrix(manifest_path: Path, blob_dir: Path) -> Dict[str, Any]:
    """
    Run the network tuple oracle over an experiment-style MANIFEST + prebuilt blobs.

    - `manifest_path` is expected to follow the shape used by
      `book/experiments/libsandbox-encoder/sb/network_matrix/MANIFEST.json`.
    - `blob_dir` must contain `spec_id.sb.bin` for every manifest case.
    """
    root = find_repo_root(manifest_path)
    data = json.loads(manifest_path.read_text())
    cases = data.get("cases", [])

    entries: List[Dict[str, Any]] = []
    for case in cases:
        spec_id = case["spec_id"]
        blob_path = blob_dir / f"{spec_id}.sb.bin"
        result = extract_network_tuple(blob_path.read_bytes()).to_dict()
        result["spec_id"] = spec_id
        result["blob"] = to_repo_relative(blob_path, root)
        entries.append(result)

    return {
        "world_id": WORLD_ID,
        "oracle_id": "sbpl_oracle.network_tuple.v1",
        "purpose": "Extract (domain,type,proto) tuples from compiled blobs using structural witnesses only.",
        "inputs": {
            "manifest": to_repo_relative(manifest_path, root),
            "blob_dir": to_repo_relative(blob_dir, root),
        },
        "entries": entries,
    }
