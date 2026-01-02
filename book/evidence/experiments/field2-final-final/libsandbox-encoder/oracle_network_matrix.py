#!/usr/bin/env python3
"""
Falsifiable SBPL ↔ compiled profile oracle (experiment-local).

HISTORICAL: This script is preserved as the original experiment-local oracle used
to generate `out/network_matrix/oracle_tuples.json`. The maintained oracle now
lives in `book/api/profile/oracles/` and is guarded by parity tests against this
experiment’s checked-in corpus.

This script extracts the socket (domain,type,proto) tuple from the compiled blobs
in the libsandbox-encoder Phase A network matrix using only byte-level,
world-scoped structural witnesses (no kernel semantics).

Output: `out/network_matrix/oracle_tuples.json`
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile import ingestion as pi

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def u16le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "little")


@dataclass(frozen=True)
class Record8:
    blob_offset: int
    tag: int
    kind: int
    u16: Tuple[int, int, int]

    @classmethod
    def parse_from_nodes(cls, nodes: bytes, nodes_start: int, node_offset: int) -> "Record8":
        chunk = nodes[node_offset : node_offset + 8]
        if len(chunk) != 8:
            raise ValueError(f"short record8 at node_offset={node_offset}")
        return cls(
            blob_offset=nodes_start + node_offset,
            tag=chunk[0],
            kind=chunk[1],
            u16=(u16le(chunk, 2), u16le(chunk, 4), u16le(chunk, 6)),
        )


def iter_record8(nodes: bytes, nodes_start: int) -> Iterable[Record8]:
    for node_offset in range(0, len(nodes) - (len(nodes) % 8), 8):
        yield Record8.parse_from_nodes(nodes, nodes_start, node_offset)


def _append_source(
    sources: Dict[str, List[Dict[str, Any]]],
    dim: str,
    source: str,
    value: int,
    record: Record8,
) -> None:
    sources.setdefault(dim, []).append(
        {
            "source": source,
            "value": int(value),
            "blob_offset": int(record.blob_offset),
            "record": {"tag": int(record.tag), "kind": int(record.kind), "u16": list(record.u16)},
        }
    )


def extract_domain_type_proto(blob: bytes) -> Dict[str, Any]:
    """
    Extract (domain,type,proto) from a compiled profile blob.

    Returns:
      {
        "domain": int|None,
        "type": int|None,
        "proto": int|None,
        "sources": {dim: [..]},
        "conflicts": [{dim, primary, other}],
      }
    """
    profile = pi.ProfileBlob(bytes=blob, source="blob")
    header = pi.parse_header(profile)
    sections = pi.slice_sections(profile, header)
    nodes = sections.nodes
    nodes_start = 16 + len(sections.op_table)

    # Structural witness families (Phase A):
    # - single: tag=1 kind=0, u16[0] in {0x0B00,0x0C00,0x0D00}, value in u16[1]
    # - pairwise: tag=0 kind in {11,12,13}, value in u16[0]
    # - triple: u16[2] in {0x0C00,0x0D00,0x0E00}, value in (tag + kind*256)
    sources: Dict[str, List[Dict[str, Any]]] = {}

    # Collect candidates.
    triple_candidates: Dict[int, Record8] = {}  # marker -> earliest record
    for rec in iter_record8(nodes, nodes_start):
        # minimal single-filter specimen record
        if rec.tag == 1 and rec.kind == 0 and rec.u16[0] in (0x0B00, 0x0C00, 0x0D00):
            if rec.u16[0] == 0x0B00:
                _append_source(sources, "domain", "single:u16[0]=0x0B00,u16[1]", rec.u16[1], rec)
            elif rec.u16[0] == 0x0C00:
                _append_source(sources, "type", "single:u16[0]=0x0C00,u16[1]", rec.u16[1], rec)
            elif rec.u16[0] == 0x0D00:
                _append_source(sources, "proto", "single:u16[0]=0x0D00,u16[1]", rec.u16[1], rec)

        # pairwise combined-form records (kind encodes family)
        if rec.tag == 0 and rec.kind in (11, 12, 13):
            if rec.kind == 11:
                _append_source(sources, "domain", "pairwise:tag0,kind11,u16[0]", rec.u16[0], rec)
            elif rec.kind == 12:
                _append_source(sources, "type", "pairwise:tag0,kind12,u16[0]", rec.u16[0], rec)
            elif rec.kind == 13:
                _append_source(sources, "proto", "pairwise:tag0,kind13,u16[0]", rec.u16[0], rec)

        # triple combined-form marker records (payload u16[2] encodes family)
        if rec.u16[2] in (0x0C00, 0x0D00, 0x0E00):
            marker = rec.u16[2]
            if marker not in triple_candidates or rec.blob_offset < triple_candidates[marker].blob_offset:
                triple_candidates[marker] = rec

    for marker, dim in [(0x0C00, "domain"), (0x0D00, "type"), (0x0E00, "proto")]:
        rec = triple_candidates.get(marker)
        if rec is None:
            continue
        value = rec.tag + (rec.kind << 8)
        _append_source(sources, dim, f"triple:u16[2]=0x{marker:04x},u16(tag|kind)", value, rec)

    # Resolve with a stable precedence (triple > pairwise > single), while flagging conflicts.
    precedence = {
        "triple": 0,
        "pairwise": 1,
        "single": 2,
    }

    def score(src: str) -> Tuple[int, int]:
        for k, v in precedence.items():
            if src.startswith(k + ":"):
                return (v, 0)
        return (99, 0)

    resolved: Dict[str, Optional[int]] = {"domain": None, "type": None, "proto": None}
    conflicts: List[Dict[str, Any]] = []
    for dim in ["domain", "type", "proto"]:
        cand = sources.get(dim, [])
        if not cand:
            continue
        cand_sorted = sorted(cand, key=lambda c: (score(c["source"]), c["blob_offset"]))
        primary = cand_sorted[0]
        resolved[dim] = int(primary["value"])
        for other in cand_sorted[1:]:
            if int(other["value"]) != int(primary["value"]):
                conflicts.append({"dim": dim, "primary": primary, "other": other})

    return {
        "header": {"format_variant": header.format_variant, "op_count": header.operation_count},
        "domain": resolved["domain"],
        "type": resolved["type"],
        "proto": resolved["proto"],
        "sources": sources,
        "conflicts": conflicts,
    }


def load_manifest_cases() -> List[Dict[str, Any]]:
    manifest_path = ROOT / "book/evidence/experiments/field2-final-final/libsandbox-encoder/sb/network_matrix/MANIFEST.json"
    data = json.loads(manifest_path.read_text())
    return data.get("cases", [])


def main() -> None:
    out_dir = ROOT / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "oracle_tuples.json"

    cases = load_manifest_cases()
    entries: List[Dict[str, Any]] = []
    for case in cases:
        spec_id = case["spec_id"]
        blob_path = out_dir / f"{spec_id}.sb.bin"
        if not blob_path.exists():
            raise FileNotFoundError(f"missing compiled blob for {spec_id}: {blob_path}")
        result = extract_domain_type_proto(blob_path.read_bytes())
        result["spec_id"] = spec_id
        result["blob"] = rel(blob_path)
        entries.append(result)

    out = {
        "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
        "purpose": "Extract (domain,type,proto) tuples from libsandbox-encoder network_matrix compiled blobs using structural witnesses only.",
        "inputs": {
            "manifest": rel(ROOT / "book/evidence/experiments/field2-final-final/libsandbox-encoder/sb/network_matrix/MANIFEST.json"),
        },
        "outputs": {"oracle_tuples": rel(out_path)},
        "entries": entries,
    }
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {out_path}")


if __name__ == "__main__":
    main()
