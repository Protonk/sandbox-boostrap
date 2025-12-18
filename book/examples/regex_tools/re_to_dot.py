#!/usr/bin/env python3
"""
HISTORICAL EXAMPLE (legacy decision-tree profiles)

Render a compiled AppleMatch regex blob (.re) to Graphviz .dot.

This script is maintained as part of the legacy profile/regex inspection toolchain; it is not wired into modern
graph-based profile extraction/decoding in SANDBOX_LORE.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class RegexGraph:
    tags: Dict[int, Tuple[str, List[int]]] = field(default_factory=dict)


def _read_u32_be(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "big")


def parse_re(blob: bytes) -> RegexGraph:
    if len(blob) < 24:
        raise ValueError("regex blob too small")
    node_count = _read_u32_be(blob, 4)
    start_offset = _read_u32_be(blob, 8)
    _ = start_offset  # unused in this minimal parser
    pos = 24
    graph = RegexGraph()
    for idx in range(node_count):
        opcode = _read_u32_be(blob, pos)
        child1 = _read_u32_be(blob, pos + 4)
        child2 = _read_u32_be(blob, pos + 8)
        pos += 12
        graph.tags[idx] = (_opcode_name(opcode), [child1, child2])
    return graph


def _opcode_name(opcode: int) -> str:
    # Minimal mapping for illustration; extend if more opcodes are needed.
    if opcode == 0x22:
        return "ACCEPT"
    return f"OP_{opcode}"


def graph_to_dot(graph: RegexGraph) -> str:
    lines = ["digraph regex {", '  rankdir="LR";']
    for idx, (name, edges) in graph.tags.items():
        lines.append(f'  n{idx} [label="{name}"];')
        for target in edges:
            if target == 0xFFFFFFFF:
                continue
            lines.append(f"  n{idx} -> n{target};")
    lines.append("}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render a compiled AppleMatch regex blob to Graphviz .dot.")
    ap.add_argument("re_path", type=Path, help=".re file to parse")
    ap.add_argument("-o", "--out", type=Path, help="Output .dot path (default stdout)")
    args = ap.parse_args(argv)
    blob = args.re_path.read_bytes()
    g = parse_re(blob)
    dot = graph_to_dot(g)
    if args.out:
        args.out.write_text(dot)
        print(f"wrote {args.out}")
    else:
        print(dot)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
