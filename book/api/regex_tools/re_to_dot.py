#!/usr/bin/env python3
"""
Convert a compiled AppleMatch regex blob (.re) into a Graphviz .dot file.

Supports the legacy decision-tree profile format. The parser follows the
serialized NFA described in substrate/Appendix.md (“Regular Expressions and Literal Tables”).
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


NFA_NAMES = {
    0x10: "CONST",
    0x22: "ACCEPT",
    0x23: "PAREN_CLOSE",
    0x24: "PAREN_OPEN",
    0x25: "SPLIT",
    0x30: "DOT",
    0x31: "EPSILON_MOVE",
    0x32: "LINE_BEGIN",
    0x33: "LINE_END",
    0x34: "IN_CCLASS",
    0x35: "NOT_IN_CCLASS",
}


class Graph:
    def __init__(self):
        self.edges = {}
        self.tags = {}

    def add_edge(self, u, v):
        self.edges.setdefault(u, set()).add(v)
        self.edges.setdefault(v, set())

    def set_tag(self, u, tag):
        self.tags[u] = tag


def parse_re(blob: bytes) -> Graph:
    header = struct.unpack(">IIIIII", blob[:24])
    node_count = header[1]
    cclass_count = header[4]

    off = 24
    nodes = [struct.unpack(">III", blob[off + i * 12 : off + (i + 1) * 12]) for i in range(node_count)]
    off += node_count * 12

    cclasses = []
    for _ in range(cclass_count):
        span_count = struct.unpack(">I", blob[off : off + 4])[0]
        off += 4
        spans = [struct.unpack(">I", blob[off + i * 4 : off + (i + 1) * 4])[0] for i in range(span_count)]
        off += span_count * 4
        cclasses.append(spans)

    g = Graph()
    for idx, (typ, nxt, arg) in enumerate(nodes):
        if typ == 0x10:  # CONST
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("CONST", chr(arg & 0xFF)))
        elif typ == 0x22:  # ACCEPT
            g.set_tag(idx, ("ACCEPT", None))
        elif typ == 0x23:  # PAREN_CLOSE
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("PAREN_CLOSE", ")"))
        elif typ == 0x24:  # PAREN_OPEN
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("PAREN_OPEN", "("))
        elif typ == 0x25:  # SPLIT
            g.add_edge(idx, nxt)
            g.add_edge(idx, arg)
            g.set_tag(idx, ("SPLIT", None))
        elif typ == 0x30:  # DOT
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("DOT", "."))
        elif typ == 0x31:  # EPSILON_MOVE
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("EPSILON", None))
        elif typ == 0x32:  # LINE_BEGIN
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("LINE_BEGIN", "^"))
        elif typ == 0x33:  # LINE_END
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("LINE_END", "$"))
        elif typ in (0x34, 0x35):  # character class
            rngs = "^" if typ == 0x35 else ""
            spans = cclasses[arg]
            for i in range(0, len(spans), 2):
                start = spans[i]
                end = spans[i + 1]
                rngs += chr(start)
                if start != end:
                    rngs += "-" + chr(end)
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("CCLASS", f"[{rngs}]"))
        else:
            g.add_edge(idx, nxt)
            g.set_tag(idx, (f"0x{typ:x}", None))

    return g


def graph_to_dot(g: Graph) -> str:
    lines = ["digraph regex {", '  rankdir=LR;', '  node [shape=box, fontname="Menlo"];']
    nodes = set(g.edges.keys()) | set(g.tags.keys())
    for node in sorted(nodes):
        tag = g.tags.get(node, ("?", None))
        label = tag[0]
        if tag[1]:
            label += f"\\n{tag[1]}"
        lines.append(f'  n{node} [label="{label}"];')

    for u, vs in g.edges.items():
        for v in vs:
            lines.append(f"  n{u} -> n{v};")
    lines.append("}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Convert compiled .re regex blobs to Graphviz .dot (legacy format).")
    ap.add_argument("regex", type=Path, help="Input .re file")
    ap.add_argument("-o", "--out", type=Path, help="Output .dot path (default: stdout)")
    args = ap.parse_args(argv)

    blob = args.regex.read_bytes()
    g = parse_re(blob)
    dot = graph_to_dot(g)

    if args.out:
        args.out.write_text(dot)
        print(f"[+] wrote {args.out}")
    else:
        print(dot)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
