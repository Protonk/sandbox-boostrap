## 1. What this example is about

This example is a **converter from compiled AppleMatch regex blobs (`.re`) to Graphviz `.dot` graphs**:

* Input: a raw `.re` file containing a compiled AppleMatch NFA (the regex engine used in Seatbelt’s regex tables).
* Output: a `.dot` file describing the NFA as a directed graph (nodes + edges), suitable for `dot`, `xdot`, or any Graphviz viewer.
* Purpose: bridge the gap between the **opaque binary regex blobs** stored alongside the policy graph and a **human-visible regex structure** (states, splits, character classes, etc.), as described in Appendix.md (“Regular Expressions and Literal Tables”).

You can treat `re2dot.py` as a microscope for the **regex side** of Seatbelt’s policy graph: it doesn’t touch SBPL itself, only the AppleMatch NFA blobs referenced from the profile’s literal/regex tables.

---

## 2. How to run it

Single file:

* `re2dot.py`

Typical usage:

```sh
# Show .dot on stdout
./re2dot.py path/to/regex.re

# Write to a file and then render with Graphviz
./re2dot.py path/to/regex.re -o regex.dot
dot -Tpng regex.dot -o regex.png
```

You pass it a compiled `.re` blob (extracted from a profile’s regex table). It parses the blob, builds an internal graph, and emits a `.dot` description of the NFA.

---

## 3. Data structures: `NFA_NAMES` and `Graph`

### 3.1 NFA opcode names

```python
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
```

These are the core AppleMatch NFA opcodes the parser recognizes:

* `CONST` – literal character edges.
* `ACCEPT` – accepting state.
* `PAREN_OPEN` / `PAREN_CLOSE` – group markers.
* `SPLIT` – epsilon branch (used for alternation, repetition).
* `DOT` – “any character”.
* `EPSILON_MOVE` – epsilon transitions.
* `LINE_BEGIN` / `LINE_END` – anchors.
* `IN_CCLASS` / `NOT_IN_CCLASS` – character class predicates.

The parser uses these numeric tags to decide how to interpret each node and how to label it in the final graph.

### 3.2 Lightweight `Graph` container

```python
class Graph:
    def __init__(self):
        self.edges = {}
        self.tags = {}

    def add_edge(self, u, v):
        self.edges.setdefault(u, set()).add(v)
        self.edges.setdefault(v, set())

    def set_tag(self, u, tag):
        self.tags[u] = tag
```

`Graph` is a minimal in-memory representation:

* `edges`: `node_id -> set(child_ids)` adjacency list.
* `tags`: `node_id -> (opcode_name, human_label)`.

It doesn’t try to represent the full AppleMatch semantics; it just keeps enough structure to express an NFA as a `.dot` graph:

* Nodes: `n0`, `n1`, … with labels like `CONST\n'a'`, `SPLIT`, `CCLASS\n[...]`.
* Directed edges: `n0 -> n1`, `n0 -> n5`, etc.

---

## 4. Parsing the `.re` blob: `parse_re`

```python
def parse_re(blob: bytes) -> Graph:
    """Parse a compiled AppleMatch regex into a Graph."""
    header = struct.unpack(">IIIIII", blob[:24])
    node_count = header[1]
    cclass_count = header[4]
```

The `.re` format starts with a fixed-size header:

* 6 big-endian 32-bit integers (`>IIIIII`).
* The parser uses:

  * `header[1]` as `node_count` (number of NFA nodes).
  * `header[4]` as `cclass_count` (number of character classes).

The exact semantics of each header field live in Appendix.md, but for visualization purposes you only need `node_count` and `cclass_count`.

### 4.1 Reading node records

```python
    off = 24
    nodes = [struct.unpack(">III", blob[off + i * 12 : off + (i + 1) * 12]) for i in range(node_count)]
    off += node_count * 12
```

Each node is 12 bytes:

* Three big-endian 32-bit integers: `(typ, nxt, arg)`:

  * `typ`: opcode (e.g., `0x10` for `CONST`).
  * `nxt`: index of next node or child in the NFA.
  * `arg`: extra field whose meaning depends on `typ`:

    * For `CONST`: character code.
    * For `SPLIT`: index of second branch.
    * For character-class nodes: index into the `cclasses` table.

At this point you have a list:

```python
nodes = [
    (typ0, nxt0, arg0),
    (typ1, nxt1, arg1),
    ...
]
```

with indices `0..node_count-1`.

### 4.2 Reading character classes

```python
    cclasses = []
    for _ in range(cclass_count):
        span_count = struct.unpack(">I", blob[off : off + 4])[0]
        off += 4
        spans = [struct.unpack(">I", blob[off + i * 4 : off + (i + 1) * 4])[0] for i in range(span_count)]
        off += span_count * 4
        cclasses.append(spans)
```

Each character class:

* Starts with `span_count` (32-bit big-endian).
* Followed by `span_count` 32-bit integers in a flat list.

The interpretation:

* Spans are read in pairs: `(start, end)`.
* Together they describe ranges of character codes contained in the class.
* For example: `[65, 90, 97, 122]` might represent `A-Z` and `a-z`.

The parser stores `cclasses` as a list of flat span arrays; it later converts them into a user-friendly label like `[a-z0-9]`.

---

## 5. Building the graph from nodes

```python
    g = Graph()
    for idx, (typ, nxt, arg) in enumerate(nodes):
        ...
```

For each node index `idx`:

* It examines `typ`.
* It adds edges based on control flow (`nxt`, sometimes `arg`).
* It sets a human-readable tag for that node.

### 5.1 Simple linear nodes

Examples:

```python
        if typ == 0x10:  # CONST
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("CONST", chr(arg & 0xFF)))
```

* `CONST`: literal character match:

  * Edge: this node → `nxt`.
  * Tag: `"CONST"` plus the character (low byte of `arg`).

```python
        elif typ == 0x30:  # DOT
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("DOT", "."))
```

* `DOT`: “any character”:

  * Straight edge to `nxt`.
  * Tag: `"DOT"` and `"."`.

Other linear nodes:

```python
        elif typ == 0x31:  # EPSILON_MOVE
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("EPSILON", None))
        elif typ == 0x32:  # LINE_BEGIN
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("LINE_BEGIN", "^"))
        elif typ == 0x33:  # LINE_END
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("LINE_END", "$"))
        elif typ == 0x23:  # PAREN_CLOSE
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("PAREN_CLOSE", ")"))
        elif typ == 0x24:  # PAREN_OPEN
            g.add_edge(idx, nxt)
            g.set_tag(idx, ("PAREN_OPEN", "("))
        elif typ == 0x22:  # ACCEPT
            g.set_tag(idx, ("ACCEPT", None))
```

* Each gets:

  * A single outgoing edge to `nxt` (except `ACCEPT`, which has no explicit outgoing edge).
  * A label capturing its role.

### 5.2 `SPLIT`: branching

```python
        elif typ == 0x25:  # SPLIT
            g.add_edge(idx, nxt)
            g.add_edge(idx, arg)
            g.set_tag(idx, ("SPLIT", None))
```

* `SPLIT` creates two outgoing edges:

  * `idx → nxt`
  * `idx → arg`
* This is the classic Thompson NFA branching node, used for:

  * alternation (`A|B`),
  * quantifiers (`A*`, `A?`, etc.).

In the `.dot` graph you’ll see a box labeled `SPLIT` with two arrows, showing where the regex engine can go next.

### 5.3 Character classes: `IN_CCLASS` / `NOT_IN_CCLASS`

```python
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
```

Here:

* `arg` indexes into `cclasses`, giving you the span list.

* The code converts the spans into a string like `[a-z0-9]`:

  * For `IN_CCLASS` (`0x34`), `rngs` starts empty and accumulates ranges.
  * For `NOT_IN_CCLASS` (`0x35`), `rngs` starts with `"^"` to indicate negation: `[^...]`.

* Adds an edge from this node to `nxt`.

* Tags the node as `"CCLASS"` with the class string as the secondary label.

In the graph, you see:

* Nodes labeled like:

  * `CCLASS\n[a-z]`
  * `CCLASS\n[^0-9]`

which makes the regex intent much clearer.

### 5.4 Fallback for unknown types

```python
        else:
            g.add_edge(idx, nxt)
            g.set_tag(idx, (f"0x{typ:x}", None))
```

If the opcode isn’t recognized:

* The parser still preserves control flow (edge to `nxt`).
* Labels the node with the raw hex type (e.g., `0x40`).

This keeps the graph structurally complete, even if some opcodes are unfamiliar.

---

## 6. Emitting Graphviz: `graph_to_dot`

```python
def graph_to_dot(g: Graph) -> str:
    lines = ["digraph regex {", '  rankdir=LR;', '  node [shape=box, fontname="Menlo"];']
```

Starts a left-to-right directed graph:

* `rankdir=LR` – states progress left → right.
* Nodes: boxes with a monospaced font.

### 6.1 Node labels

```python
    for node in sorted(g.edges.keys()):
        tag = g.tags.get(node, ("?", None))
        label = tag[0]
        if tag[1]:
            label += f"\\n{tag[1]}"
        lines.append(f'  n{node} [label="{label}"];')
```

For each node:

* Primary label: opcode name (`CONST`, `SPLIT`, `CCLASS`, etc.) or `?`.
* Secondary label (on a new line) if present:

  * The literal character,
  * Character-class string,
  * Symbol (`.`, `^`, `$`, `(`, `)`).

Example:

* `CONST 'a'` → box label:

  ```
  CONST
  a
  ```

* `CCLASS [^0-9]` → box label:

  ```
  CCLASS
  [^0-9]
  ```

### 6.2 Edges

```python
    for u, vs in g.edges.items():
        for v in vs:
            lines.append(f"  n{u} -> n{v};")
    lines.append("}")
    return "\n".join(lines)
```

Edges are straightforward:

* `n0 -> n1;`
* `n3 -> n5;`
* etc.

The output is a valid `.dot` file.

---

## 7. CLI entry point: `main()`

```python
def main():
    ap = argparse.ArgumentParser(description="Convert compiled .re regex blobs to Graphviz .dot")
    ap.add_argument("regex", type=Path, help="Input .re file")
    ap.add_argument("-o", "--out", type=Path, help="Output .dot path (default: stdout)")
    args = ap.parse_args()

    blob = args.regex.read_bytes()
    g = parse_re(blob)
    dot = graph_to_dot(g)

    if args.out:
        args.out.write_text(dot)
        print(f"[+] wrote {args.out}")
    else:
        print(dot)
```

Usage pattern:

* `regex`: required positional argument → the `.re` blob to parse.
* `--out`:

  * If provided, `.dot` text is written to that file and a short success message is printed.
  * If omitted, `.dot` is printed to stdout (useful for piping to other tools).

`if __name__ == "__main__": main()` wires it up as a standard Python CLI.

---

## 8. How to use this in the sandbox context

In the broader Seatbelt / XNUSandbox workflow:

1. **Extract regex blobs**

   * From a compiled profile blob (`.sb.bin`), locate the regex table as described in Appendix.md.
   * Extract individual `.re` blobs (e.g., using your own disassembler or tooling).

2. **Convert to graphs**

   * For each `.re` file, run:

     ```sh
     ./re2dot.py x.re -o x.dot
     dot -Tpng x.dot -o x.png
     ```

   * You now have a visual NFA for each AppleMatch regex used in path filters, entitlement checks, etc.

3. **Connect to SBPL filters**

   * In decoded SBPL, find rules that use regex-based filters (e.g., `regex` path filters).
   * Map those filters’ regex literals to the specific `.re` blobs you extracted.
   * Use the `.dot`/PNG output to understand:

     * how complex the regex is,
     * what character classes and branches it uses,
     * where splits and loops occur.

4. **Diff and audit**

   * Across OS versions or policy revisions:

     * extract the same `.re` blob,
     * convert both to `.dot`,
     * compare NFAs for added/removed branches, widened character classes, etc.

In short, `re2dot.py` is the “regex-side” analogue of your profile graph tools: it turns AppleMatch’s opaque NFA blobs into readable graph structures, making it easier to audit and understand the regex-heavy parts of Apple’s sandbox policies.
