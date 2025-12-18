> HISTORICAL EXAMPLE (legacy decision-tree profiles)
>
> This example targets the early “decision-tree” compiled profile format and is kept for historical inspection. It does not describe the modern graph-based compiled profile format used on this host baseline.

## 1. What this example is about

This example is a **legacy sandbox profile disassembler** for the early “decision-tree” format (Blazakis-era):

* It reads an old `*.sb.bin` profile (the early format described in `sb_format.txt`).
* It reconstructs, for each operation (e.g. `file-read*`, `mach-lookup`, `sysctl-read`), the **filter decision tree**:

  * Which filters are tested (`path`, `mach-global`, `file-mode`, etc.).
  * What regex the filter uses (decoded from AppleMatch NFA blobs).
  * Whether the eventual result is `allow`, `deny`, `deny-with-log`, etc.
* It prints a **structured, human-readable representation** of “for operation X, here’s the if/else structure and outcomes.”

It now uses the shared **Axis 4.1 profile ingestion layer** (`book.api.profile_tools.ingestion`) to slice the legacy blob into header + sections, but the actual decision-tree decoding (nodes/filters) remains local.

Modern graph-based profiles should be handled by newer tools; `sbdis` is explicitly for the **legacy, decision-tree format**.

---

## 2. How to run it

Convenience wrapper:

```sh
./run-demo.sh path/to/legacy.sb.bin
```

`run-demo.sh`:

* Enforces strict shell flags (`set -euo pipefail`).
* Requires exactly one argument (the legacy `.sb.bin` profile).
* Runs:

  ```sh
  python3 sbdis.py osx path/to/legacy.sb.bin
  ```

Direct usage:

```sh
# For an iOS-style blob (uses ops.txt)
python3 sbdis.py ios legacy.sb.bin

# For an OS X/macOS blob (tries to derive op names from Sandbox.kext)
python3 sbdis.py osx legacy.sb.bin
```

If you pass the wrong number of arguments or an invalid mode, `sbdis.py` prints:

* Usage (`sbdis (ios | osx) binary.sb.bin`).
* A brief explanation that you must match the profile origin.

On success you will see a series of Python `pprint` structures, one per distinct operation handler, of the form:

```python
(['file-read*'],
 [('deny', 'path.match("/some/regex")'), ... or nested ('if', ...) trees])
```

This is the disassembled decision tree for each operation.

---

## 3. Legacy format context (`sb_format.txt`)

`sb_format.txt` documents the **early binary layout** that `sbdis` targets:

* **Header:**

  ```text
  u2 re_table_offset (8-byte words from start of sb)
  u1 re_table_count (really just the low byte)
  u1 padding
  u2[] op_table (8-byte word offset)
  ```

  * `re_table_offset` and `re_table_count` describe the regex table.
  * `op_table` is an array of operation handlers, each stored as a 16-bit word offset (×8 bytes) into the blob.

* **Operation handlers (decision tree nodes):**

  ```text
  u1 opcode
      01: terminal
      00: non-terminal
  ```

  * **terminal**:

    * `u1 padding`
    * `u1 result` (bit-coded: allow/deny/log flags)
  * **non-terminal**:

    * `u1 filter` (type ID)
    * `u2 filter_arg`
    * `u2 transition_matched`
    * `u2 transition_unmatched`

  These form a recursive tree: each non-terminal node tests a filter and branches to a “matched” and “unmatched” child; terminals end in `allow` or `deny`.

* **Regex table:**

  ```text
  re_table:
    u2 re_offset (8-byte word offset)
    u2 padding
    u4 padding

  re:
    u4 version
    u4 node_count
    u4 start_node
    u4 ??? (end_node?)
    u4 cclass_count
    u4 ???
    node nodes[]
    cclass cclasses[]
  ```

  This matches the early AppleMatch NFA format that `redis.py` and `re2dot.py` understand.

`sbdis.py` implements a decoder for exactly this format, but now uses the shared ingestion layer to locate the relevant sections instead of reading from the raw blob offset 0 by hand.

---

## 4. Support modules

### 4.1 Operation names: `find_operations.py` and `ops.txt`

`sbd‍is` needs human-readable operation names (e.g. `file-read*`) to label each operation’s decision tree.

#### iOS mode (`ios`): static list (`ops.txt`)

`ops.txt` is a textual list of operation names (in order):

```text
default
file*
file-chroot
file-ioctl
...
mach-per-user-lookup
```

`load_op_names_ios()`:

```python
def load_op_names_ios():
  global OP_TABLE_COUNT
  OP_TABLE_COUNT = 0x49
  with open('ops.txt', 'r') as f:
    ops = [s.strip() for s in f.readlines()]
  return ops[0:OP_TABLE_COUNT]
```

* Reads all lines from `ops.txt`.
* Truncates to the expected count (`0x49`).
* Uses this list as `ops[0..operation_count-1]`.

#### OS X/macOS mode (`osx`): dynamic extraction (`find_operations.py`)

`load_op_names_osx()`:

```python
def load_op_names_osx():
  try:
    ops = find_operations.get_operations("/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox")
  except Exception:
    ops = []
  return ops
```

`find_operations.get_operations`:

* Runs `nm -arch i386` and `otool -arch i386 -l` on the `Sandbox.kext` binary.
* Finds the `_operation_names` symbol and uses section info to locate the C string array containing operation names.
* Walks that array in `__cstring` until it hits a pointer outside the string section.
* Decodes each pointer into a null-terminated string.

If extraction fails, it returns an empty list; later code will synthesize generic names (`op_0`, `op_1`, …) if there are fewer names than `header.operation_count`.

### 4.2 Regex reconstruction: `redis.py`

`redis.py` is a legacy tool that:

1. Parses an AppleMatch regex blob into a graph (`reToGraph`).
2. Simplifies the NFA back into a **textual regex string** (`graphToRegEx`).

This is similar in spirit to `re2dot.py`, but instead of producing a `.dot` graph, it tries to reconstruct a human-readable regex.

Core pieces:

* `Graph` is an NFA graph representation:

  * `nodes`, `edges`, `redges`, `tags`.
  * `mergeIfPossible`, `removeNode`, `addEdge`.

* `reToGraph(re_bytes)`:

  * Reads header (`>IIIIII`).
  * Reads nodes as `(typ, next, arg)`.
  * Reads character classes and builds `Graph` with tags:

    * `TYPE_CONST`, `TYPE_SPLIT`, `TYPE_IN_CCLASS`, etc.
    * Regex characters stored in `tags` as `(0x100, 'literal')` or `[range]`.

* `graphToRegEx(g)`:

  * Repeatedly rewrites the graph:

    * Removes ACCEPT nodes.
    * Recognizes `*` and `+` patterns around SPLIT/self-loop structures.
    * Recognizes `A|B` patterns where both sides converge on the same successor.
    * Eliminates EPSILON nodes by shortcutting edges.
    * Merges adjacent constant segments.

  * If the graph collapses to a single node with a `(0x100, 'pattern')` tag, returns that pattern string.

  * Otherwise returns `None`.

`sbd‍is.py` uses this to turn each compiled regex into a text form it can embed in filter descriptions like `path.match("...")`.

---

## 5. `sbdis.py`: main disassembler

### 5.1 Argument handling and ingestion

At the top, `sbdis.py`:

* Parses CLI arguments (`ios` or `osx` + `binary.sb.bin`).

* Loads `ops`:

  ```python
  if mode == 'ios':
    ops = load_op_names_ios()
  elif mode == 'osx':
    ops = load_op_names_osx()
  else:
    usage()
  ```

* Uses the shared ingestion layer:

  ```python
  blob = ingestion.ProfileBlob.from_path(sys.argv[2], source="sbdis")
  header = ingestion.parse_header(blob)
  if header.format_variant != ingestion.FORMAT_LEGACY_V1:
    print(f"unsupported profile format: {header.format_variant} (expected legacy decision-tree)")
    sys.exit(1)
  sections = ingestion.slice_sections(blob, header)
  ```

So:

* It only proceeds if the profile is recognized as `FORMAT_LEGACY_V1` (the early decision-tree format).
* `sections` gives you:

  * `sections.op_table` – raw bytes for the op table region.
  * `sections.regex_literals` – raw bytes for the regex table region.
  * The full blob is `blob.bytes`.

### 5.2 Decoding op table and regex table

```python
data = blob.bytes
op_table = struct.unpack_from(f"<{header.operation_count}H", sections.op_table, 0)
```

* `op_table` is an array of `operation_count` 16-bit word offsets, little-endian.

Regex table:

```python
regex_table = []
if header.regex_count:
  re_table = struct.unpack_from(f"<{header.regex_count}H", sections.regex_literals, 0)
  for offset in re_table:
    start = offset * 8
    if start + 4 > len(data):
      regex_table.append("<invalid-regex-offset>")
      continue
    re_count = struct.unpack_from("<I", data, start)[0]
    raw = data[start + 4 : start + 4 + re_count]
    g = redis.reToGraph(raw)
    re = redis.graphToRegEx(g)
    regex_table.append(re)
```

* `header.regex_count` describes the number of regex entries.
* `sections.regex_literals` is interpreted as an array of 16-bit offsets in 8-byte words.
* For each `offset`:

  * Compute byte `start = offset * 8`.
  * Read a 4-byte length `re_count`.
  * Take `re_count` bytes of compiled regex after the length.
  * Use `redis.reToGraph` + `redis.graphToRegEx` to translate to a regex string.
* Store the resulting string in `regex_table[arg]` so `show_filter` can use it.

If the offset is invalid, the script inserts `"<invalid-regex-offset>"`.

### 5.3 Ensuring operation names

After reading op names and the op table, it ensures there is a name for each operation index:

```python
op_count = header.operation_count
if len(ops) < op_count:
  ops.extend([f'op_{i}' for i in range(len(ops), op_count)])
```

* If discovery from `Sandbox.kext` (OS X mode) yields fewer names than operations, it fills the remainder with `op_<index>` placeholders.

### 5.4 Grouping operations by handler offset

Multiple operations can share the **same decision tree** (same handler offset). `sbdis` groups them:

```python
op_bag = {}
for i, op_offset in enumerate(op_table):
  if op_offset not in op_bag:
    op_bag[op_offset] = set()
  op_bag[op_offset].add(i)
```

* `op_bag` maps from `op_offset` (word offset) → set of operation indices that use that handler.

Later, when iterating, it prints one tree per unique handler and lists all operations that share it.

### 5.5 Filter display helper: `show_filter`

```python
def show_filter(typ, arg, re_table):
  if typ == 1:
    return 'path.match("%s")' % (re_table[arg],)
  elif typ == 3:
    return 'file-mode == %d' % (arg,)
  elif typ == 4:
    return 'mach-global.match("%s")' % (re_table[arg],)
  elif typ == 11:
    return 'iokit.match("%s")' % (re_table[arg],)
  elif typ == 12:
    return 'path_in_extensions'
  else:
    return 'filter(%d, %d)' % (typ, arg)
```

This maps legacy filter type IDs and arguments into readable conditions:

* `typ == 1` → `path.match("<regex>")`.
* `typ == 3` → `file-mode == <arg>`.
* `typ == 4` → `mach-global.match("<regex>")`.
* `typ == 11` → `iokit.match("<regex>")`.
* `typ == 12` → `path_in_extensions`.

Other types fall back to `filter(typ, arg)`, which is still usable as a placeholder.

### 5.6 Parsing a handler tree: `parse_filter`

```python
def parse_filter(data, offset_words):
  base = offset_words * 8
  if base >= len(data):
    return (True, "<invalid-offset>")
  is_terminal = data[base] == 1
  if is_terminal:
    result = data[base + 2] if base + 2 < len(data) else 0
    resultstr = {0 : 'allow', 1 : 'deny'}.get(result & 1, f'unknown-{result & 1}')
    resultstr += {0 : '', 2 : '-with-log'}[result & 2]
    resultstr += {True : '', False : '-with-unknown-modifiers'}[(result & 0xfffc) == 0]
    return (True, resultstr)
  else:
    if base + 8 > len(data):
      return (True, "<truncated-nonterminal>")
    filter, filter_arg, match, unmatch = struct.unpack_from('<BHHH', data, base + 1)
    return (False, (filter, filter_arg), parse_filter(data, match), parse_filter(data, unmatch))
```

Each handler node is represented recursively as:

* Terminal node:

  ```python
  (True, "allow-with-log")  # or similar
  ```

  * `data[base] == 1` → terminal.
  * `result` byte is decoded:

    * Low bit: `0 → allow`, `1 → deny`, others → `unknown-<value>`.
    * Bit 1 (`0x2`): `-with-log` suffix.
    * Any other bits → `-with-unknown-modifiers`.

* Non-terminal node:

  ```python
  (False, (filter_type, filter_arg), left_subtree, right_subtree)
  ```

  * `filter_type` and `filter_arg` are decoded from `<BHHH`.
  * `match` / `unmatch` are two 16-bit word offsets.
  * Recursively parse both branches with `parse_filter`.

This structure retains the full decision tree, including nested boolean conditions.

### 5.7 Converting a tree to a more readable “pfilter” form

Inside the main loop over handlers, `sbdis` defines `make_pfilter`:

```python
  def make_pfilter(filter):
    pfilter = []
    while filter is not None:
      if filter[0]:
        pfilter.append(filter[1])
        filter = None
      else:
        typ, arg = filter[1]
        true_filter = filter[2]
        false_filter = filter[3]

        if not true_filter[0] and \
           not false_filter[0]:
          pfilter.append(('if', show_filter(typ, arg, regex_table),
            make_pfilter(true_filter), make_pfilter(false_filter)))
          filter = None
        elif true_filter[0]:
          pfilter.append((true_filter[1], show_filter(typ, arg, regex_table)))
          filter = false_filter
        elif false_filter[0]:
          ff = 'true'
          if false_filter[1] == 'true':
            ff = 'false'
          pfilter.append((ff, show_filter(typ, arg, regex_table)))
          filter = true_filter
    return pfilter
```

This is a **pretty-printer** for the decision tree:

* It consumes the recursive `(terminal?, ...)` structure and produces a list of “clauses” (`pfilter`).
* It handles three core patterns:

  1. Both branches are non-terminal:

     * Represent as an explicit `('if', condition, then_branch, else_branch)` node.
  2. `true_filter` is terminal:

     * Represent the condition as “if condition then `<result>`”, and then continue walking the false branch.
  3. `false_filter` is terminal:

     * Represent as something like `(true/false, condition)` depending on the value, then continue on the true branch.

Conditions use `show_filter(typ, arg, regex_table)` so they read like:

* `path.match("...")`
* `mach-global.match("...")`
* `file-mode == 0755`
* etc.

Terminal results are strings like:

* `"allow"`, `"deny"`,
* `"deny-with-log"`,
* `"allow-with-unknown-modifiers"` if unknown bits are present.

Finally, for each handler:

```python
  pfilter = ([ops[op] for op in op_list], make_pfilter(filter))
  pprint.pprint(pfilter)
```

* `op_list` is all operations that share this handler offset.
* `[ops[op] for op in op_list]` gives their names.
* `pfilter` is the pretty-printed decision tree.

The final printed structure is:

```python
(['file-read*', 'file-read-data', ...],
  [('deny-with-log', 'path.match("/secret/...")'),
   ('allow', 'true'),
   ('if', 'path.match("...")', [...], [...]),
   ...])
```

which is easy to read and diff.

---

## 6. Overall workflow for legacy profiles

Putting this together, the `sbdis` example provides:

1. **Format knowledge**: `sb_format.txt` documents the early decision-tree layout.
2. **Profile slicing**: `sbdis.py` uses `profile_ingestion` to locate:

   * op table,
   * regex literals,
   * header metadata (operation count, regex count, format variant).
3. **Regex decoding**: `redis.py` converts compiled AppleMatch NFA blobs to textual regexes.
4. **Operation naming**:

   * `ops.txt` for iOS.
   * `find_operations.py` for OS X/macOS (dynamic extraction from `Sandbox.kext`).
5. **Disassembly**: `sbdis.py` reconstructs, per operation:

   * A tree of filter tests and terminal results.
   * A readable representation using predicate strings and `allow/deny` outcomes.

You use it whenever you have an early-format `.sb.bin` and want to see **what decisions** it makes for each operation, expressed in terms of path/regex/mode filters and allow/deny behavior.
