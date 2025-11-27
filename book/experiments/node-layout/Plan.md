# Node Layout Experiment Plan

Goal: recover enough of the modern compiled profile node layout to extract node tags, edges, and filter key IDs, so we can generate vocab tables (op/filter IDs) per OS/build/format. This plan assumes only the spine context; no prior debugging state needed.

## Scope

- Target modern graph-based profile blobs produced by `libsandbox` on the current host.
- Do not aim for full decompilation; focus on:
  - Node stride/format (size, tag field).
  - Edge fields (successor indices).
  - Filter key codes and literal/regex indices.
- Use tiny synthetic SBPL profiles to create controlled diffs.

## Inputs

- `book/examples/sb/` to produce small compiled blobs (`sample.sb.bin` and variants).
- System blobs (e.g., `airlock.sb.bin`, `bsd.sb.bin`) for cross-checking patterns.
- Spine concepts: operations, filters, policy nodes, policy graphs, vocab maps.

## Outputs

- Notes and scripts under `book/experiments/node-layout/`.
- A hypothesized node layout per OS/format (stride, tag mask, edge offsets, filter key offset, literal index offset).
- Optional: JSON snippets with extracted node counts and filter key IDs per blob.

## Approach

1. **Generate minimal profiles**
   - Compile a baseline SBPL that denies/permits a single operation without filters.
   - Compile variants that add one filter (`subpath "/tmp/foo"`), another with a different literal, and one with a different operation.
   - Keep blobs small to make diffs readable.

2. **Locate op-table and node region**
   - Reuse the existing heuristic: preamble (0x10 bytes), then op-table (`op_count * 2` bytes).
   - Treat the remainder as candidate nodes + literals; isolate the literal tail by scanning for printable runs.

3. **Hypothesize node stride and tag field**
   - Try common strides (8, 12, 16 bytes) over the node region.
   - For each stride, interpret the first byte/word as a tag; check whether a small set of values repeats.
   - Validate that op-table entrypoints land on nodes with plausible tags.

4. **Find edge fields**
   - For each stride candidate, treat subsequent words as edge indices; check if they fall within node count bounds.
   - Prefer layouts where most edge fields are small integers < node_count and where branching patterns are consistent across variants.

5. **Identify filter keys and literal indices**
   - Look for a field with many distinct values across variants; likely the filter key.
   - Use controlled SBPL changes (different literals, same filter) to see which field changes with the literal index.
   - Use the literal pool offset to verify indices land near string boundaries.

6. **Automate scoring**
   - Write a small script to brute-force stride/field layouts and score candidates:
     - Tags occupy a small set.
     - Edge fields mostly in bounds.
     - Literal index fields point into the literal pool region.
   - Compare scores across baseline and modified profiles to stabilize the hypothesis.

7. **Cross-check with system blobs**
   - Apply the best-fit layout to `airlock.sb.bin` / `bsd.sb.bin` to ensure it scales to larger graphs.
   - Extract node counts and filter key codes; store as provisional vocab evidence.

8. **Document and export**
   - Record the chosen layout per OS/build in a small markdown/JSON note.
   - If stable, add an extractor script to dump op-table, node count, and filter key IDs per blob for downstream vocab generation.

## Success criteria

- A reproducible layout hypothesis that:
  - Yields a consistent node count and sane edge indices on multiple blobs.
  - Recovers filter key IDs and literal indices for simple synthetic profiles.
  - Can be applied to system blobs without obvious corruption (edges in bounds, strings untouched).

## Notes

- Keep experiments self-contained under this directory; do not modify substrate files.
- Prefer small, deterministic SBPL inputs for diffs.
- If the layout remains ambiguous, document the competing hypotheses and their scores; partial progress still informs vocab work.

## Areas to be informed

Nailing down a modern node layout directly improves the **static-format** and **vocabulary/mapping** parts of the book. With trustworthy node and filter-key decoding, we can show concrete PolicyGraph shapes for current macOS, not just schematic diagrams, and back the operation/filter vocab tables with real IDs extracted from live profiles. That makes chapters that talk about compiled profiles, operation pointer tables, and vocab maps (and the associated capability catalogs) much more grounded: every “operation X” and “filter Y” can be tied to bytes in a blob and to observed behavior in a probe.

It also sharpens the **runtime lifecycle and extension** story. Once we can read node counts and filter keys from system profiles, we can correlate scenario probes (containers, extensions, mach, network) with the actual graph fragments they exercise, rather than treating the profiles as opaque. That supports clearer worked examples in the TextEdit and Example.app chapters, where we want to move seamlessly between SBPL snippets, profile graphs, process labels, and extension-driven capability changes.

## Open questions / current unknowns

- Literal index mapping: changing a `subpath` literal (`/tmp/foo` → `/tmp/bar`) did not change node bytes in initial variants, even though the literal pool changed. Need to determine where/how literal indices are encoded and whether they are shared across equal-length literals or normalized differently.
- Multiple literals: unclear how nodes reference multiple literals of the same filter type; need a variant with two distinct literals to see if node records diverge.
- Filter key location: tags and edge fields are plausible at stride 12, but the field carrying filter key codes (vs literal indices) remains unidentified without a known node tag schema.
- Op-table anchoring: mapping node indices back to specific operations may help interpret edge fields; op-table entrypoints are known but not yet used to partition the node array.

## Targeted resolution plan

To resolve the unknowns, run a short battery of controlled variants and automated diffs:

1. **Literal index mapping**
   - Build profiles with multiple literals in the same filter form, e.g., `(allow file-read* (require-any (subpath "/tmp/foo") (subpath "/tmp/bar")))` and a third literal of different length.
   - Diff node records across single-literal vs multi-literal variants; watch the suspected literal-index field (bytes 6–7 at stride 12). If it stays constant, the literal reference may be elsewhere (e.g., a shared ID).
   - Inspect literal pool order to see whether indices are small IDs unrelated to offsets.

2. **Multiple literals mapping**
   - Add variants mixing filter types (e.g., `subpath`, `literal`, `vnode-type`) in otherwise identical profiles. Look for tag or field changes when the filter type changes but literals remain constant.

3. **Filter key location**
   - Use the mixed filter-type variants above to identify a field that varies with filter type. If tags change, map tag values to filter types; if a mid-record word changes, treat it as a key code candidate.

4. **Op-table anchoring**
   - Parse op-table entrypoints (u16 indices) and use them to segment the node array per operation. This can clarify which records belong to which op and how op-count changes affect entry nodes.

5. **Automate diffing/scoring**
   - Write a small analyzer to load variants, test strides (8/12/16), and report fields that change across specific pairs (foo→bar, add filter type, add literal). Score candidates where edges stay in-bounds and literal fields plausibly align with the literal pool.

6. **Cross-check with system blobs**
   - Apply the candidate layout to `airlock`/`bsd` to ensure edges are in bounds and literal indices point into the literal tail. If it holds, extract node counts and filter key IDs as provisional vocab evidence.

This plan targets each open question with a specific variant/diff. It uses controlled changes (literal content, number of literals, filter type) to isolate which node fields encode literals vs keys, and uses op-table entrypoints to anchor node indices. Automated scoring helps choose between stride/layout hypotheses before applying them to system blobs.
