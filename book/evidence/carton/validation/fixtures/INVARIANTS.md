# Decoder Invariants Checklist

Use this checklist when implementing a modern profile decoder. It is parser-agnostic; assertions should hold across variants unless evidence proves otherwise.

- Header/op-table
  - Treat the first 16 bytes as a u16 preamble; the second word is often `operation_count` (must be >0, <2048).
  - If `operation_count` is present, op-table length should be `operation_count * 2` bytes and reside immediately after the 16-byte preamble.
  - Op-table entries are u16 indices into the node array; all entries should be within the node array bounds.
- Node array
  - Modern blobs typically start with 12-byte records: tag (u16), two payload words, and two edge indices.
  - Edge indices must be within the node array length; cycles are allowed but out-of-bounds indices are not.
  - Decision nodes vs filter nodes are distinguished by tag ranges; unrecognized tags should be logged, not silently ignored.
- Literal/regex pool
  - A mostly printable tail exists; parsing should not overrun into op-table/node regions.
  - Regex blobs, if present, should be recorded even if not parsed into NFAs; lengths must not exceed total blob length.
- Safety and bounds
  - All offsets/lengths must be checked before slicing; reject blobs where sections overlap or exceed total length.
  - Preserve unknown/extra bytes (tails) for future analysis rather than discarding them.
- Provenance
  - Record OS/build, blob hash, and any format-variant heuristics alongside parsed output for reproducibility.

If any invariant fails on a known-good blob from `fixtures.json`, treat it as a parser bug or a format-variant clue and document it.
