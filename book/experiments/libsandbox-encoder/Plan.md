## Aim

Establish how this host’s `libsandbox` encodes filter arguments into the `field2` u16, aligning userland encoder outputs with the known Filter Vocabulary Map (`book/graph/mappings/vocab/filters.json`, status: ok). Treat the kernel as a black box that consumes a raw u16; focus only on what `libsandbox` writes.

## Phases

- **Phase A — SBPL→blob matrix (encoder output view)**
  - Use `book/api/sbpl_compile` + `book/api/decoder` as a black-box compiler/decoder pair.
  - Build a small SBPL matrix over a few operations (`file-read*`, `mach-lookup`, `network-outbound`) crossed with filter/argument shapes (literal path, regex path, socket family/type/proto, iokit class/property, mach anchors).
  - First pass: regex-free (literal/subpath for paths, socket/iokit/mach shapes only); defer regex to a follow-up matrix to reduce confounders.
  - Record per probe: operation, filter name, SBPL argument text, filter_id from `filters.json`, tag, raw `field2`.
  - Confirm `field2 == filter_id` where expected; flag any “weird” encodings and check against high/unknown codes observed in `field2-filters` (16660, 2560, 0xffff, 3584, 10752, etc.).

- **Phase B — libsandbox internals (encoder implementation view)**
  - Inspect the trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/` (static only).
  - Locate emitter paths that build and store the `field2` u16 for filter nodes; identify patterns (raw vocab ID vs ID+flags/indices).
  - Summarize encoder sites in a small JSON (site, filter_id, expression) and narrative buckets: raw ID, packed, unknown/blocked.

## Deliverables

- `out/field2_encoder_matrix.json` (Phase A table) plus SBPL probes under `sb/`.
- `out/encoder_sites.json` (Phase B note-level mapping of encoder expressions).
- Updated `Report.md` with status per phase, evidence pointers, and next steps.

## Status

- Phase A: scoped (ops/filters/args selected); probes and matrix output pending.
- Phase B: not started (heuristics gathered; disassembly pending).
