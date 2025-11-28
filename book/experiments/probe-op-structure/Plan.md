# Probe Op Structure Experiment (Sonoma host)

Goal: design and run a set of SBPL probes with richer, varied structure to extract clearer mappings between operations, filters (and their `field2` encodings), and op-table behavior. This experiment should complement the field2-focused work by using more complex profiles (multiple filters, layered ops) to surface filter-specific nodes beyond the generic path/name scaffolding.

---

## 1) Scope and setup

- [ ] Record host baseline (OS/build, kernel, SIP) in `ResearchReport.md`.
- [ ] Confirm vocab artifacts (`validation/out/vocab/ops.json`, `filters.json`) are `status: ok`.
- [ ] Identify prior experiments to reuse/compare: `field2-filters`, `op-table-operation`, `node-layout`.

Deliverables:
- `Plan.md`, `Notes.md`, `ResearchReport.md` in this directory.
- A structured probe matrix describing intended SBPL variants.

## 2) Probe design (structure matrix)

- [ ] Define families of probes that vary:
  - **Operation mix**: single-op vs mixed ops (file/mach/network/iokit).
  - **Filter diversity**: multiple distinct filters in one rule, filters across different ops, nested `require-any`/`require-all`.
  - **Literal/context clues**: include filters with strong literal anchors (paths, mach names, iokit classes) to aid identification.
  - **Meta-filter shape**: deep vs shallow combinations to force additional nodes/branches.
- [ ] Document the probe matrix (profile name → ops/filters/metafilters) before implementation.

Deliverables:
- Probe matrix written in `Notes.md` or a dedicated table.

## 3) Implementation and compilation

- [ ] Author SBPL profiles per the matrix; keep them small but structurally rich.
- [ ] Compile via `libsandbox` into `sb/build/*.sb.bin`.
- [ ] Capture compile logs/errors in `Notes.md`.

Deliverables:
- `sb/` source files and compiled blobs under `sb/build/`.

## 4) Decoding and traversal

- [ ] Decode each blob with `decoder.decode_profile_dict` and/or `profile_ingestion`.
- [ ] For each profile:
  - Record op-table entries (with full vocab length).
  - Walk graphs from relevant op entries; collect `field2`, tags, and literals encountered.
  - Where possible, tie literals (paths, names) to specific filters for context.

Deliverables:
- Machine-readable summaries (JSON) of per-profile traversals and `field2` findings.

## 5) Analysis and mapping

- [ ] Compare `field2` sets across probes to isolate filter-specific values.
- [ ] Check cross-op consistency for shared filters.
- [ ] Note any structural patterns (tags, branch shapes) that correlate with particular filters.

Deliverables:
- Updated `ResearchReport.md` with provisional mappings and structural observations.

## 6) Guardrails and reuse

- [ ] Add a small assertion script/test to verify key mappings found here.
- [ ] Document how these probes can be reused by other experiments (field2 mapping, op-table alignment).

Deliverables:
- Guardrail script/test (if mappings emerge), plus usage notes in `Notes.md`.
