# Op-table vs Operation Mapping Experiment (Sonoma host)

Goal: empirically tie operation names (SBPL ops) to op-table entry indices and observed graph entrypoints in compiled profiles, so we can ground the “Operation vocabulary map” and per-operation graph segmentation claims. Keep everything reproducible and versioned using only local tooling and probes.

---

## 1. Setup and scope

- [x] Define the operation set to probe:
  - core filesystem ops: `file-read*`, `file-write*`
  - IPC: `mach-lookup` (fixed global-name e.g., `com.apple.cfprefsd.agent`)
  - network: `network-outbound`
  - baseline/no-op profile (deny default, no allows)
- [x] Create minimal SBPL profiles under `sb/`:
  - [x] Single-op profiles for each op above.
  - [x] Paired-op profiles that differ by exactly one operation (for delta analysis).
- [x] Add a slim wrapper (`analyze.py`) to emit:
  - `op_count`, `op_entries`
  - stride-12 tag counts and remainders
  - literal pool ASCII runs

Deliverables:
- `sb/*.sb` variants + compiled blobs under `sb/build/`.
- `out/summary.json` (per-variant structured data).
- A correlation artifact `out/op_table_map.json` that attempts to map op names → op-table index guess.

---

## 2. Data collection and correlation

- [x] Compile all `sb/*.sb` variants via libsandbox.
- [x] Run analyzer/wrapper to produce `out/summary.json`.
- [x] Build a simple correlation pass:
  - [x] Compare single-op vs paired-op profiles to see which `op_entries` value changes or appears.
  - [x] If op-table entries are uniform, record that and fall back to node/tag deltas for hints.
  - [x] Emit `out/op_table_map.json` keyed by profile → op_entries, plus inferred op→index notes.
  - [x] Record filters present per profile (via vocab) to enable filter-aware alignment downstream.

---

## 3. Cross-check with semantic probes (optional stretch)

- [x] Reuse the shared decoder (`book.graph.concepts.validation.decoder`) to:
  - [x] Walk from each op-table entrypoint into the node array and collect per-entry `tag_counts` and reachable literals as structural “signatures”.
- [ ] Run existing semantic probes (e.g., `network-filters`, `mach-services`) with logging of SBPL op names and annotate traces with the op-table slot and structural signature inferred from compiled profiles.
- [ ] Write `out/runtime_usage.json` with op names, any inferred op-table index, associated signature, and observed behavior.

---

## 4. Documentation and reporting

- [x] Keep running notes in `Notes.md` (dated entries).
- [x] Summarize findings and remaining open questions in `ResearchReport.md`.
- [x] Version all outputs by host/OS if needed (Sonoma baseline).

---

## 5. Open questions to resolve

- [ ] Which op name maps to the distinct op-table entry seen in mixed profiles (e.g., `[6,…,5]` in prior node-layout experiments)? Use decoder-backed per-entry signatures (tag/literal patterns) to narrow candidates, even before vocab IDs are known.
- [ ] Does the position of a non-uniform entry move when adding/removing specific ops? Re-run `analyze.py` with decoder integration and track per-entry signatures across profile variants.
- [ ] Can node/tag deltas (with uniform op-tables) provide secondary evidence for op→entry mapping? Use decoder field deltas (tag_counts, literal usage) to distinguish operations that share a bucket.
- [ ] Does introducing filters/literals (e.g., subpath, literal) reintroduce the `[6,…,5]` divergence, and can we pin the lone entry to an op vocabulary slot once vocab is available?
- [ ] For filtered ops (e.g., `file-read*` with subpath), why does the op-table bucket shift (4→5), and does the `[6,…,5]` split come from mach, subpath, literal filters, or their interaction? Design deltas to isolate this (e.g., read+literal only, mach+literal only, mach with/without filters), and analyze them through decoder-backed signatures.
