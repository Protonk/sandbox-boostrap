# Op-table vs Operation Mapping – Notes

## 2025-11-27 1

- Initialized a new experiment under `book/experiments/op-table-operation` to map SBPL operation names to op-table entry indices in compiled profiles.
- Drafted `Plan.md` with a scope focused on core ops (`file-read*`, `file-write*`, `mach-lookup` with `com.apple.cfprefsd.agent`, `network-outbound`, plus a baseline/no-op profile), single-op and paired-op profiles, reuse of the existing analyzer, and a correlation artifact `out/op_table_map.json`.
- Set expectations for artifacts: `sb/*.sb` variants and `sb/build/*.sb.bin` blobs, `out/summary.json` via analyzer/wrapper, and correlation JSON for op-table mapping. Cross-checks with existing semantic probes are noted as an optional stretch.
- Next steps: create the `sb/` variants, wire the analyzer/wrapper, generate `summary.json`, and build the initial op-table correlation.

## 2025-11-29 2

- Created this note block to log execution/troubleshooting while standing up the experiment.
- Added `sb/` variants covering the planned ops:
  - `v0_empty` (deny default only), `v1_read`, `v2_write`, `v3_mach` (cfprefsd), `v4_network`.
  - Paired mixes differing by one op: `v5_read_write`, `v6_read_mach`, `v7_read_network`, `v8_write_mach`, `v9_write_network`, `v10_mach_network`.
- No analyzer wiring yet; next step is to stand up a wrapper (reuse node-layout analyzer or a slim copy) and generate summaries.
- Implemented `analyze.py` in this experiment to compile all `sb/*.sb`, emit `out/summary.json`, and a simple `out/op_table_map.json` that records ops, op_entries, and unique entry values per profile plus single-op hints. Added a literal/tag summary for quick inspection.
- First run exposed a parsing bug: `parse_ops` grabbed the entire `(allow …)` clause (including filter) for `mach-lookup`; fixed regex to capture only the operation symbol and reran.
- Current outputs (post-fix):
  - Single-op profiles: read/write/network share uniform op entries `[4,…]` (op_count=5); mach-only profiles use `[5,…]` (op_count=6).
  - Paired combos: read+write/read+network/write+network remain `[4,…]`; any combo including mach remains `[5,…]`.
  - The baseline `v0_empty` also shows `[4,…]` with op_count=5.
  - `op_table_map.json` now records single-op entries: {read: [4], write: [4], network: [4], mach: [5]} and per-profile unique entries (either {4} or {5}). No non-uniform op-table entries observed in this batch.
- Next steps: craft asymmetric mixes that reproduce the `[6,…,5]` pattern from the node-layout experiment (e.g., include subpath literals) or add analyzer logic to correlate op_table slots across differing op_count shapes; update Plan/Report accordingly.

## 2025-11-29 3

- New goal: reintroduce filters/literals in this op-table experiment to see if the `[6,…,5]` pattern resurfaces and to try to pin the lone `5` to a specific op.
- Added filtered variants:
  - `v11_read_subpath`: read with `(subpath "/tmp/foo")`.
  - `v12_read_subpath_mach`: read with subpath + mach-lookup.
  - `v13_read_subpath_write`: read with subpath + write.
  - `v14_read_subpath_network`: read with subpath + network.
- Reran `analyze.py` to refresh summaries and `op_table_map.json`.
- Results:
  - `v11` (single-op read+subpath): `op_count=6`, op entries `[5,…]`, tags {0:1,1:1,4:6,5:22}, remainder `0500050004`, literal `G/tmp/foo`. This flips read from the earlier `[4,…]` bucket to `[5,…]` when a subpath is present.
  - `v12` (read+subpath + mach): `op_count=7`, op entries `[6,6,6,6,6,6,5]` → the `[6,…,5]` pattern reappears. Tags include 6 (count 25) and 5 (count 5); literals include both path and mach global-name.
  - `v13` (read+subpath + write): `op_count=6`, op entries `[5,…]`, tags {0:1,1:1,4:7,5:21}, literal `G/tmp/foo`.
  - `v14` (read+subpath + network): `op_count=6`, op entries `[5,…]`, tags {0:1,1:1,4:6,5:22}, literal `G/tmp/foo`.
- Takeaways:
  - Adding a subpath filter changes the op-table bucket for `file-read*` from 4 (no filters) to 5 (with subpath), even in single-op form.
  - The mixed profile with subpath+mach brings back the `[6,…,5]` non-uniform entries; the presence of both subpath and mach seems to be the trigger, suggesting the lone `5` may be tied to one of these ops or to a specific parameterized variant.
  - Other mixes with subpath (write, network) remain uniform `[5,…]`; no additional entry indices beyond 5/6 observed so far.
- Next: design targeted deltas to isolate whether the `[6,…,5]` split is driven by mach, by subpath+mach interaction, or by op_count shape; consider adding a pure subpath+write+network triple or toggling subpath off/on within mach profiles to watch op entries move.

## 2025-11-29 4

- Added literal-driven mixes to see whether literals alone provoke the `[6,…,5]` split:
  - `v15_mach_literal`: mach-lookup + `file-read*` with `(literal "/etc/hosts")`.
  - `v16_subpath_mach_literal`: mach-lookup + two read filters (subpath `/tmp/foo` and literal `/etc/hosts`).
- Reran `analyze.py`; results:
  - `v15`: `op_count=7`, op entries `[6,6,6,6,6,6,5]`, tags {0:1,5:5,6:25}, remainder `010005000600000e010005`, literals include `I/etc/hosts` and `Wcom.apple.cfprefsd.agent`. Shows the same `[6,…,5]` pattern without subpath, implying mach+literal is enough.
  - `v16`: `op_count=7`, op entries `[6,6,6,6,6,6,5]`, tags {0:1,1:1,5:5,6:25}, literals include `Ftmp/foo`, `Hetc/hosts`, `Wcom.apple.cfprefsd.agent`. Also `[6,…,5]`; tag1 appears (maybe a different node type for the extra filter).
- Updated `op_table_map.json`: multiple profiles now exhibit `[6,…,5]` (subpath+mach, mach+literal). The lone `5` entry persists, but we still can’t assign it to a specific op.
- Next steps: pause analyzer changes; consider crafting single-op literal profiles (read+literal only) and mach-only with literal to see op_count/entry buckets, and design deltas that toggle mach off while keeping literals to watch op_entries shift (or not). The analyzer may need a correlation pass, but holding off for now per instruction.

## 2025-11-30 1

- Refreshed `analyze.py` to use the shared decoder for each blob and to emit per-entry structural signatures:
  - Each summary now includes a `decoder` block (`node_count`, decoder `tag_counts`, `op_table_offset`, decoder literal strings, section lengths) plus an `entry_signatures` map.
  - Added a new artifact `out/op_table_signatures.json` capturing the per-profile `entry_signatures`.
- Signature method: treat the first two fields of each 12-byte node as edges, walk from each unique op-table entry, and record reachable tags/literal field values (capped at 256 visits).
- Reran the analyzer; op-table entries remain unchanged, but signatures now show:
  - The “4” bucket (empty/read/write/network families) reaches a single tag4 node with literal field 4.
  - The “5” bucket reaches tag5 (and sometimes tag6) with literal field 5; `[6,…,5]` profiles give both entries signatures with tags {5,6}.
  - Walks are shallow (1–2 nodes) because the heuristic edges likely stop quickly, so signatures are best treated as coarse fingerprints, not decoded graphs.
- No decoder errors; outputs regenerated cleanly. Next steps stay focused on using these decoder-backed signatures to correlate buckets across profiles once vocab IDs exist or to design deltas that move the lone `5` entry in the `[6,…,5]` pattern.

## 2025-12-03

- Extended `analyze.py` to parse filter symbols from SBPL (via vocab intersection) and emit `filters` / `filter_ids` alongside `ops`. This keeps per-profile summaries aligned with both operation and filter vocab.
- Reran analyzer with current vocab lengths; regenerated `summary.json`, `op_table_map.json`, and `op_table_signatures.json` with filter annotations intact.

## 2025-12-04

- Pulled a quick bucket→operation ID snapshot using the refreshed alignment: `file-read*` (21), `file-write*` (29), and `network-outbound` (112) show up in buckets {3,4}; `mach-lookup` (96) shows buckets {5,6}, with bucket 6 only in mach+filtered-read mixes. Recorded in the ResearchReport.

## 2025-12-07

- Reran `analyze.py` after decoder updates; summaries and alignment regenerated (no bucket shifts observed). Alignment refreshed via `op-table-vocab-alignment/update_alignment.py`.

## 2026-01-XX

- SBPL wrapper now available (`book/api/SBPL-wrapper/wrapper --sbpl/--blob`); runtime-checks harness can invoke compiled blobs via `run_probes.py`.
- Next actionable: reuse the wrapper to run a small runtime spot-check for representative profiles (e.g., `v1_read`, `v11_read_subpath`) and correlate observed allow/deny with the op-table buckets already mapped.
