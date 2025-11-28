# Node Layout Experiment – Running Notes

## 2025-11-27 1

- Baseline blob: `book/examples/sb/build/sample.sb.bin` (583 bytes). Heuristic slices:
  - op_count=9 → op-table length 18 bytes (offset 0x10..0x21).
  - nodes: ~395 bytes.
  - literals/regex: starts at offset ~0x1ad (429), length ~154 bytes. Literal tail shows strings: `/etc/hosts`, `usr`, `dev`, `system`, `/tmp/sb-demo`.
- Quick stride scan on node region:
  - stride 8: tags {0,1,2,3,5,7,8}, all edges in-bounds (interpreting two u16 edges), distinct edges ~6.
  - stride 12: tags {0,3,5,7,8}, edges in bounds 63/64, distinct edges ~8.
  - stride 16: tags {1,3,7,8}, edges in bounds 48/48, distinct edges ~3.
  - 12-byte stride looks promising: more tags than 16, fewer junk tags than 8; edge fields mostly small/bounded.
- Sample record dump @stride=12 (fields: tag, edge1, edge2, literal_idx?, extra):
  - (0, 8, 8, 7, 8, extra=08000700)
  - (1, 7, 7, 8, 8, 08000500)
  - (2, 5, 5, 5, 8, 08000700)
  - (3, 8, 3, 3, 3, 03000300)
  - … many records with tags 7/8 and edges 7/8; occasional literals 1/2 near later records.
  - Offsets suggest: byte0=tag, bytes2-3=edgeA, bytes4-5=edgeB, bytes6-7=literal/regex index candidate.
- Literal region starts at offset 429; many node records show lit index 8 or 3. Need a variant profile to see lit index changes.
- Next steps (not yet done):
  - Compile minimal SBPL variants (single operation; add one `subpath` literal, then change literal) to diff node bytes and confirm which field is the literal index.
  - Automate scoring over strides/fields; check that literal field points into literal pool (index×? lands near `/tmp/...` offsets).
  - Apply candidate layout to `airlock.sb.bin`/`bsd.sb.bin` to see if stride/tag pattern holds and if edges stay in bounds.

## 2025-11-27 2

- Created minimal SBPL variants under `book/experiments/node-layout/sb/`:
  - `v0_baseline`: allow `file-read*` only.
  - `v1_subpath_foo`: allow `file-read*` with `(subpath "/tmp/foo")`.
  - `v2_subpath_bar`: same with `/tmp/bar`.
  - `v3_two_filters`: `(require-all (subpath "/tmp/foo") (subpath "/dev"))` on `file-read*`.
- Compiled with `sandbox_compile_string`:
  - v0 len=440, ops=5, nodes=387, literals=27.
  - v1/v2 len=467, ops=6, nodes=365, literals=74.
  - v3 len=440, ops=5, nodes=387, literals=27.
- Stride=12 node slices:
  - v1 vs v2: node regions are identical (no differing records), so changing literal from `/tmp/foo` to `/tmp/bar` did not change node bytes (literal table differs; literal pool contains `/tmp/foo` in v1). Suggests literal indices may be encoded elsewhere or nodes reference a shared literal index that didn’t change across these two strings.
  - v0 vs v1: 31 records differ; op_count increases (5→6) and literals grow. Indicates adding a `subpath` filter changes node region but not in a way that distinguishes foo vs bar.
  - v0 vs v3: 2 differing records; both have same op_count (5). Diffs show only literal index changes (e.g., record 2 lit 3→4) and tag change in record 3 (3→4). Hypothesis: adding a second filter tweaks literal indices but keeps node count constant when op_count unchanged.
- Literal pools:
  - v0/v3 literals are short, no path strings visible (pure metadata?).
  - v1 literals contain `/tmp/foo`; v2 literals contain `/tmp/bar`. Node bytes unchanged between v1 and v2, so literal index field at bytes6-7 may be a small ID independent of the literal table position, or the literal pool order is fixed and both literals share the same index bucket.
- Open questions:
  - How to map literal indices to actual offsets; current heuristic doesn’t link node field to literal pool address.
  - Whether a different filter type or additional literal would change the node bytes enough to isolate the literal index field.
- Next steps:
  - Add a profile with two distinct literals for the same filter type (e.g., two subpaths) to see if node records diverge.
  - Try stride 8/16 again on v1/v2 to see if any field changes with foo→bar.
  - Consider parsing the op-table entrypoints to anchor which records belong to which operation.

## 2025-11-27 3

- Added open questions to Plan.md (literal index mapping, multiple literals, filter key location, op-table anchoring).
- Still need a variant with two distinct literals in the same profile to force literal index differences; current v1 vs v2 suggests literal field isn’t simply “literal pool offset.”
- Possible next probes:
  - Profile with `(allow file-read* (require-any (subpath "/tmp/foo") (subpath "/tmp/bar")))`.
  - Profile with different filter types (e.g., `literal` vs `subpath`) to see if tag or field changes more clearly.
  - Use op-table entrypoints to segment node array per operation and see if edge fields line up with op_count changes (5→6).

## 2025-11-27 4

- Added variants:
  - `v4_any_two_literals`: `(allow file-read* (require-any (subpath "/tmp/foo") (subpath "/tmp/bar")))`.
  - `v5_literal_and_subpath`: `(allow file-read* (require-all (literal "/etc/hosts") (subpath "/tmp/foo")))`.
- Compiled all variants with `sandbox_compile_string`:
  - v4: len=481, ops=6, nodes=403, lits=50.
  - v5: len=440, ops=5, nodes=387, lits=27.
- Diffs:
  - v1 (`/tmp/foo`) vs v4 (foo+bar): node region lengths differ (365 vs 403) but **no differing records** when comparing common prefix; literal pool differs (contains both foo/bar). Suggests added literals/operators are appended beyond the smaller node array; shared prefix identical. Literal index still not visible in shared records.
  - v1 vs v5 (literal + subpath): 30 differing records, node length increases to 387. This profile introduces a `literal` filter and keeps op_count at 5; indicates new nodes inserted for the extra filter type.
  - v0 (baseline) vs v5: only 2 differing records; both node arrays 387 bytes. Adding `(literal "/etc/hosts")` + subpath without increasing ops tweaks a couple of records (likely the filter nodes) but not the whole shape.
  - v1 vs v2 (foo vs bar): still identical nodes; literal pool differs.
  - v1 vs v4 literal pools: v4 shows `/tmp/foo` and `/tmp/bar` strings; nodes unchanged in shared prefix.
- Observations:
  - Literal strings move into the pool, but node fields for shared regions remain unchanged. Likely literal references are via IDs or the differing nodes live beyond the shorter node array (v4 has extra nodes after the shared prefix).
  - Tag/edge pattern at stride 12 still plausible; need to segment nodes per operation using op-table entrypoints to see which records are new for the added filter(s).
- Next steps:
  - Use op-table entrypoints (first 9 u16s) to derive entry node indices and map which node ranges are actually used by each operation; compare v1 vs v4 in the non-shared tail.
  - Add a variant with two different filter types on the same op but keeping op_count constant, then diff with op-table-aware segmentation.
  - Write a small analyzer to list op-table entries and dump per-op node slices for comparison across variants.

## 2025-11-27 5

- Wrote a quick diff/analyzer to compare node records at stride 12 and to dump op-table entries.
- Diff results:
  - v1 (`/tmp/foo`) vs v4 (foo+bar) still shows zero differing records in the shared prefix; node lengths differ (365 vs 403 bytes), suggesting extra nodes beyond the shared range. Node lengths are not multiples of 12, reinforcing that stride might be an approximation or that trailing data is partial.
  - v1 vs v5 (literal+subpath) shows many differing records in the prefix (first 20 diffs all in early records), indicating that introducing a literal filter changes node records even when op_count stays at 5.
  - v0 vs v5 shows only 2 differing records despite identical node lengths; adding literal+subpath tweaks a couple of nodes when starting from the baseline.
- Op-table entries for all variants are uniform:
  - v0/v5: op_count=5, op entries [4,4,4,4,4].
  - v1/v4: op_count=6, op entries [5,5,5,5,5,5].
  This suggests entrypoints are consistent across ops in a profile and may simply index the first node; does not help segment nodes per op yet.
- Observations:
  - Literal pool contents differ as expected (v4 pool has both foo/bar; v5 pool minimal), but node fields in the shared prefix don’t reflect literal changes.
  - Non-multiple-of-stride node lengths hint that either stride≠12 or the node region includes variable-length/trailer data; need to reconsider stride or allow for trailing metadata.
- Next steps:
  - Examine the extra tail nodes in v4 beyond the v1 length to see if literal references live there.
  - Revisit stride assumption: test 8/16 on new variants and check how many full records fit; consider that records might not be fixed-size.
  - Use op-table entry 4/5 as a starting index to walk nodes (if tags can be interpreted as branch/terminal) to see which nodes are reachable per op.
- Tail inspection (v1 vs v4):
  - v1 has 30 full 12-byte records + 5-byte tail; v4 has 33 full records + 7-byte tail. Extra v4 records include a tag0 record with edges (1,4) and a record with an out-of-bounds edge value (3584), plus partial trailing bytes. This casts doubt on fixed 12-byte stride and suggests variable-length or packed structures; stride may still be a useful approximation for the front of the node array but not the tail.

## 2025-11-27 6

- Re-ran stride checks on v1 and v4 across strides 8/12/16:
  - All strides produce full records plus remainders; edge counts mostly in-bounds but v4 at stride 8 shows 96/100 in-bounds (some edges point past node array), supporting the idea that fixed stride is only an approximation.
  - Tag sets stay small (e.g., stride 12 tags {0,1,4,5}).
- Op-table entrypoints are uniform (all 5s) in v4; listing records starting at entry 5 shows a run of tag 5/4 nodes with small edges/lits, offering no per-op differentiation.
- Examined v4 nodes beyond v1’s length (records 30–32 at stride 12):
  - rec30: tag5, edges (5,4), lit=0
  - rec31: tag0, edges (1,4), lit=5
  - rec32: tag4, edges (5,3584 out-of-bounds), lit=1
  - Remaining partial tail bytes: 7 bytes. These reinforce that the tail layout may not follow the assumed stride or that some fields encode non-edge data.
- Current status:
  - Stride=12 still the best low-noise view for the front of the node array, but tails are messy (remainders, odd edge values).
  - Literal references are still not observable in shared prefixes; added nodes in v4 carry lit values 0,5,1 but without a mapping to literal pool offsets.
- Next steps:
  - Consider a variable-length parse: treat tags as node types with differing sizes (speculate on tag→size mapping by measuring remainders).
  - Alternatively, step back and extract op-table entry values and literal pool indices as separate artifacts for vocab, acknowledging that precise node decoding may require external references.
  - If time, draft a tiny analyzer to brute-force tag→size hypotheses to explain remainders and out-of-bounds edges; otherwise, capture the current limits.

- Persisted tooling/output:
  - Added `book/experiments/node-layout/analyze.py` to compile SBPL variants, emit blobs, and write `out/summary.json` (lengths, op entries, section lengths, stride stats, tail records).
  - Running with `PYTHONPATH=. python3 book/experiments/node-layout/analyze.py` regenerates build blobs and structured summaries for future analysis.

## 2025-11-28 1

- Tried to infer variable-size nodes by mapping tags→{8,12,16} to match total node length on v1; no exact mapping found (brute force failed).
- Stride scan recap across v1/v4/v5: tags stay small; node lengths produce remainders for all tested strides; edges mostly in-bounds, suggesting stride=12 is a workable approximation only for the front.
- Literal pool previews:
  - v1 literals len 74, binary header-like data then paths; v4 literals len 50 with `/tmp/foo` and `/tmp/bar`; v5 literals len 27, no paths.
- Remaining blockers:
  - Node layout still unclear (tails, tag→size mapping unresolved).
  - Literal references in node fields not identified; op-table entries are uniform and unhelpful for segmentation.
- Next actionable step (not yet done): store `out/summary.json` (done) and consider exporting literal pools/op-entries separately for vocab seeding even without full node decode.
- Persisted tooling/output:
  - Added `book/experiments/node-layout/analyze.py` to compile SBPL variants, emit blobs, and write `out/summary.json` (lengths, op entries, section lengths, stride stats, tail records).
  - Running with `PYTHONPATH=. python3 book/experiments/node-layout/analyze.py` regenerates build blobs and structured summaries for future analysis.
## Narrative (Codex)

Started by slicing the existing `sample.sb.bin` to establish a baseline: the heuristic split yields a small op-table, a ~395-byte node region, and a literal tail with obvious strings; stride=12 looked most promising for node records. Generated minimal SBPL variants to force controlled changes: a baseline allow-only profile, single subpath (`/tmp/foo`), same subpath with `/tmp/bar`, and a two-filter require-all. Compiling these showed op_count bumps and node/literal size changes; stride-based diffs revealed that changing foo→bar didn’t alter node bytes, while adding filters did. Added more targeted variants (require-any with two subpaths; literal+subpath) to tease out literal and filter key fields. The two-subpath variant lengthened the node region but kept the shared prefix identical; literal pools differed. Adding a literal filter introduced more node differences. Literal strings reliably appear in the pools, but the node fields referencing them remain opaque in shared regions. Plan is to use op-table entrypoints to map nodes to operations and compare non-shared tails, and to probe mixed filter types further. Throughout, kept notes of stride/tag patterns and the need for a small analyzer to automate per-op slicing and scoring.

## Narrative (Chat)

We began by taking a careful “first cut” through `sample.sb.bin`, using the existing heuristic to separate the op-table, node region, and literal tail. That initial pass already showed the essential structure the substrate promises: a compact operation pointer table, a dense block of policy nodes, and a trailing pool of human-readable strings like `/etc/hosts` and `/tmp/sb-demo`. A quick stride analysis over the node region suggested that treating each node as a 12-byte record produced a small, stable set of tag values and in-bounds successor indices, which made stride=12 a reasonable working hypothesis for the node layout.

To probe the layout, we then constructed a series of tiny SBPL profiles that differed in exactly one respect: a baseline profile that simply allows `file-read*`, a version that adds a single `(subpath "/tmp/foo")` filter, a clone that flips the literal to `/tmp/bar`, and another that uses `(require-all (subpath "/tmp/foo") (subpath "/dev"))`. Compiling these with `sandbox_compile_string` and comparing node regions showed that adding filters changes the node bytes and op-count, while changing `/tmp/foo` to `/tmp/bar` leaves the node bytes identical but alters the literal pool. This pattern told us that literals clearly live in the pool, but the node fields that refer to them are not obviously tied to the literal’s raw position.

From there, we introduced more focused variants to stress “multiple literals” and “mixed filter types”: a profile that uses `require-any` over two subpaths (`/tmp/foo` and `/tmp/bar`), and one that combines a `literal "/etc/hosts"` with a `subpath "/tmp/foo"` in a `require-all`. The require-any profile increased the node region length but kept the shared prefix identical with the single-subpath case, while the literal+subpath profile changed a slice of records without altering op-count. Across all of these, the literal pools evolved exactly as expected—new strings appeared where they should—but the node bytes in the shared regions remained opaque, reinforcing the idea that node fields likely hold compact IDs rather than raw literal offsets.

Taken together, these steps give us a progressively tighter picture of the graph layout: we have a plausible stride, a sense of how adding filters and literals perturbs the node region, and confirmation that literal tables behave as a separate pool. The remaining work is to anchor nodes to specific operations via the op-table, examine the non-shared tails where new filters live, and build a small analyzer that can systematically test candidate field layouts for tags, edges, filter keys, and literal indices across all these controlled variants.

## 2025-11-28 2

- Added two more SBPL probes: `v6_read_write.sb` (allow `file-read*` + `file-write*`) and `v7_read_and_mach.sb` (allow `file-read*` + `mach-lookup` on `com.apple.cfprefsd.agent`).
- Enhanced `analyze.py` to emit full stride=12 record dumps, per-tag counts, literal ASCII runs with offsets, and to keep the existing tail/remainder view.
- Regenerated all blobs/summaries. `summary.json` now carries `records_stride12`, `tag_counts_stride12`, `remainder_stride12_hex`, and `literal_strings` per variant for deeper offline inspection.
- Observations:
  - `v6_read_write` keeps op_count=5 with uniform op entries `[4,...]` and node length 387 (same as baseline), but the first few stride=12 records shift (indices 3–5 swap tag4/tag3 patterns) and tag counts move (tag3: 15 vs 13, tag4: 15 vs 17). Literal pool still has no ASCII runs. Adding a second operation did not diversify the op-table; dispatch is still hidden in the shared graph.
  - `v7_read_and_mach` lands at op_count=6 with op entries `[5,...]`, node length 365 (same shape as the single-subpath profile), and a literal string `Wcom.apple.cfprefsd.agent` in the pool. Stride=12 counts match the subpath case (tags {0:1,1:1,4:6,5:22}); only a couple of records differ (indices 2 and 14 swap edge/extra values), suggesting the mach-lookup op uses the same entrypoint skeleton with small tweaks rather than a separate op-table entry.
- Cross-cutting: even with multiple operations in one profile, the op-table still points every operation ID at the same entry index. Per-op segmentation remains unsolved; whatever per-op branching exists is buried in the node graph rather than the table.

## 2025-11-28 3

- Added mixed-op probes to stress per-op entrypoints:
  - `v8_read_write_dual_subpath.sb`: `file-read*` on `/tmp/foo`, `file-write*` on `/tmp/bar`.
  - `v9_read_subpath_mach_name.sb`: `file-read*` on `/tmp/foo`, `mach-lookup` for `com.apple.cfprefsd.agent`.
  - `v10_read_literal_write_subpath.sb`: `file-read*` with `literal "/etc/hosts"`, `file-write*` with `subpath "/tmp/foo"`.
- Analyzer now emits per-tag counts and full stride=12 record dumps; reran it to refresh `out/summary.json` with the new variants.
- Observations:
  - All three mixed-op profiles jump to `op_count=7` and, for the first time, op-table entries are not uniform: `[6, 6, 6, 6, 6, 6, 5]`. This is the first hint of differentiated entrypoints by operation ID, though the vocabulary map is still unknown.
  - Tag sets now include tag6; tag counts sit around {0:1,1:1,3:2?,5:5,6:23–25}. Early stride=12 records show the main differences across variants (indices ~3–5, 14). For example, v8 vs v9 flips literals/edges at indices 3–5 (lit 3→6, tag6↔tag3) and index 14 extra bytes swap `06000600`/`03000600`.
  - Node lengths differ slightly: v8/v9 have 32 stride=12 records plus a 2-byte remainder; v10 has 31 records with an 11-byte remainder, suggesting a small structural shift when using `literal` on the read side.
  - Literal pools show prefixed strings: `G/tmp/foo`, `G/tmp/bar`, `Wcom.apple.cfprefsd.agent`, `I/etc/hosts`. The leading letters likely encode string type/class (global-name vs path vs literal), reinforcing that the pool encodes metadata alongside bytes.
  - Even with two distinct op-table entry values (5 and 6), multiple operations still share the same entry index within a profile; per-op segmentation remains coarse.
- Next: isolate which operation maps to the lone `5` entry by crafting asymmetric profiles (e.g., single-op vs dual-op variants with the same op_count) and watching which op-table slot flips, or augment the analyzer to dump op-table indices alongside guessed operation IDs from the ingestion header if available.

## Narrative (Chat x2)

The node layout experiment opens on 2025-11-27 with a single compiled PolicyGraph: `sample.sb.bin` in `book/examples/sb/build/`. Using the shared ingestion helpers, the agent slices that blob into a 16-byte preamble, a compact operation pointer table (derived from `op_count=9`), a ~395-byte node region, and a literal/regex tail of about 154 bytes containing `/etc/hosts`, `usr`, `dev`, `system`, and `/tmp/sb-demo`. A quick stride scan over the node region tries 8-, 12-, and 16-byte records, treating byte0 as a node tag and the next two u16s as candidate edges. All strides keep most interpreted edges in-bounds, but stride=12 gives the cleanest tag set at the front, with tags clustered in a small range and very few obviously bogus edges. The agent tentatively treats 12 bytes as a working record size for the front of the array and notes bytes 6–7 as a plausible “literal index” field, but also records that the literal pool begins at offset ~429 and that many nodes show candidate literal indices 8 or 3, without yet tying those indices to literal offsets. The initial day ends with a to-do list: build minimal SBPL variants, automate stride scoring, and eventually try the same heuristics on other platform profiles like `airlock.sb.bin` and `bsd.sb.bin`.

Later on 2025-11-27, the agent creates a first suite of synthetic SBPL profiles in `book/experiments/node-layout/sb/`: `v0_baseline` (plain `file-read*`), `v1_subpath_foo` and `v2_subpath_bar` (single `subpath` on `/tmp/foo` vs `/tmp/bar`), and `v3_two_filters` (a `require-all` over `/tmp/foo` and `/tmp/dev`). These are compiled with `sandbox_compile_string` via a small helper, and their blobs are compared under the stride=12 view. The numbers line up as expected: v0 and v3 share `op_count=5` and node length 387, while v1/v2 have `op_count=6`, a slightly shorter node region (365 bytes), and a larger literal pool (74 bytes). Diffing the node regions shows that v1 and v2 are bit-identical despite different literal strings, while v0 vs v1 changes 31 records and v0 vs v3 changes only two, with small shifts in the suspected literal field and a tag flip on one record. This pushes the hypothesis toward “literal references are compact IDs or go through a secondary structure” rather than “node field directly encodes a literal pool offset.” The agent records open questions about mapping literal indices to actual offsets and about whether mixing filter types will make the literal field more obvious.

In a shorter third entry for 2025-11-27, the agent turns these questions into structure: `Plan.md` is updated with explicit open items (literal index mapping, multiple literals, filter key location, op-table anchoring), and a next wave of probes is sketched. The plan calls for a profile that uses `require-any` over two subpaths (`/tmp/foo` and `/tmp/bar`), another that mixes `literal` and `subpath` filters in a `require-all`, and for using op-table entrypoints to segment the node array per operation once there is more than one op in play.

By the fourth entry on 2025-11-27, those probes exist as `v4_any_two_literals` and `v5_literal_and_subpath`. Both are compiled and folded into the same stride-based analysis. v4, with `require-any` over two subpaths, increases both the node and literal regions relative to v1 but keeps the prefix of the node region identical; new nodes appear only in the tail, where stride-12 records start to show out-of-bounds “edges” and extra fields that look less like pure node indices. v5, combining `literal "/etc/hosts"` with the existing subpath, keeps `op_count` at 5, changes only a small slice of node records, and grows the literal pool just enough to hold the new path. At this point the agent has enough examples to say: literal strings reliably live in the tail; the front of the node region behaves as though it were an array of 12-byte nodes; and many of the interesting literal-related nodes seem to live in the messy tail region that no simple stride fully explains.

On 2025-11-28, the agent tries to escape the fixed-stride dead end by hypothesizing variable-size nodes. A brute-force search over tag→{8,12,16}-byte size assignments is run (at least conceptually) to see whether any mapping exactly matches the total node length for v1, but no mapping fits. A recap of stride scans across v1, v4, and v5 shows that tags remain in a small range and node lengths always leave remainders; stride=12 continues to be the best approximation for the front, but the tails stubbornly resist explanation. Literal pool “previews” confirm that v1’s pool (len 74) contains header-like data followed by `/tmp/foo`, v4’s pool (len 50) contains both `/tmp/foo` and `/tmp/bar`, and v5’s pool (len 27) has no obvious paths. The agent concludes that neither the stride heuristic nor simple tag-to-size maps are sufficient, and decides to bank progress by making sure `out/summary.json` is up-to-date and rich enough to support later, more systematic reverse engineering.

At this point, notes are compressed into higher-level narratives: first by a Codex agent, then by a Chat agent with the same context, producing the “Narrative (Codex)” and “Narrative (Chat)” sections that retell the first day’s work in more fluent form while preserving the core sequence.

Subsequent entries on 2025-11-28 move the experiment into mixed-operation territory. The agent introduces `v6_read_write` (allowing both `file-read*` and `file-write*`) and `v7_read_and_mach` (allowing `file-read*` plus a `mach-lookup` on `com.apple.cfprefsd.agent`). At the same time, `analyze.py` is upgraded: it now emits full stride=12 record dumps (`records_stride12`), per-tag counts (`tag_counts_stride12`), printable ASCII runs from the literal pool with offsets, and keeps the existing tail-view and stride statistics. Running the analyzer regenerates `summary.json` with richer data for all variants. The structured summaries show that v6 retains `op_count=5` with op-table entries `[4,4,4,4,4]`, node length 387, and no ASCII literals, but the early stride-12 records and tag counts shift slightly relative to v0, indicating that adding a second operation perturbs the PolicyGraph even when entrypoints look uniform. v7 lands at `op_count=6`, op-table entries `[5,5,5,5,5,5]`, node length 365 (matching the subpath-only profile), and a literal string `Wcom.apple.cfprefsd.agent` in the pool. Stride-12 tag counts mirror the single-subpath case, and only a couple of records differ (indices 2 and 14), suggesting that mach-lookup reuses the same entrypoint skeleton with small modifications. The key takeaway is that even with multiple operations, all operation IDs still point at the same entry index in these small profiles; per-op segmentation remains hidden inside the graph.

The final notes for 2025-11-28 push further into mixed-op probes explicitly targeted at op-table behavior. Three new SBPL profiles appear: `v8_read_write_dual_subpath` (read on `/tmp/foo`, write on `/tmp/bar`), `v9_read_subpath_mach_name` (read on `/tmp/foo`, mach-lookup with the same cfprefsd global-name), and `v10_read_literal_write_subpath` (read with `literal "/etc/hosts"`, write with `subpath "/tmp/foo"`). The analyzer is rerun, now capturing per-tag counts and full stride=12 dumps for the new variants. The resulting `summary.json` shows that all three mixed-op profiles move to `op_count=7` and, for the first time, exhibit non-uniform op-table entries: `[6,6,6,6,6,6,5]`. Tag distributions include a new tag value 6; early records (indices around 3–5 and 14) differ across variants through tag6↔tag3 swaps, lit fields toggling between small IDs like 3 and 6, and “extra” bytes alternating between patterns such as `03000600` and `06000600`. Node region lengths differ slightly—v8 and v9 have 32 stride-12 records plus a 2-byte remainder, while v10 has 31 records and an 11-byte remainder—hinting that the literal-based read path imposes a slightly different structure. Literal pools now expose prefixed strings like `G/tmp/foo`, `G/tmp/bar`, `Wcom.apple.cfprefsd.agent`, and `I/etc/hosts`, which look like string-type markers (path vs global-name vs literal) attached to the payload. Even so, multiple operations still share each of the two observed entry indices, and the notes end with an explicit open task: design asymmetric profiles or extend the analyzer so that the lone `5` in the op-table can be tied back to a specific operation vocabulary ID and, eventually, to a clean per-operation slice of the PolicyGraph.

## 2025-11-29 1

- Goal: push further on per-op entrypoint mapping by stripping profiles down to single-operation cases and adding a network-only probe.
- Added three SBPL variants under `sb/`:
  - `v11_mach_only`: only `mach-lookup` with global-name `com.apple.cfprefsd.agent`.
  - `v12_write_only`: only `file-write*`.
  - `v13_network_outbound`: only `network-outbound`.
- Reran `analyze.py` (with the enriched record/literal output) to regenerate `summary.json` and all blobs.
- Quick read of the new summaries:
  - `v11_mach_only`: `op_count=6`, op-table entries `[5,5,5,5,5,5]`, node length 365, tag counts {0:1,1:1,4:6,5:22}, literal pool shows `Wcom.apple.cfprefsd.agent`. This mirrors the `file-read*` subpath case (v1/v2) and the mixed read+mach profile (v7) in both op_table and tag distribution—no per-op differentiation yet.
  - `v12_write_only`: `op_count=5`, op-table `[4,4,4,4,4]`, node length 387, tag counts {0:1,2:1,3:14,4:16}, no ASCII literals. Compared to the `file-read*` baseline (v0), only four stride-12 records differ (indices 2–5): tags/edges flip between tag4/tag3 and lit fields 3↔4. This shows the node region reacting to the operation change, but the op-table stays uniform.
  - `v13_network_outbound`: `op_count=5`, op-table `[4,4,4,4,4]`, node length 387, tag counts {0:1,2:1,3:12,4:18}, no ASCII literals. Diffing against v12 shows four record differences (indices 3–5 and 17), again small tag/edge/lit flips without op-table changes.
- Takeaways:
  - Single-op profiles for `mach-lookup`, `file-write*`, and `network-outbound` still produce uniform op-table entries (all 4s or all 5s, depending on the inferred op_count) and do not reveal which op maps to the distinct entry index observed in the mixed-op `[6,…,5]` case.
  - Even when the op-table is flat, the node region shifts in a small, repeatable way across operations (few record flips near the front, tag count reshuffles). These diffs may be useful later for tag/field attribution, but they don’t yet unlock per-op entrypoint mapping.
  - The standout non-uniform pattern remains the mixed-op profiles with `op_count=7` and `[6,6,6,6,6,6,5]`; isolating which operation claims the `5` entry will likely require asymmetric multi-op profiles or additional analyzer smarts (e.g., correlating op-table index positions across different op_count shapes).

## 2025-11-29 2

- Added two mixed-op variants to probe whether pairing “uniform” ops would induce op-table divergence:
  - `v14_mach_and_network`: `mach-lookup` (cfprefsd) plus `network-outbound`.
  - `v15_write_and_network`: `file-write*` plus `network-outbound`.
- Reran `analyze.py`; the summaries show:
  - `v14`: `op_count=6`, op entries `[5,5,5,5,5,5]`, node length 365, literal pool with `Wcom.apple.cfprefsd.agent`; tag counts {0:1,1:1,4:6,5:22}. Identical to the single-op mach profiles—no new op-table or tag differentiation.
  - `v15`: `op_count=5`, op entries `[4,4,4,4,4]`, node length 387, no literals; tag counts {0:1,2:1,3:14,4:16}. Matches the write-only and network-only profiles; op-table still uniform.
- Takeaway: combining operations that each produce a flat op-table on their own does not surface new entry indices; the op-table stays uniform and node differences remain confined to small record flips. The only non-uniform op-table pattern remains the earlier mixed-op profiles (`v8`–`v10`) with `[6,…,5]`, so further per-op mapping likely requires asymmetric mixes (e.g., pairing one op that yields `op_count=5` with one that forces `op_count=7`), or tooling that can correlate op-table slots to the operation vocabulary.

## 2025-11-29 3

- Tried more asymmetric mixes to see if the lone `5` in `[6,…,5]` would move when we blend “flat” ops with ones that previously diverged:
  - `v16_read_and_network`: read + network → `op_count=5`, op entries `[4,4,4,4,4]`, nodes 387, no literals, tags {0:1,2:1,3:13,4:17}. Uniform.
  - `v17_read_write_network`: read + write + network → `op_count=5`, op entries `[4,4,4,4,4]`, nodes 387, no literals, tags {0:1,2:1,3:15,4:15}. Still uniform despite three ops.
  - `v18_read_mach_network`: read + mach + network → `op_count=6`, op entries `[5,5,5,5,5,5]`, nodes 365, literal `Wcom.apple.cfprefsd.agent`, tags {0:1,1:1,4:6,5:22}. Matches prior read+mach shape.
  - `v19_mach_write_network`: mach + write + network → `op_count=6`, op entries `[5,5,5,5,5,5]`, nodes 365, same literal, tags {0:1,1:1,4:7,5:21}. Uniform.
- Outcome: adding network alongside read/write/mach did not surface new op-table entries; all these combos stayed flat. The only observed non-uniform op-table remains `[6,6,6,6,6,6,5]` in `v8`–`v10`. Next lever is either smarter analyzer correlation of op-table slots to operation vocab or more deliberately asymmetric mixes that reproduce the `[6,…,5]` pattern while varying the operation set to force the `5` into a different slot.

## 2025-11-30 1

- Integrated the shared decoder (`decoder.decode_profile_dict`) into `analyze.py` so each summary now includes a decoder block (`node_count`, decoder `tag_counts`, `op_table_offset`, decoder literals) alongside the existing stride stats.
- Regenerated `out/summary.json` with the decoder fields. The decoder snapshot lines up with prior heuristics:
  - `op_table_offset` is consistently 16 bytes, and decoder `op_count` matches the ingestion header across variants.
  - Node counts land in the low 30s (e.g., v0_baseline: 32 nodes; v11_mach_only: 30).
  - Decoder tag counts mirror the stride-12 view (baseline {0:1,2:1,3:13,4:17}; mach-only {0:1,1:1,4:6,5:22}; mixed op profiles with tag6 still present).
  - Decoder literal strings surface the prefixed forms (`G/tmp/foo`, `I/etc/hosts`, `Wcom.apple.cfprefsd.agent`), reinforcing the literal pool structure without yet exposing index wiring.
- No errors from the decoder or analyzer. The added fields should help the pending tasks (literal index mapping, filter key location, tail layout) by giving a consistent, shared parse rather than relying solely on stride heuristics.

## 2025-11-30 2

- Began chasing literal-index/filter-key hints using the decoder output directly on compiled blobs (not just the summary):
  - Compared node lists across variants with `decoder.decode_profile_dict`. `v1_subpath_foo` vs `v2_subpath_bar` are bit-identical in nodes (node_count=30 each), confirming that changing literal content leaves node bytes untouched.
  - `v1_subpath_foo` vs `v4_any_two_literals` share the first 30 nodes; `v4` appends a single extra node at offset 360 (`tag5`, fields `[5,4,0,0,0]`), suggesting additional `require-any` structure lives in the tail without perturbing the shared prefix.
  - `v1_subpath_foo` vs `v5_literal_and_subpath` differ across all nodes (node_count 30→32), indicating that adding a `literal` filter reshapes the graph more broadly than adding a second `subpath`.
- Focused on the word at byte offsets 6–7 of each node (the decoder’s third field, `fields[2]`), treating it as a candidate “literal/filter index”:
  - Baseline (`v0_baseline`): field2 values {3:12, 4:20} across 32 nodes.
  - Single subpath (`v1_subpath_foo` and `v2_subpath_bar`): field2 values shift to {3:1, 4:9, 5:20}; foo→bar still identical → field2 reacts to filter presence, not literal content.
  - Two-subpath require-any (`v4_any_two_literals`): field2 values {0:1, 3:1, 4:9, 5:20}; the new node carries field2=0, a new value not present in the single-subpath case.
  - Mixed filtered profiles with tag6 (e.g., `v8_read_write_dual_subpath`, `v9_read_subpath_mach_name`, `v10_read_literal_write_subpath`) introduce field2 values 0 and 6 in addition to the prior set, with counts like {0:1, 3:2, 4:1, 5:12, 6:15}.
  - Mach-only and mach+network variants show field2 in {4,5}; write/network-only profiles stay at {3,4}.
- Decoder literal_strings remain imperfect (some prefixed strings show as `D/tmp/`, `Bbar`, etc.), but the field2 patterns are stable per profile. This supports the hypothesis that the word at offset 6–7 carries filter/literal identity (or an indirect key) that depends on which filters are present, not on literal text.
- No direct mapping from field2 → literal pool offset yet; pending: map field2 deltas against literal pool ordering, and correlate new values (0,5,6) with specific filter combinations. Tests remain green after the decoder integration and analysis scripts.

## 2025-11-30 3

- Tried aligning field2 values with literal pool ordering using raw decoder objects:
  - Literal string offsets (searching the literal pool bytes) vary by profile: e.g., `v1_subpath_foo` has `G/tmp/foo` at offset 57; `v4_any_two_literals` has `D/tmp/` at 43, `Bbar` at 50, `\nBfoo` at 61; dual subpath `v8` puts `G/tmp/foo` at 45 and `G/tmp/bar` at 69; `v10` places `I/etc/hosts` at 47 and `G/tmp/foo` at 71. Field2 values do not directly match these offsets.
  - Field2 histograms stay stable per filter mix even as literal offsets move: `v1` vs `v2` have identical field2 counts despite different literal bytes; `v4` adds a single field2=0 node; `v8`/`v9`/`v10` share field2 sets {0,3,4,5,6} even though their literal pools differ (paths vs mach vs literal).
  - Extra tail node in `v4` (`tag5`, fields `[5,4,0,0,0]`) is the only node with field2=0 in that profile; suggests field2=0 marks “second branch” of require-any rather than a literal offset.
  - In tag6-heavy profiles (v8/v9), the nodes containing field2=0/6 are concentrated in tag6 records at the front and tail; field2=6 proliferates (15–17 occurrences) and coexists with many tag6 nodes, hinting that tag6 + field2=6 is the filtered branch machinery.
- Literal pool offsets therefore do not correlate directly with field2 values; field2 appears to be a small key space (0/3/4/5/6) tied to filter presence/structure, not byte positions. Next lever: map specific field2 values to SBPL constructs by designing deltas that introduce/remove one filter at a time and watching which value disappears.

## 2025-11-30 4

- Added two new probes to isolate literal-only behavior:
  - `v20_read_literal`: single `(literal "/etc/hosts")` on `file-read*`.
  - `v21_two_literals_require_any`: `file-read*` with `require-any` over two literals (`/etc/hosts`, `/tmp/foo`).
- Decoder results:
  - `v20` (literal-only) → `op_count=6`, tag counts {0:1,1:1,4:6,5:22}, field2 counts {5:20, 4:9, 3:1}, literals `['I/etc/hosts']`. Field2 set matches the single-subpath case (no field2=0/6), suggesting a single literal alone behaves like “one filtered op” without introducing new keys.
  - `v21` (two literals require-any) → `op_count=6`, tag counts {0:1,1:1,4:6,5:23}, field2 counts {5:20, 4:9, 3:1, 0:1}, literals `['Ftmp/foo', '\\nHetc/hosts']`. Adds exactly one field2=0 node, mirroring the dual-subpath require-any pattern.
- Interpretation: field2=0 tracks “second branch in a require-any” regardless of whether the children are subpath or literal. Field2=5 continues to dominate single-filter cases; field2=6 still only appears in tag6-heavy mixed profiles (mach + filtered read). Literal byte offsets remain unrelated to field2 values. Next action: craft a minimal mach+literal-only profile to see if field2=6 appears without subpath/multi-branching.

## 2025-12-01 1

- Added `v22_mach_literal.sb` (file-read* with `(literal "/etc/hosts")` plus `mach-lookup` for `com.apple.cfprefsd.agent`) to see whether the tag6/field2=6 pattern depends on subpath vs literal when paired with mach.
- Reran `PYTHONPATH=. python3 analyze.py`; regenerated blobs and `out/summary.json`.
- Decoder stats for `v22`: `op_count=7`, op entries `[6,6,6,6,6,6,5]`, tag counts {0:1,5:5,6:25}, field2 histogram {6:17,5:12,4:1,0:1}, literal pool `['I/etc/hosts', 'Wcom.apple.cfprefsd.agent']`.
- The field2/tag pattern matches `v9_read_subpath_mach_name` exactly (same values, `[6,…,5]` op-table split) even though the filter is a literal instead of a subpath. Node bytes differ slightly (node region 383 vs 389 bytes), so filter type still alters structure, but field2 values track “mach + filtered read” rather than the specific filter flavor.

## 2025-12-01 2

- Compared `v9_read_subpath_mach_name` vs `v22_mach_literal` at the decoded node level: decoder `nodes` lists are identical (31 nodes; same tags and fields), but raw node regions differ in length (389 vs 383 bytes) and remainder bytes; literal pools differ as expected. Conclusion: structural graph stays fixed while tail/remainder bytes and literals shift with filter flavor.
- Added `v23_mach_two_literals_require_any.sb` (mach-lookup plus `file-read*` with `require-any` over two literals `/etc/hosts` and `/tmp/foo`) to see if a literal-only branch under mach introduces new field2 values.
- Reran `PYTHONPATH=. python3 analyze.py`; decoder stats for `v23`: `op_count=7`, op entries `[6,6,6,6,6,6,5]`, tag counts {0:1,5:5,6:25}, field2 histogram {6:17,5:12,4:1,0:1}, literals `['Ftmp/foo', '\\nHetc/hosts', 'Wcom.apple.cfprefsd.agent']`, node_count=31.
- Decoder `nodes` for `v22` and `v23` are identical; only literal pools and node-region tails differ (remainder hex `010005000600000e010005` vs `06`). Require-any over literals under mach did not introduce new field2 values (no extra field2=0 beyond the baseline mach+filtered pattern).

## 2025-12-01 3

- Added `v24_three_literals_require_any.sb` (`file-read*` with `require-any` over three literals: `/etc/hosts`, `/tmp/foo`, `/usr/bin/yes`) to stress literal count/order without mach.
- Reran analyzer; decoder for `v24`: `op_count=6`, op entries `[5,5,5,5,5,5]`, tag counts {0:1,1:1,4:6,5:22}, field2 histogram {5:20,4:9,3:1}, literals `['Ftmp/foo', '\\nHetc/hosts', '\\nJusr/bin/yes']`, node_count=30. Notably, `field2=0` disappears (present in the two-literal require-any) and node_count drops by one; the extra branch node is gone.
- Decoder node diff `v21` (two literals require-any) vs `v24` shows a single missing node at index 30 in `v24` (the `tag5` node with `field2=0`). Three-literal require-any seems to compile into a shape that no longer emits the explicit “second branch” marker seen with two children.
- Tail snapshots (stride-12 remainder hex, node bytes vs literals):
  - `v9` vs `v22`: same decoded nodes, node lens 389 vs 383; remainders `0600000e01` vs `010005000600000e010005`; literal lens 92 vs 98.
  - `v22` vs `v23`: same decoded nodes, node lens 383 vs 385; remainders swap (`010005000600000e010005` vs `06`); literal lens 98 vs 104.
  - `v21` vs `v24`: node lens 379 vs 365; remainders `000e0100040005` vs `0500050004`; literal lens 72 vs 102.
- Takeaways:
  - Field2 continues to track filter structure, not literal content; the disappearance of field2=0 in the three-literal case suggests require-any may compile differently once there are more than two branches (possibly balancing or folding the tree without an explicit “second branch” flag).
  - Decoder `nodes` can stay identical across filter swaps while tail bytes and literal pools shift; tail differences are now logged for later modeling.

## 2025-12-02 1

- Added more literal probes:
  - `v25_four_literals_require_any` and `v26_four_literals_require_any_reordered` (same four literals, different order).
  - `v27_two_literals_require_all` and `v28_four_literals_require_all` (require-all over literals).
- Reran analyzer; decoder results:
  - `v25`/`v26`: `op_count=6`, op entries `[5,…]`, tag counts {0:1,1:1,4:6,5:22}, field2 {5:20,4:9,3:1}, literals include all four paths. Decoder `nodes` identical across v24→v25→v26; reordering literals has no effect on nodes. `field2=0` stays absent even with four children.
  - `v27`/`v28` (require-all): `op_count=5`, op entries `[4,…]`, tag counts {0:1,2:1,3:12,4:18}, field2 {3:11,4:21}, decoder literal_strings empty despite literal pool length 27; nodes identical between two vs four literals. Field2 collapses back to {3,4} like the baseline.
- Tail/remainder snapshots:
  - Require-any series: v21 rem `000e0100040005` (len7, lit_len 72) → v24 rem `0500050004` (len5, lit_len 102) → v25/v26 same rem `0500050004` (len5, lit_len 125).
  - Require-all series: v27/v28 rem `010003` (len3, lit_len 27).
- Takeaways:
  - Require-any drops the `field2=0` branch marker once there are ≥3 literals; adding a fourth or reordering literals leaves decoded nodes untouched.
  - Require-all behaves like the baseline field2 set {3,4} regardless of literal count and does not surface literal strings via the decoder (pool still grows). Likely a different combinator path that doesn’t expose branch markers in `field2`.
  - Tail bytes track filter/combinator changes even when decoded nodes stay identical; remainders now cataloged for require-any/all families.

## 2025-12-02 2

- Added more require-any probes to push literal count further:
  - `v29_five_literals_require_any`: adds `/Applications/Calculator.app`.
  - `v30_six_literals_require_any`: adds the Calculator literal plus a font path.
- Analyzer results:
  - `v29`: op-table `[5,…]`, tag counts {0:1,1:1,4:6,5:22}, field2 {5:20,4:9,3:1}, node_count=30, literals length 157; decoder nodes identical to v25 (four literals).
  - `v30`: op-table `[5,…]`, tag counts {0:1,1:1,4:6,5:23}, field2 {5:20,4:9,3:1,0:1}, node_count=31; decoder adds one `tag5` node with `field2=0` at offset 360 (same shape as the two-literal require-any branch marker). Six literals reintroduce the branch marker that disappeared at three–five literals.
- Tail helper (little-endian u16 words) for require-any/all families:
  - Require-any: v21 (2 literals) rem_hex `000e0100040005` → words [3584, 1, 4, 5]; v24/v25/v26/v29 (3–5 literals) rem_hex `0500050004` → words [5, 5, 4]; v30 (6 literals) rem_hex `000e0100040005` → words [3584, 1, 4, 5].
  - Require-all: v27/v28 rem_hex `010003` → words [1, 3].
  - Literal pool lengths scale with literal count (require-any: 72 → 102 → 125 → 157 → 191; require-all fixed at 27).
- Takeaways:
  - Require-any combinator toggles between two tail patterns: `[3584,1,4,5]` when there are exactly 2 or ≥6 literals (and emits a `field2=0` node), and `[5,5,4]` for 3–5 literals with no `field2=0`. Ordering does not matter.
  - Require-all continues to hide literals from the decoder and keeps field2 at {3,4} with a stable tail `[1,3]`, independent of literal count.
  - Tail words appear to encode combinator shape/branching, not literal text; they flip in lockstep with the presence/absence of the branch marker node.

## 2025-12-02 3

- Pushed require-any to 7 and 8 literals (`v31_seven_literals_require_any`, `v32_eight_literals_require_any`).
- Decoder results:
  - `v31`/`v32`: op-table `[5,…]`, tag counts {0:1,1:1,4:6,5:23}, field2 {5:20,4:9,3:1,0:1}, node_count=31; `field2=0` present (single `tag5` node at offset 360); decoder nodes identical to the six-literal case (`v30`).
  - Literal pools keep growing (len 229 / 281) but do not change decoded nodes.
- Tail words (u16) across require-any counts:
  - 2 literals (`v21`): `[3584, 1, 4, 5]` (rem len 7).
  - 3–5 literals (`v24`/`v25`/`v29`): `[5, 5, 4]` (rem len 5).
  - 6–8 literals (`v30`/`v31`/`v32`): `[3584, 1, 4, 5]` (rem len 7).
- Takeaway: require-any shows a bimodal tail/branch pattern—branch marker + `[3584,1,4,5]` for 2 or ≥6 literals; no marker + `[5,5,4]` for 3–5 literals. Ordering stays irrelevant; decoder nodes stabilize per mode.
