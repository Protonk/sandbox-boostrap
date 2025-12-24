# bsd-airlock-highvals

## Purpose

Track and retire the remaining high/opaque `field2` payloads tied to platform profiles now that the world-scoped stride framing is better understood. The `sys:bsd` “high” cluster is treated as resolved-by-framing (decode artifacts under the earlier 12-byte approximation); the remaining open work is the `sys:airlock` survivors from the current `field2-filters` unknown census (notably `165` and `49171`) plus any probe-only sentinel-like payloads that recur under controlled compilation.

## Baseline & scope

- Host/world: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (project baseline).
- Scope: static compile/decode first; runtime only if needed and feasible. No cross-version claims.

## Prior evidence (static)

- `field2-filters` census and reports contain the canonical sightings and context: [../field2-filters/Report.md](../field2-filters/Report.md), [../field2-filters/Notes.md](../field2-filters/Notes.md), [../field2-filters/Manual-Ghidra.md](../field2-filters/Manual-Ghidra.md), [../field2-filters/out/unknown_nodes.json](../field2-filters/out/unknown_nodes.json), and [../field2-filters/out/field2_inventory.json](../field2-filters/out/field2_inventory.json).
- Tag-layout probing notes the same highs and stride ambiguity for tag 26: [../probe-op-structure/Report.md](../probe-op-structure/Report.md), [../probe-op-structure/out/tag_layout_assumptions.json](../probe-op-structure/out/tag_layout_assumptions.json).
- Literal-bearing tag inventories include these payloads: [../tag-layout-decode/out/tag_literal_nodes.json](../tag-layout-decode/out/tag_literal_nodes.json).
- System profile digests/decodes showing occurrences: [../system-profile-digest/out/digests.json](../system-profile-digest/out/digests.json), [../../graph/concepts/validation/golden_corpus/decodes/platform_airlock.json](../../graph/concepts/validation/golden_corpus/decodes/platform_airlock.json).
- Anchor map currently lacks bindings for these highs (or lists them as unknown): [../anchor-filter-map/Report.md](../anchor-filter-map/Report.md).

## Prior attempts and dead ends

- Targeted SBPL probes aimed at `bsd` literals failed to surface the high payloads outside the full profile: [../field2-filters/sb/bsd_tail_context.sb](../field2-filters/sb/bsd_tail_context.sb), [../field2-filters/sb/dtracehelper_posixspawn.sb](../field2-filters/sb/dtracehelper_posixspawn.sb) (with and without extra mach rules). Decodes showed only low vocab IDs.
- `field2-filters` now records the stride=8 framing update explicitly: the canonical `sys:bsd` “tail” and tag-26 highs disappear under the promoted framing and are treated as decode artifacts. `sys:airlock` still contains a small out-of-vocab set (currently `165` and `49171`) with no anchor binding.
- Kernel immediate searches for key constants (0xa00, 0x4114, 0x2a00) returned zero hits: see `kernel_imm_search` notes in [../field2-filters/Notes.md](../field2-filters/Notes.md).
  - This remains negative evidence only; it does not by itself rule out encoded semantics.

## Deliverables / expected outcomes

- A focused probe matrix (SBPL → compiled blobs → decodes) that can either reproduce or exclude these payloads under controlled variants (especially tag 26 paths for `bsd` and tag 166/1 scaffolding for `airlock`).
- Normalized inventories under `out/` (e.g., decoded node records, unknown/high payload slices) joinable against existing field2 census for cross-checks.
- A characterization or anchor-binding proposal (if found) that can be promoted into atlas/guardrails without hand-editing stable mappings.
- Clear blockers if the values remain opaque (e.g., layout ambiguity, compile gating).

## Plan & execution log

- ✅ Initialize experiment scaffold.
- ✅ First probe pass: compiled/decoded two probes via `run_probes.py` (compiled with `book.api.profile_tools`, decoded with `book.api.profile_tools.decoder` into `out/decode_records.jsonl` / `out/field2_summary.json`).
  - `sb/bsd_tag26_matrix.sb` (right-name + preference-domain + bsd-tail literals + file/process ops) yielded only low/vocab field2 payloads {6,5,0} across tags {5,6}; none of the bsd highs (170/174/115/109/16660) reproduced.
  - `sb/airlock_system_fcntl_variants.sb` (system-fcntl allow/deny matrix + minimal scaffolding) produced low IDs {8,7,3,2,0} and a single hi-bit payload `0xce00` (hi=0xc000, lo=3584) on tag 0; did not reproduce airlock highs 165/166/10752 or sentinel 0xffff. The 0xce00 instance needs follow-up to decide if it is a stable sentinel or incidental node.
- ➖ Second probe pass: added `sb/bsd_tag26_richer.sb` (more right/preference variants, bsd literals, broader ops) and `sb/airlock_system_fcntl_wide.sb` (larger fcntl-command sweep). Both compiled but decode to zero nodes (node_count=0), contributing no records; negative/empty result that likely indicates the compiler collapsed these shapes. No new sightings beyond the earlier 0xce00 payload.
- ➖ Third probe pass (varying system-fcntl context before any decode/stride tweaks): added `sb/airlock_system_fcntl_minimal.sb` (system-fcntl only) and `sb/airlock_system_fcntl_context.sb` (mixed allow/deny + light scaffolding). Reran harness (6 probes total):
  - `airlock_system_fcntl_minimal`: decodes with nodes, only low IDs {4,3}.
  - `airlock_system_fcntl_variants`: unchanged; still low IDs plus a single `0xce00` hi-bit payload (tag 0).
  - `airlock_system_fcntl_context`: node_count=0 (empty); `airlock_system_fcntl_wide` and `bsd_tag26_richer` remain empty; `bsd_tag26_matrix` unchanged with low IDs.
  - Net: airlock highs 165/166/10752/0xffff and bsd highs remain unreproduced; only stable anomaly is the lone `0xce00` hi-bit payload in the variants probe.
- ➖ Fourth probe pass (more fcntl shapes, avoiding stride tweaks): added `sb/airlock_system_fcntl_split.sb` (small allow/deny set plus large command) and `sb/airlock_system_fcntl_gate.sb` (mach-lookup gate + fcntl allow/deny). Harness now skips `.gitkeep` and compiles 8 probes:
  - `airlock_system_fcntl_gate`: only low IDs {7,6,5,4,0}; no highs.
  - `airlock_system_fcntl_split`: low IDs {7,6,0,5,1} and one low payload 1024 (`0x400`); no highs.
  - `airlock_system_fcntl_minimal` and `airlock_system_fcntl_variants` unchanged (variants still the sole source of `0xce00` hi-bit payload). `airlock_system_fcntl_context`, `airlock_system_fcntl_wide`, `bsd_tag26_richer` remain empty; `bsd_tag26_matrix` still only low IDs.
  - Net: target airlock highs and bsd highs still unreproduced; the only non-vocab payload observed locally is `0xce00` in the variants profile.
- ➖ Fifth probe pass (additional minimal shapes): added `sb/airlock_system_fcntl_single0.sb` (single allow) and `sb/airlock_system_fcntl_literal_guard.sb` (file literal + single allow). Harness compiles 10 probes:
  - `airlock_system_fcntl_single0`: only low IDs {4,3}, same as minimal.
  - `airlock_system_fcntl_literal_guard`: only low IDs {5,4,3}; no highs.
  - Other probes unchanged: `variants` still the lone source of `0xce00`; `gate`, `split` stay low-only; `context`, `wide`, `bsd_tag26_richer` remain empty; `bsd_tag26_matrix` remains low-only.
  - Net: still no reproduction of airlock highs 165/166/10752/0xffff or bsd highs; only anomaly is isolated `0xce00` in variants.

## Conclusion (system-fcntl SBPL avenue)

The “vary `system-fcntl` SBPL shape/context” avenue appears exhausted for this host baseline: across ten probe variants (minimal, literal-guarded, gated, split, allow/deny mixes, and wider command sweeps), we did not reproduce the `sys:airlock` high/out-of-vocab payloads (165/166/10752) or the `0xffff` sentinel seen in earlier probes, and several richer variants consistently collapsed to empty graphs (node_count=0). The only stable non-vocab payload surfaced in this family is a single `0xce00` (hi=0xc000, lo=3584) node in `airlock_system_fcntl_variants`, which is not sufficient to characterize the `sys:airlock` cluster without additional layout/decoder work.

## Next (beyond SBPL shape sweeps)

- For `airlock`: prioritize layout/role analysis of the canonical `sys:airlock` blob and comparison against the probe-only sentinels (`0xffff`, `0xce00`) rather than further SBPL shape permutations.
- For `bsd`: pursue non-SBPL routes (layout/edge validation, decoder cross-checks, and/or encoder tracing) to explain tag-26 payloads and the tag-0 hi-bit tail, which have not reproduced in targeted SBPL probes.
- If any characterization becomes stable, propose promotion via atlas/guardrails rather than ad-hoc mapping edits.

## A-first layout check (edge-as-offset)

We started the A-first check (“treat fields[0]/fields[1] as branch offsets”) using a brute stride scan over the canonical `sys:bsd` and `sys:airlock` blobs:

- Script: `stride_offset_scan.py` (experiment-local, does not mutate mappings).
- Output: `out/stride_offset_scan.json`.
- Companion script: `airlock_subgraph.py` (reachability slice for `sys:airlock` under candidate strides).
- Output: `out/airlock_subgraph.json`.
- Slot histogram script: `canonical_slot_hist.py` (12-byte decode view of fields[3]/fields[4]).
- Output: `out/canonical_slots34_hist.json`.

Key early observations (partial; intended to bound where the current decoder/graph-walk is likely misleading):

- `sys:airlock`: interpreting records with stride=12 causes tag-166 branch targets to land frequently on ASCII-looking starts (e.g., `(tag,b1)=(108,116)`), while stride=8 yields tag-166 branch targets that mostly land on non-ASCII `(tag,b1)` pairs with `b1==0` (notably `(166,0)` and `(159,0)`). This supports the hypothesis that the “tiny airlock graph” and out-of-bounds edge behavior are artifacts of a stride/offset mismatch rather than true leaf structure.
- `sys:airlock` reachability witness (system-fcntl root): treating op-table entry index 162 as `system-fcntl` (op-table value 5 in this canonical blob), the reachable set from that root expands under stride=8 (reachable_count=10) but stays tiny under stride=12 (reachable_count=4). See `out/airlock_subgraph.json`.
- `sys:bsd`: for tag 26, field0 behaves like a consistent branch target (always in-range under stride=12 on the canonical node array), but the unknown-high tag-26 nodes have field1 values (e.g., 2560/1536/1792/12800) that do not behave like record indices in the canonical blob. This suggests tag-26 field1 is not uniformly an “edge” field even if it sits in the edge slot under the current layout map.
- Slot 3/4 low-entropy (12-byte decode view): `out/canonical_slots34_hist.json` shows that in canonical `sys:bsd`, tag-26/tag-27 nodes have fields[3]/fields[4] concentrated on {26,27} (with a small number of outliers), suggesting these slots carry compact, tag-local structure rather than unconstrained pointers.
  - Update: after the stride=8 framing cross-check below, this “low-entropy slots” signal should be treated as **framing evidence** (spillover from adjacent 8-byte record headers/fields) rather than evidence that tags 26/27 truly have stable u16 slots beyond the first three u16s.

## Stride=8 framing cross-check (byte-level)

Goal: produce byte-level witnesses that the 12-byte “modern-heuristic” record framing is consuming bytes from adjacent records, and that op-table/branch targets are u16 offsets in 8-byte words.

- Script: `stride8_decoder_crosscheck.py` (experiment-local).
- Output: `out/stride8_decoder_crosscheck.json`.

Key witnesses:

- **bsd spillover witness (fields[3]/fields[4] are framing artifacts)**:
  - At `abs_off=360` (`rel_off=288` from `nodes_base=72`), an 8-byte record view yields:
    - current: `tag=26 kind=0 fields=[26,27,27]`
    - next begins at `abs_off+8`: `tag=26 kind=0 fields=[27,27,27]`
  - A 12-byte record view at the same offset necessarily consumes 4 bytes from the next 8-byte record:
    - 12-byte fields: `[26,27,27,26,27]` where `fields[3]=26` is the next record’s `(tag,kind)` read as a u16, and `fields[4]=27` is the next record’s first u16.
  - This collapses the “what do fields[3]/fields[4] mean?” blocker for tags {26,27} in `sys:bsd`: those values can be an artifact of a 12-byte framing imposed on an 8-byte stream.

- **airlock op-table scaling witness (scale=8 vs scale=12)**:
  - Scoring `op_table[i]` as offsets into the node stream:
    - scale=8 (`abs_off = nodes_base + op_table[i]*8`) lands on mostly non-ASCII `kind=0` headers, dominated by `(tag,kind)=(159,0)` and `(157,0)`.
    - scale=12 lands overwhelmingly on ASCII pairs, dominated by `(108,116)` (“lt”) and `(80,73)` (“PI”).
  - This is a strong static witness that the op-table entries are offsets in 8-byte words, and that the current 12-byte framing/graph-walk is mis-scaling those targets, producing “ASCII starts” and truncation artifacts.

Implication:
- The stride=8/offset8 interpretation is now promoted into shared tooling for this world baseline (decoder stride selection + published tag layouts). This resolves the `sys:bsd` “high field2” cluster as a decode artifact of the earlier 12-byte approximation.
- Remaining unknown/high work is now scoped to `sys:airlock`’s out-of-vocab payloads that survive under the promoted framing (currently `165` and `49171` in `field2-filters/out/unknown_nodes.json`).

## Evidence & artifacts

- `out/decode_records.jsonl` – joinable node records for all local probes (tag/fields/field2 hi/lo, role, literal refs).
- `out/field2_summary.json` – per-probe field2 payload histograms.
- `out/stride_offset_scan.json` – brute stride/offset scan results for canonical bsd/airlock blobs.
- `out/airlock_subgraph.json` – reachability slices for canonical airlock under strides {8,10,12}.
- `out/canonical_slots34_hist.json` – per-tag histograms for fields[3]/fields[4] in canonical bsd/airlock under the current 12-byte decode view.
- `sb/` – SBPL probes for `bsd`/`airlock` variants; compiled blobs live in `sb/build/`.
- Upstream references: inventories and reports linked above.

## Blockers / risks

- `sys:airlock` apply/runtime gates limit runtime witnesses; static-only paths must suffice.
- High payloads may be tightly coupled to full platform profiles; simplified SBPL may fail to reproduce them, risking false negatives.

## Next steps

- For `airlock`: analyze the canonical `sys:airlock` unknown/high nodes (`165`, `49171`) and compare them structurally against probe-only sentinels (notably the `0xce00` hi-bit instance) to identify stable node-shape invariants that could support characterization.
- If characterization becomes stable, propose promotion through atlas/guardrails; otherwise record the bounded unknowns and blockers explicitly.
