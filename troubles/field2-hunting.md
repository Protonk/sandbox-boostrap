# Field2 hunting (reopened)

Unknown `filter_arg_raw` values are structurally bounded (tags/ops/fan-in/out) and the kernel treats this slot as a raw u16; earlier work treated this as closed. This note is reopened to track dependencies and coordination points for any further field2 work.

This note captures the hunt for the third 16‑bit payload slot in compiled PolicyGraph nodes on this Sonoma host. Early drafts called it `field2`; the decoder now exposes it as `filter_arg_raw` (with `field2_hi = raw & 0xc000`, `field2_lo = raw & 0x3fff`). The search is **closed**: low values line up with the public filter vocabulary, every remaining unknown is bounded by tag/op context, and the kernel reads this slot as a raw u16 with no hi/lo split or obvious node struct.

Key artifacts (all under `book/evidence/experiments/field2-final-final/field2-filters/`):
- Inventories: `out/field2_inventory.json`, `out/unknown_nodes.json`.
- System + probe SBPL: `sb/` and `sb/build/*.sb.bin` (including `bsd_ops_default_file`, `airlock_system_fcntl`, flow-divert variants).
- Ghidra evaluator/helper dumps: `book/evidence/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/` (`field2_evaluator.json`, `helper.txt`, `eval.txt`, `candidates.json`).
- Ghidra struct hunt (negative): `book/evidence/dumps/ghidra/out/14.4.1-23E224/find-field2-evaluator/node_struct_scan.txt` and `.json` (0 real candidates reachable from `_eval`).
- Scripts: `harvest_field2.py`, `unknown_focus.py`, `book/api/ghidra/scripts/find_field2_evaluator.py`, `kernel_node_struct_scan.py`.

## What is known

### Profile-side facts (decoded graphs)
- `bsd`: highs {16660 on tag 0, ops 0–27, hi=0x4000; 170/174/115/109 on tag 26, op-empty}. Lows match vocab (path/socket/iokit/right-name/preference-domain/mac-policy-name).
- `airlock`: highs {165, 166, 10752} on tags 166/1/0 tied to op 162 (`system-fcntl`); synthetic `airlock_system_fcntl` adds sentinel 0xffff (hi=0xc000) on tag 1. Lows otherwise path/socket.
- `sample`: single sentinel 3584 (hi=0, lo=0xe00) on tag 0; rest low IDs (path/local/remote).
- Flow-divert mixed probes (`v4_network_socket_require_all`, `v7_file_network_combo`, `net_require_all_domain_type_proto`): include a node with `filter_arg_raw = 2560` (hi=0, lo=0x0a00) tied to literal `com.apple.flow-divert`, fan_in=0, fan_out=2→0, op-empty; only appears when domain+type+protocol are all required. Simplified network-only variants collapse to low IDs.
- Other synthetic probes (dtracehelper/posix_spawn, bsd_tail_context, flow_divert_variant, flow_divert_mixed) collapse to low IDs; no reproduction of bsd highs outside the canonical `bsd` blob.

### Kernel-side facts (arm64e sandbox kext)
- `_eval @ fffffe000b40d698` is a bytecode VM over the profile blob; masks 0x7f/0xffffff/0x7fffff for other operands but **no** 0x3fff/0x4000 masks on the u16 payload.
- `__read16 @ fffffe000b40fa1c` is the u16 reader: bounds-check + `ldrh`, no masking or bit tests. Payload is forwarded raw.
- No immediates or masks for the unknown constants (16660/2560/10752/0xffff/3584) appear in evaluator/helper dumps.
- Struct hunt: `kernel_node_struct_scan.py scan ...` over all functions reachable from `_eval` finds **no** fixed-stride `[byte + ≥2×u16]` node layout; only two noisy non-sandbox hits. This effectively rules out a Blazakis-style in-kernel node array on 14.4.1.

**Bottom line:** `filter_arg_raw` is consumed as a plain u16; hi/lo splitting is an analytic convenience only. The unmapped values remain: 16660, 2560, 10752, 165, 166, 170, 174, 115, 109, 3584, 0xffff.

## Current experiments that touch field2

- `book/evidence/experiments/field2-final-final/field2-filters` — status: complete (negative). Primary inventories (`out/field2_inventory.json`, `out/unknown_nodes.json`); SBPL probes + Ghidra VM/struct hunts; no hi/lo split.
- `book/evidence/experiments/field2-final-final/probe-op-structure` — status: partial. Anchor-aware/tag-aware field2 structuring (`out/anchor_hits.json`, `out/analysis.json`, tag layout assumptions); binds anchors → node indices → field2 values.
- `book/evidence/experiments/field2-final-final/anchor-filter-map` — status: partial. Consumes field2 inventories + anchor hits to publish curated anchor → Filter IDs (`book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json`, candidates in `out/anchor_filter_candidates.json`); guardrailed by `tests/test_mappings_guardrail.py`.
- `book/evidence/experiments/tag-layout-decode` — status: ok (structural). Publishes literal-bearing tag layouts at `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`, used by decoder and field2 consumers.
- `book/evidence/experiments/field2-final-final/libsandbox-encoder` — status: partial. Field2 encoder matrix (`out/field2_encoder_matrix.json`) from SBPL→blob probes; explores compiler emission of field2/payloads for selected tags.
- `book/evidence/experiments/node-layout` — status: ok (structural). Node stride/layout census informing where field2/payloads live.
- `book/evidence/experiments/runtime-final-final/suites/metadata-runner` — status: partial. Structural checks include anchor/field2 consistency (`out/anchor_structural_check.json`).
- `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization` — status: partial. Decodes temp profiles; notes field2 payload placement in `out/decode_tmp_profiles.json`.
- `book/evidence/experiments/op-table-operation`, `runtime-adversarial`, `entitlement-diff` — indirect. Use shared decoder/tag layouts (and thus field2 positioning) but do not advance field2 semantics.

## How we got here (paths and outcomes)

1) **Census and tagging:** `harvest_field2.py` + `unknown_focus.py` over system profiles and probes to locate all unknowns with tag/op/fan-in/fan-out context (`out/field2_inventory.json`, `out/unknown_nodes.json`).
2) **SBPL probes:** single-filter and mixed profiles to peel highs into simpler graphs. Result: either collapse to low IDs or one new sentinel (0xffff) without mapping the original highs.
3) **Kernel helper/evaluator:** carved `com.apple.security.sandbox`, located `_eval` and `__read16`, confirmed raw-u16 handling, ran mask/imm searches for 0x3fff/0x4000/0xc000 and the unknown constants with negative results.
4) **Struct search:** `kernel_node_struct_scan.py` over `_eval`’s callees and callgraph reach produced 0 viable `[byte + 2×u16]` structs. Treat this as definitive: the evaluator is VM-style, not a fixed node array.

## Status and closure

Closed. Unknowns are bounded by structure (tags, ops, fan-in/out) but unmapped. No kernel-side hi/lo split or recoverable node struct was found. Further progress would require new work (e.g., helper-level compare/index analysis or userland `libsandbox` compiler study) and should be tracked as a new trouble or experiment, referencing these artifacts for context.
