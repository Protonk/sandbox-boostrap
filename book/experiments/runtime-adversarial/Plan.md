# Runtime Adversarial Suite – Plan

## Aim
Probe for static↔runtime divergences by running deliberately adversarial SBPL profiles through the existing golden_runner/runtime harness. Phase 1 covers two families: (1) structurally distinct but semantically equivalent profiles, and (2) path/literal edge cases that stress normalization and literal vs subpath handling. Outputs include expected/runtime matrices, mismatch summaries, and an impact map hook.

## Infrastructure reuse
- Compile/decode via `book.api.profile` and `book.api.profile.decoder`.
- Runtime harness via `book.api.runtime.execution.harness.runner.run_matrix` (reusing `runtime-checks` shims).
- Expectation wiring patterned after `book/experiments/sbpl-graph-runtime`.
- Comparison and summaries live in this experiment’s `out/`.
- Plan/registry files are generated from the runtime template:
  `python -m book.api.runtime plan-build --template runtime-adversarial --out book/experiments/runtime-adversarial --overwrite`.

## Deliverables (Phase 1)
- `out/expected_matrix.json`, `out/runtime_results.json`, `out/mismatch_summary.json`, `out/impact_map.json` (world_id-stamped).
- SBPL + blobs under `sb/` and `sb/build/`.
- Guardrail test ensuring mismatches are either absent or annotated.

## Test families (Phase 1)
- Structural variants: `struct_flat` vs `struct_nested` (same file-read semantics, different graph shapes via metafilter nesting vs flat filters).
- Path/literal edge stress: `path_edges` with overlapping `/tmp` vs `/private/tmp`, `..` segments, literal vs subpath mix.

## Comparison signals
- Per expectation_id: expected allow/deny, runtime allow/deny, match flag, mismatch_type (`apply_gate`, `unexpected_allow`, `unexpected_deny`, `path_normalization`, `op_misroute`, `filter_diff`), notes.
- `mismatch_summary.json` aggregates mismatches + counts by type; `impact_map.json` hooks expectation_ids to bedrock claims/status suggestions.

## Sequencing
1. Refresh plan/registry via runtime template (see above).
2. Run runtime harness to produce runtime_results; compute mismatch_summary.
3. Add guardrail test and adversarial summary stub under `book/graph/mappings/runtime/`.
4. Iterate by adding more families (header/format toggles, field2/tag ambiguity) after Phase 1 lands.

## Constraints / status markers
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (from `book/world/.../world.json`).
- Platform blobs remain apply-gated; Phase 1 sticks to custom SBPL.
- No new vocab/format assumptions; uses existing decoder and harness only.
