# Runtime Adversarial Suite – Plan

## Aim
Probe for static↔runtime divergences by running deliberately adversarial SBPL profiles through the plan-based runtime CLI. Phase 1 covers two families: (1) structurally distinct but semantically equivalent profiles, and (2) path/literal edge cases that stress normalization and literal vs subpath handling. Outputs are bundle-scoped expected/runtime matrices and mismatch packets.

## Infrastructure reuse
- Compile/decode via `book.api.profile` and `book.api.profile.decoder`.
- Runtime execution via `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean`.
- Expectation wiring patterned after `book/experiments/sbpl-graph-runtime`.
- Comparison and summaries live in the committed bundle under `out/<run_id>/` (resolve via `out/LATEST`).
- Plan/registry files are generated from the runtime template:
  `python -m book.api.runtime plan-build --template runtime-adversarial --out book/experiments/runtime-adversarial --overwrite` (plan-build skips expected_matrix.json by default; use `--write-expected-matrix` for a static snapshot).

## Deliverables (Phase 1)
- Bundle artifacts in `out/LATEST/` (`expected_matrix.json`, `runtime_results.json`, `runtime_events.normalized.json`, `mismatch_summary.json`, `mismatch_packets.jsonl`, `artifact_index.json`).
- SBPL + blobs under `sb/` and `sb/build/`.
- Guardrail test ensuring mismatch packets remain coherent.

## Test families (Phase 1)
- Structural variants: `struct_flat` vs `struct_nested` (same file-read semantics, different graph shapes via metafilter nesting vs flat filters).
- Path/literal edge stress: `path_edges` with overlapping `/tmp` vs `/private/tmp`, `..` segments, literal vs subpath mix.

## Comparison signals
- Per expectation_id: expected allow/deny, runtime allow/deny, match flag, mismatch_type (`apply_gate`, `unexpected_allow`, `unexpected_deny`, `canonicalization_boundary`, `op_misroute`, `filter_diff`), notes.
- `mismatch_summary.json` aggregates mismatches + counts by type; `mismatch_packets.jsonl` captures bounded mismatch packets.

## Sequencing
1. Refresh plan/registry via runtime template (see above).
2. Run runtime harness to produce runtime_results; compute mismatch_summary.
3. Add guardrail test and adversarial summary stub under `book/graph/mappings/runtime/`.
4. Iterate by adding more families (header/format toggles, field2/tag ambiguity) after Phase 1 lands.

## Constraints / status markers
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (from `book/world/.../world.json`).
- Platform blobs remain apply-gated; Phase 1 sticks to custom SBPL.
- No new vocab/format assumptions; uses existing decoder and harness only.
