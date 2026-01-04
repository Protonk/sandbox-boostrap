# Runtime Adversarial Suite – Plan

## Aim
Probe for static↔runtime divergences by running deliberately adversarial SBPL profiles through the plan-based runtime CLI. Phase 1 covers two families: (1) structurally distinct but semantically equivalent profiles, and (2) path/literal edge cases that stress normalization and literal vs subpath handling. Outputs are bundle-scoped expected/runtime matrices and mismatch packets.

## Infrastructure reuse
- Compile/decode via `book.api.profile` and `book.api.profile.decoder`.
- Runtime execution via `python -m book.api.runtime run --plan book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/plan.json --channel launchd_clean`.
- Expectation wiring patterned after `book/evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime`.
- Comparison and summaries live in the committed bundle under `out/<run_id>/` (resolve via `out/LATEST`).
- Plan/registry files are generated from the runtime template:
  `python -m book.api.runtime plan-build --template runtime-adversarial --out book/evidence/experiments/runtime-final-final/suites/runtime-adversarial --overwrite` (plan-build skips expected_matrix.json by default; use `--write-expected-matrix` for a static snapshot).

## Deliverables (Phase 1)
- Bundle artifacts in `out/LATEST/` (`expected_matrix.json`, `runtime_results.json`, `runtime_events.normalized.json`, `mismatch_summary.json`, `mismatch_packets.jsonl`, `artifact_index.json`).
- SBPL + blobs under `sb/` and `sb/build/`.
- Guardrail test ensuring mismatch packets remain coherent.

## Test families (Phase 1)
- Structural variants: `struct_flat` vs `struct_nested` (same file-read semantics, different graph shapes via metafilter nesting vs flat filters).
- Path/literal edge stress: `path_edges` with overlapping `/tmp` vs `/private/tmp`, `..` segments, literal vs subpath mix.

## Field2 canonicalization witness (runtime-adversarial)
Goal: produce a packet-backed witness for the `/tmp` -> `/private/tmp` canonicalization boundary so field2=0 can be closed with decision-stage evidence in the runtime-adversarial packet.

Inputs (read-only, do not advance):
- `status/learnings/merged_vfs_report.md`
- `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md`
- `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json`

Design:
- Add three runtime-adversarial profiles that mirror the vfs-canonicalization trio:
  - alias-only: allow only `/tmp/runtime-adv/canon/*`
  - canonical-only: allow only `/private/tmp/runtime-adv/canon/*`
  - both: allow both spellings (control)
- Keep the operation surface minimal (`file-read*`, `file-write*`) and avoid `/etc`, `/var`, and symlink-component families so traversal gates do not confound the boundary.
- Use the oracle lane (sandbox_check canonical flag) to tag canonicalization-boundary mismatches; do not treat this as a path discovery mechanism.
- Run the suite via `launchd_clean` and emit a promotion packet so the field2 atlas can consume the witness from a single packet boundary.

Outputs (runtime-adversarial):
- `out/LATEST/runtime_results.json` and `out/LATEST/path_witnesses.json` with allow-side witnesses for `/tmp` and `/private/tmp`.
- `out/LATEST/mismatch_packets.jsonl` with `canonicalization_boundary` tags for alias-only denials.

## Comparison signals
- Per expectation_id: expected allow/deny, runtime allow/deny, match flag, mismatch_type (`apply_gate`, `unexpected_allow`, `unexpected_deny`, `canonicalization_boundary`, `op_misroute`, `filter_diff`), notes.
- `mismatch_summary.json` aggregates mismatches + counts by type; `mismatch_packets.jsonl` captures bounded mismatch packets.

## Sequencing
1. Refresh plan/registry via runtime template (see above).
2. Run runtime harness to produce runtime_results; compute mismatch_summary.
3. Add guardrail test and adversarial summary stub under `book/integration/carton/bundle/relationships/mappings/runtime/`.
4. Iterate by adding more families (header/format toggles, field2/tag ambiguity) after Phase 1 lands.

## Constraints / status markers
- Host: `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9` (from `book/world/.../world.json`).
- Platform blobs remain apply-gated; Phase 1 sticks to custom SBPL.
- No new vocab/format assumptions; uses existing decoder and harness only.
