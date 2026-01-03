# Profile Pipeline - Report

## Purpose
Consolidate the userland SBPL pipeline for this host baseline: compile-time encoder traces, PolicyGraph layout decoding, op-table bucket structure, vocabulary alignment, and `sandbox_init*` apply-stage handle packing.

## Baseline & scope
- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Scope: userland compile/apply only. No kernel dispatcher semantics; runtime results are scenario-lane apply-stage witnesses unless explicitly promoted.
- Dependencies (shared mappings):
  - Operation/Filter vocabularies: `book/integration/carton/bundle/relationships/mappings/vocab/ops.json`, `book/integration/carton/bundle/relationships/mappings/vocab/filters.json`, `book/integration/carton/bundle/relationships/mappings/vocab/ops_coverage.json`.
  - Modern tag layouts: `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`.

## Tracks (consolidated)
- `encoder-write-trace/` - compiler write tracing that joins libsandbox writes to compiled blob bytes.
- `node-layout/` - PolicyGraph structural layout: node region, literals/regex pool, stride/tag behavior.
- `op-table-operation/` - Operation Pointer Table bucket patterns under Operation/Filter changes.
- `op-table-vocab-alignment/` - SBPL Operation/Filter symbols aligned to vocab IDs (no slot semantics claims).
- `sandbox-init-params/` - `sandbox_init*` -> `_sandbox_apply` -> `__sandbox_ms` handle/arg packing.

## Deliverables / expected outcomes
- A single experiment root with stable subtracks and shared baseline metadata.
- Trace/layout/op-table/alignment/apply artifacts preserved with repo-relative paths.
- Clear separation of observed facts vs open questions across the pipeline.

## Evidence & artifacts
- Encoder trace: `book/evidence/experiments/profile-pipeline/encoder-write-trace/Report.md` and `book/evidence/experiments/profile-pipeline/encoder-write-trace/out/`.
- Layout summary: `book/evidence/experiments/profile-pipeline/node-layout/out/summary.json`.
- Op-table buckets: `book/evidence/experiments/profile-pipeline/op-table-operation/out/summary.json` and `book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_signatures.json`.
- Vocab alignment: `book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json`.
- Apply packing: `book/evidence/experiments/profile-pipeline/sandbox-init-params/out/layout_snapshot.json` and `book/evidence/experiments/profile-pipeline/sandbox-init-params/out/handoff_snapshot.json`.

## Status
- Status: **partial** (each track has outputs; slot/offset semantics remain open).

## Blockers / risks
- Encoder tracing remains limited by unexported callsites and immutable text pages; hardware-breakpoint coverage may be incomplete.
- Op-table bucket patterns are stable for synthetic probes but slot semantics are still unresolved.
- Apply-stage handle layout is observed for the current path; the natural non-zero handle branch is still missing a witness.

## Next steps
- Tighten per-track open questions with minimal probes (single-change SBPL variants; additional trace inputs; new `sandbox_init*` named profiles).
- Maintain guardrails by refreshing track outputs only through their local run scripts; do not hand-edit generated artifacts.
- When an open question is resolved by new witnesses, reflect it in the relevant track report and cross-link here.
