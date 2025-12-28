# Runtime Integration Plan

World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. Goal: treat `runtime-checks`, `runtime-adversarial`, and `op-coverage-and-runtime-signatures` as a single runtime evidence web with shared tooling, schemas, guardrails, and promoted artifacts.

## Executive Summary

This document proposes a single, host-bound runtime evidence pipeline that connects `runtime-checks`, `runtime-adversarial`, and `op-coverage-and-runtime-signatures` into one coherent system. The pipeline standardizes how runtime probes are captured, validated, compared against expectations, and aggregated into per-operation summaries for this world.

- Unify capture, log schema, and loaders into a shared runtime module under `book/api/`, and treat the three experiments as callers of that module rather than independent implementations.
- Promote normalized runtime artifacts into `book/graph/mappings/runtime/` at event, scenario, operation, and global-summary levels, all keyed by `world_id` and stable scenario identifiers.
- Carry forward existing guardrails (shape checks, network-outbound constraints, coverage thresholds) so they protect the shared runtime module and mappings instead of remaining experiment-local.
- Make cross-artifact navigation a first-class feature: from operations to scenarios to raw events and back, preserving divergences as explicit annotations rather than losing them in aggregation.

## Introduction

Runtime work in this project is intentionally narrow and host-specific: it is about how Seatbelt behaves on `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`, and nothing else. The current runtime evidence is spread across three experiments—`runtime-checks`, `runtime-adversarial`, and `op-coverage-and-runtime-signatures`—that were built incrementally and share code and assumptions without a single home.

This plan treats those experiments as phases of one runtime evidence pipeline. `runtime-checks` provides raw, schema-validated logs tied to expectations; `runtime-adversarial` adds curated probe families and mismatch/impact views; `op-coverage-and-runtime-signatures` aggregates those results into per-operation scorecards and signatures. The goal is to lift shared tooling and stabilized artifacts out of the experiments into `book/api` and `book/graph/mappings`, then refit the experiments to validate and extend that shared layer.

Throughout, runtime evidence is treated as mapped: useful and grounded on this host, but not silently upgraded to bedrock. Schemas, world identifiers, and traceability back to raw events are used to keep the runtime story reproducible and checkable over time.

## Pipeline Stages (raw → adversarial → op scorecards)
- **Raw capture (runtime-checks)**: sandbox_runner/reader/writer shims + runtime_harness produce per-probe logs (`runtime_results.json`) against an `expected_matrix.json`, using `runtime_log_schema.v0.1.json`.
- **Adversarial orchestration (runtime-adversarial)**: runs curated probe families, reuses the harness to emit `runtime_results.json` + `expected_matrix.json`, then derives `mismatch_summary.json` and `impact_map.json` (semantic classification of divergences).
- **Op-level aggregation (op-coverage-and-runtime-signatures)**: copies adversarial outputs, aggregates per operation into `op_runtime_summary.json` (counts, examples, mismatch details).

## Tooling Inventory (shared pool)
- **Runners (capture/schema/loaders)**: `runtime_log_schema.v0.1.json`; sandbox_runner/reader/writer; mach_probe; runtime_harness runner; log readers in run_probes.py/run_adversarial.py; path_utils helpers.
- **Drivers (families/orchestration)**: runtime-checks `run_probes.py`; runtime-adversarial `run_adversarial.py` (expected matrix generation, probe families, mismatch/impact computation); harvest_runtime_artifacts.py (copy stage).
- **Aggregators (summaries)**: runtime-adversarial mismatch/impact builders; op-coverage summarize_from_adversarial.py (per-op scorecards); coverage/signature generation feeding `book/graph/mappings/runtime/runtime_signatures.json` and `ops_coverage.json`.
- **Plan**: lift runners+drivers+aggregators together into `book/api/runtime` (module exposing capture, run, mismatch, coverage transforms).

## Artifact Families (grouped by level)
- **Event-level**: per-probe runtime log entries (`runtime_results.json`, schema-backed).
- **Scenario-level**: expectations (`expected_matrix.json`), mismatch views (`mismatch_summary.json`), impact classifications (`impact_map.json`), adversarial runtime_signatures entries.
- **Op-level**: `op_runtime_summary.json`, `runtime_signatures.json` (operation ↔ scenario results), `ops_coverage.json` runtime_evidence flags.
- **Global summary**: coverage indices (CARTON operation/profile indexes), any cross-op mismatch index.
- Treat each family as a candidate mapping set under `book/graph/mappings/runtime/` with aligned schemas.

## Canonical Runtime Schema (align to runtime_log_schema)
- **Observation**: `{world_id, profile_id, scenario_id, expectation_id, operation, target, probe_name, expected, actual, match, errno, errno_name, stdout/stderr snippets, command, harness, timestamp?, notes}`.
- **Scenario identity**: tuple of `{profile_id, probe_name | expectation_id}` plus world_id; optionally include `runtime_signature_id`.
- **Op keying**: operation name from vocab; include op_id when vocab is available.
- **World**: required metadata on every record and manifest (world_id, host build, harness version, source commit).

## Home for Artifacts vs Operations
- **Data**: promote canonical logs/matrices/mismatch/coverage into `book/graph/mappings/runtime/` (event/scenario/op/global layers).
- **Operations**: promote generators/consumers into `book/api/runtime`:
  - capture/run (harness entrypoint),
  - normalize logs (schema validation),
  - build expected matrices,
  - derive mismatches/impact,
  - compute per-op summaries/coverage,
  - serve navigation/index views.
- Always pair mapping promotion with the operation that regenerates it.

## API Surface Extensions (book/api/runtime)
- Endpoints to:
  - run probes (existing runtime_harness),
  - load raw logs (event-level),
  - fetch mismatch/impact views (scenario-level),
  - fetch per-op coverage/summary (op-level),
  - list runtime signatures and coverage by op/profile/world.
- Single interface over the promoted artifacts; consistent keys (world_id, scenario_id, op).

## Link to Existing Mappings
- Join per-op runtime data with static descriptors: op-table (buckets/signatures), vocab IDs, system profiles, anchors, tag layouts.
- Emit a joined mapping (e.g., `runtime_operation_story`) under `book/graph/mappings/runtime/` that carries `{op_id/name, runtime_signatures, coverage, mismatches, static_refs}`.

## Metadata Keys
- Make `world_id` and `scenario_id` first-class in every artifact and index.
- Scenario_id pattern: `<profile_id>::<probe_name>` or explicit expectation_id; include profile layer info when available.

## Guardrails Promotion
- Re-home `test_runtime_matrix_shape.py`, `test_network_outbound_guardrail.py`, and similar checks to guard the shared runtime module and promoted mappings. New tests should validate schema conformance, world_id presence, coverage counts, and key scenarios (e.g., network-outbound allow/deny split).

## Transform Paths to Promote
- Raw logs → validated events (schema).
- Validated events + expectations → mismatch_summary + impact_map.
- Mismatch/impact + events → op_runtime_summary (counts/examples).
- Expose each transform in `book/api/runtime` so future worlds regenerate without touching experiments.

## Cross-Artifact Navigation
- Build indexes:
  - op → scenarios → event refs,
  - scenario → mismatches/impact entries → raw events,
  - runtime_signature_id → events/expectations/coverage rows.
- Keep indexes as first-class mappings for traceability.

## Consolidation of Coverage/Signatures
- Canonicalize coverage/signature representations under `book/graph/mappings/runtime/` (e.g., runtime_signatures.json + ops_coverage.json). Have runtime-adversarial and op-coverage pipeline target this single format.

## Centralize Shared Runtime Helpers
- Move shared assumptions (log schema, op IDs, scenario naming, world metadata) into `book/api/runtime` utilities; have `run_adversarial.py`, `run_probes.py`, `summarize_from_adversarial.py`, and harvest scripts import these instead of re-encoding formats.

## Refitting Experiments
- Convert the three experiments to consume the promoted runtime module and mappings:
  - import shared harness/transforms,
  - write/read promoted artifacts,
  - use experiments as validation/extenders, not as owners of core code.

## Naming/Directory Pattern
- Under `book/graph/mappings/runtime/`: `{events.jsonl, expected_matrix.json, runtime_results.json, mismatch_summary.json, impact_map.json, runtime_signatures.json, op_runtime_summary.json, coverage_index.json}` with `world_id` in metadata blocks and filenames if multiple worlds arise.
- Scenario IDs and op IDs/names stable across layers.

## Two-Direction Links & Divergences
- API should allow annotating mappings with new evidence (e.g., add a runtime trace, flag a mismatch). Keep divergence flags from `impact_map`/mismatch summaries attached to ops/scenarios for query (“where reality diverged from expectation for op X?”). Canonicalize VFS canonicalization and similar falsifications as explicit annotations.

## Conclusion

The runtime pipeline for this world now has a clear target shape: a shared runtime module in `book/api` that owns capture, schema, and transforms, plus a family of runtime mappings in `book/graph/mappings/runtime/` that hold normalized, world-tagged evidence. The three existing experiments become structured callers and validators of that layer instead of the primary home for runtime logic.

If implemented as outlined here, the result should be a runtime evidence web where every per-op summary, coverage flag, and runtime signature can be traced back to concrete, schema-checked events and expectations. Guardrails and tests move with the code, keeping the mappings consistent over time, and new runtime work can plug into the same patterns without ad hoc wiring. This gives the project a stable, inspectable runtime story that fits alongside the existing static-format and vocab mappings for this host.
