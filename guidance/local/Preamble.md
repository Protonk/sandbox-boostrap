>This document is a compressed context bundle, not a router or API manual. It exists to keep you inside the repo's world model, evidence tiers, and toolchain without over-claiming.

SANDBOX_LORE is a host-bound, local-only universe for the macOS Seatbelt sandbox. The repo now holds multiple world baselines under `book/world/`, but the published mappings and CARTON are pinned to the Sonoma 14.4.1 baseline with `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (`book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`). The substrate under `book/substrate/` defines the allowed vocabulary; validation IR, mappings, and CARTON record host-specific evidence with explicit status.

# Invariants (non-negotiable)

- **World scoping**: every emitted artifact (validation IR, mappings, CARTON) is keyed to exactly one `world_id`. A mismatch means you are mixing worlds or pointing at the wrong baseline; stop and fix world selection. Only mint a new `world_id` by following the rebaseline process in `book/world/README.md`.
- **Vocabulary**: operation and filter names come only from `book/graph/mappings/vocab/ops.json` and `book/graph/mappings/vocab/filters.json`. Unknowns stay unknown; do not name ops/filters by guesswork.
- **Status monotonicity**: statuses only upgrade via new host evidence plus the corresponding validation/mapping update. When claiming `ok`, `partial`, `brittle`, or `blocked`, cite the mapping file; when citing validation job results, cite `book/graph/concepts/validation/out/validation_status.json` or `book/graph/concepts/validation/out/index.json`.
- **Apply-stage gating**: apply-stage `EPERM` is blocked evidence, not policy semantics. Preflight before runtime probes that could hit known gates (see `book/tools/preflight/README.md`).
- **CARTON integrity**: files listed in `book/api/carton/CARTON.json` are manifest-verified; do not hand-edit them. Use validation -> mappings -> manifest refresh instead.

# Operating contract

- Stay within the Sonoma baseline unless explicitly rebaselining; other world directories exist, but mappings/CARTON are keyed to the active baseline.
- Use substrate vocabulary (`book/substrate/Concepts.md` and friends) and treat pretraining as subordinate to repo artifacts.
- Use repo-relative paths in outputs; resolve with `book.api.path_utils`.
- When evidence conflicts or is missing, say "we don't know yet" and point to the bounding artifacts.
- When in doubt, stop and read the nearest `AGENTS.md` and README in the subtree you touch.

# World model and world_id selection

- World baselines live in `book/world/*`; `world_id` is derived from the dyld manifest hash (see `book/world/README.md`) and stored in each baseline file.
- The active baseline is `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; most generators and tools hardcode this baseline ref.
- The runtime harness accepts an explicit baseline override (`--baseline`) for debug VM work in `book/api/runtime_harness/cli.py`; otherwise baseline selection is not automatic.

# Evidence layers and pipeline

- **Substrate + concepts**: `book/substrate/` defines the vocabulary; the concept inventory is in `book/graph/concepts/CONCEPT_INVENTORY.md` and generated JSON in `book/graph/concepts/` comes from `swift run` in `book/graph`.
- **Experiments -> validation IR**: experiments write to `book/experiments/*/out`; the validation driver (`python -m book.graph.concepts.validation`) normalizes into `book/graph/concepts/validation/out/` and records status.
- **Validation IR -> mappings**: generators under `book/graph/mappings/*/generate_*.py` read validation outputs and emit host mappings; the supported entrypoint is `book/graph/mappings/run_promotion.py`.
- **Mappings -> CARTON**: CARTON overlays live in `book/graph/mappings/carton/`; refresh the manifest with `book/api/carton/create_manifest.py`. Query via `book.api.carton.carton_query`.

# Status sources

Do not copy status details from memory. Use these sources as the current cut:

- Bedrock surfaces and their mapping paths: `book/graph/concepts/BEDROCK_SURFACES.json`.
- Validation summary and job status: `book/graph/concepts/validation/out/README.md`, `book/graph/concepts/validation/out/validation_status.json`, `book/graph/concepts/validation/out/index.json`.
- Runtime coverage and signatures: `book/graph/mappings/runtime/runtime_coverage.json`, `book/graph/mappings/vocab/ops_coverage.json`, `book/graph/mappings/runtime/runtime_signatures.json`, `book/graph/mappings/runtime/README.md`.
- Lifecycle probes: `book/graph/mappings/runtime/lifecycle.json`.
- Anchors/field2 status: `book/graph/mappings/anchors/anchor_field2_map.json`.
- Apply-gate witness and preflight corpora: `book/tools/preflight/README.md`, `book/experiments/gate-witnesses/Report.md`, `book/experiments/preflight-blob-digests/Report.md`, `book/experiments/preflight-index/Report.md`.

# High-leverage capabilities

- **Profile structure**: `book.api.profile_tools` (CLI: `python -m book.api.profile_tools`) for SBPL compile/ingest/decode/inspect/op-table/digests/oracles.
- **Runtime probes**: `book.api.runtime_harness` (CLI: `python -m book.api.runtime_harness.cli`) plus `book.api.runtime` for normalization and runtime cuts.
- **Apply-gate guardrails**: `book/tools/preflight/preflight.py` for scan + minimize-gate.
- **Apply/probe pair**: `book/tools/sbpl/wrapper/` (wrapper binary) + `book/api/file_probe/file_probe.c` (probe target).
- **Lifecycle probes**: `book.api.lifecycle_probes` (CLI: `python -m book.api.lifecycle_probes`).
- **Entitlements witness**: `book/tools/entitlement/EntitlementJail.app` (see `book/tools/entitlement/EntitlementJail.md`).
- **Kernel/symbol work**: `book.api.ghidra` (CLI: `python -m book.api.ghidra.cli`).

# Minimal routing

- Start with `README.md` and `AGENTS.md`, then the nearest `AGENTS.md` in the subtree you touch.
- For graph IR/mappings: `book/graph/AGENTS.md`, `book/graph/mappings/README.md`, `book/graph/mappings/AGENTS.md`.
- For experiments: `book/experiments/AGENTS.md` and `book/experiments/Experiments.md`.
- For API/CARTON: `book/api/AGENTS.md`, `book/api/README.md`, `book/api/carton/README.md`, `book/api/carton/API.md`.
- Single entrance test runner: `make -C book test`.

# Welcome aboard

You are not being asked to “explain macOS security in the abstract.” You are participating in a proposal-and-verification loop that is meant to turn local, host-bound observations into fixed understandings: concepts that actually line up with binaries and decoded tables, mappings that can be regenerated, and examples that a reader can rerun and inspect. Treat every step as work on the wiring diagram between theory and evidence: when you clarify something, the goal is to make it harder for the repo to drift back into self-consistent but ungrounded stories.

As you work, actively look for the promotion path from what you learned into durable repo structure: an experiment that produces a stable witness; validation IR that makes the observation queryable and statused; a mapping generator or mapping file that encodes the relationship; a CARTON refresh that makes it consumable; and an API surface that lets other agents retrieve it without re-deriving it. Prefer changes that reduce future discretion (compile-time relationships, schema-enforced records, guardrail tests, preflight checks) over changes that merely add prose. If something is blocked or inconsistent, that is still a useful result: record the boundary precisely (world_id, harness identity, minimal failing shape, where the evidence lives) so the ignorance is bounded and portable rather than implicit.