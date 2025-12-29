>This document is a compressed context bundle, not a router or API manual. It exists to keep you inside the repo's world model, evidence tiers, and toolchain without over-claiming.

SANDBOX_LORE is a host-bound, local-only universe for the macOS Seatbelt sandbox. The repo now holds multiple world baselines under `book/world/`, but the published mappings and CARTON are pinned to the Sonoma 14.4.1 baseline with `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (`book/world/sonoma-14.4.1-23E224-arm64/world.json`). The substrate under `book/substrate/` defines the allowed vocabulary; validation IR, mappings, and CARTON record host-specific evidence with explicit evidence tiering (`bedrock|mapped|hypothesis`) and optional per-artifact `status` signals.

# Invariants (non-negotiable)

- **World scoping**: every emitted artifact (validation IR, mappings, CARTON) is keyed to exactly one `world_id`. A mismatch means you are mixing worlds or pointing at the wrong baseline; stop and fix world selection. Only mint a new `world_id` by following the rebaseline process in `book/world/README.md`.
- **Vocabulary**: operation and filter names come only from `book/graph/mappings/vocab/ops.json` and `book/graph/mappings/vocab/filters.json`. Unknowns stay unknown; do not name ops/filters by guesswork.
- **Evidence tiering**: every claim names a tier: `bedrock`, `mapped`, or `hypothesis`. Bedrock surfaces are declared in `book/graph/concepts/BEDROCK_SURFACES.json`; do not upgrade mapped/hypothesis to bedrock. Many artifacts also carry a `status` field (`ok|partial|brittle|blocked`) as an operational health/detail signal; it is not a substitute for tier.
- **Apply-stage gating**: apply-stage `EPERM` is **hypothesis** evidence, not policy semantics. Preflight before runtime probes that could hit known gates (see `book/tools/preflight/README.md`).
- **Runtime labeling**: runtime statements must include both a `stage` (`compile|apply|bootstrap|operation`) and a `lane` (`scenario|baseline|oracle`). If you can’t name them, you don’t have a stable claim yet.
- **Committed runtime evidence only**: treat runtime results as evidence only when sourced from a committed runtime bundle (`artifact_index.json`) or a `promotion_packet.json`. Anything else is debug/unverified and stays `hypothesis`.
- **Repo-relative evidence paths**: checked-in JSON/IR must not embed absolute paths; emit repo-relative paths using `book.api.path_utils` helpers.
- **Regenerate shared IR**: do not hand-edit generated/shared artifacts (mappings, generated concept JSON, CARTON-listed files). Update sources and rerun the appropriate generator (`swift run` for concepts; `book/graph/mappings/run_promotion.py` for mappings/CARTON).
- **Surrounding constraints are confounders**: treat TCC, hardened runtime, SIP/platform gates, and VFS canonicalization as surrounding constraints that can dominate outcomes. For behavioral claims, prefer at least one passing neighbor and one confounder toggle.
- **CARTON integrity**: files listed in `book/api/carton/CARTON.json` are manifest-verified; do not hand-edit them. Use validation -> mappings -> manifest refresh instead.

# Claim + witness template (use this shape)

Evidence tiers (canonical):
- `bedrock`: declared in `book/graph/concepts/BEDROCK_SURFACES.json`; safe to treat as a fixed input for this host world.
- `mapped`: host-bound, evidence-backed, but scoped; do not generalize beyond the bounded artifacts/scenarios.
- `hypothesis`: plausible/partial/confounded; use it to bound unknowns, not to assert semantics.

`status` is optional and informal: `ok|partial|brittle|blocked` can add operational context regardless of tier, but it does not change the tier.

Minimal witness record (keep short and checkable):
```text
claim:
  world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
  tier: bedrock|mapped|hypothesis
  status: ok|partial|brittle|blocked (optional)
  stage: static|compile|apply|bootstrap|operation
  subject: <op/filter/profile/concept in repo vocabulary>
  evidence:
    - <repo-relative path to mapping / bundle / promotion packet>
  limits: <one line about what this does NOT prove>
```

# Operating contract

- Stay within the Sonoma baseline unless explicitly rebaselining; other world directories exist, but mappings/CARTON are keyed to the active baseline.
- Use substrate vocabulary (`book/substrate/Concepts.md` and friends) and treat pretraining as subordinate to repo artifacts.
- Use repo-relative paths in outputs; resolve with `book.api.path_utils`.
- When evidence conflicts or is missing, say "we don't know yet" and point to the bounding artifacts.
- When in doubt, stop and read the nearest `AGENTS.md` and README in the subtree you touch.

# World model and world_id selection

- World baselines live in `book/world/*`; `world_id` is derived from the dyld manifest hash (see `book/world/README.md`) and stored in each baseline file.
- The active baseline is `book/world/sonoma-14.4.1-23E224-arm64/world.json`; generators and tools resolve it via `book/world/registry.json` or `book.api.world` unless explicitly overridden.
- Baseline overrides (when a tool supports them) are explicit CLI flags; otherwise baseline selection is not automatic.

# Evidence layers and pipeline

- **Substrate + concepts**: `book/substrate/` defines the vocabulary; the concept inventory is in `book/graph/concepts/CONCEPT_INVENTORY.md` and generated JSON in `book/graph/concepts/` comes from `swift run` in `book/graph`.
- **Experiments -> validation IR**: experiments write to `book/experiments/*/out`; the validation driver (`python -m book.graph.concepts.validation`) normalizes into `book/graph/concepts/validation/out/` and records status.
- **Validation IR -> mappings**: generators under `book/graph/mappings/*/generate_*.py` read validation outputs and emit host mappings; the supported entrypoint is `book/graph/mappings/run_promotion.py`.
- **Mappings -> CARTON**: CARTON overlays live in `book/graph/mappings/carton/`; refresh the manifest with `book/api/carton/create_manifest.py`. Query via `book.api.carton.carton_query`.

# Evidence sources

Do not copy evidence details from memory. Use these sources as the current cut:

- Bedrock surfaces and their mapping paths: `book/graph/concepts/BEDROCK_SURFACES.json`.
- Validation summary and job status: `book/graph/concepts/validation/out/README.md`, `book/graph/concepts/validation/out/validation_status.json`, `book/graph/concepts/validation/out/index.json`.
- Runtime coverage and signatures: `book/graph/mappings/runtime/runtime_coverage.json`, `book/graph/mappings/vocab/ops_coverage.json`, `book/graph/mappings/runtime/runtime_signatures.json`, `book/graph/mappings/runtime/README.md`.
- Lifecycle probes: `book/graph/mappings/runtime/lifecycle.json`.
- Anchors/field2 status: `book/graph/mappings/anchors/anchor_field2_map.json`.
- Apply-gate and preflight: `book/tools/preflight/README.md`.

# Runtime interpretation primer (avoid the common confusions)

Runtime evidence in this repo is always host-scoped and must be stage-labeled.

Stages (what kind of “failure” you are looking at):
- `compile`: SBPL → compiled blob (structural; not semantics).
- `apply`: policy attachment (`sandbox_init`/`sandbox_apply`) failed; no PolicyGraph decision happened (**hypothesis**).
- `bootstrap`: apply succeeded, but the probe did not start cleanly; keep distinct from “sandbox denied my operation.”
- `operation`: the probe ran and attempted its action; deny/allow at this stage is the only place runtime semantics can live (**mapped**, scenario-scoped).

Lanes (why the same probe can have multiple records):
- `scenario`: decision-stage run under an applied profile.
- `baseline`: run without applying a profile (ambient constraints / attribution).
- `oracle`: explicitly weaker side-channel lane; never implies syscall observation.

Promotion packets are the contract boundary for runtime evidence: `python -m book.api.runtime emit-promotion --bundle ...` emits `promotion_packet.json`, which records a promotability decision (for example, “clean-channel decision-stage evidence” vs “not promotable; reasons listed”). Reference: `book/api/runtime/SPEC.md`.

# High-leverage capabilities

- **Profile structure**: `book.api.profile` (CLI: `python -m book.api.profile`) for SBPL compile/ingest/decode/inspect/op-table/digests/oracles.
- **Runtime probes**: `book.api.runtime` (CLI: `python -m book.api.runtime`) for plan-based runs, bundle validation, and promotion packets.
- **Apply-gate guardrails**: `book/tools/preflight/preflight.py` for scan + minimize-gate.
- **Apply/probe pair**: `book/tools/sbpl/wrapper/` (wrapper binary) + `book/api/runtime/native/file_probe/file_probe.c` (probe target).
- **Lifecycle probes**: `book.api.lifecycle_probes` (CLI: `python -m book.api.lifecycle_probes`).
- **Entitlements witness**: `book.api.entitlementjail` driving `book/tools/entitlement/EntitlementJail.app` (see `book/tools/entitlement/EntitlementJail.md`).
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
