>This document is a compressed context bundle, not a router or API manual. It exists to keep you inside the repo's world model, evidence tiers, and toolchain without over-claiming.

SANDBOX_LORE is a host-bound, local-only universe for the macOS Seatbelt sandbox. The repo holds multiple worlds under `book/world/`, but the published mappings and CARTON are pinned to the Sonoma 14.4.1 baseline with `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (`book/world/sonoma-14.4.1-23E224-arm64/world.json`). The substrate under `book/substrate/` defines the allowed vocabulary; validation IR, mappings, and CARTON record host-specific evidence with explicit evidence tiering (`bedrock|mapped|hypothesis`) and optional per-artifact `status` signals.

# Invariants (non-negotiable)

- **World scoping**: every emitted artifact (validation IR, mappings, CARTON) is keyed to exactly one `world_id`. A mismatch means you are mixing worlds or pointing at the wrong baseline; stop and fix world selection. Only mint a new `world_id` by following the rebaseline process in `book/world/README.md`.
- **Apply-stage gating**: apply-stage `EPERM` is evidence of a process error, not policy semantics. Preflight before runtime probes that could hit known gates (see `book/tools/preflight/README.md`).
- **Failure honesty**: do not hide harness/decoder/apply failures; treat them as first-class evidence.
- **Runtime labeling**: runtime statements must include both a `stage` (`compile|apply|bootstrap|operation`) and a `lane` (`scenario|baseline|oracle`). If you can’t name them, you don’t have a stable claim yet.
- **Repo-relative evidence paths**: checked-in JSON/IR must not embed absolute paths; emit repo-relative paths using `book.api.path_utils` helpers.
- **Regenerate shared IR**: do not hand-edit generated/shared artifacts (mappings, generated concept JSON, CARTON-listed files). Update sources and rerun the appropriate generator (`swift run` for concepts; `book/graph/mappings/run_promotion.py` for mappings; `python -m book.integration.carton.tools.update` for CARTON).
- **Surrounding constraints are confounders**: treat TCC, hardened runtime, SIP/platform gates, and VFS canonicalization as surrounding constraints that can dominate outcomes. For behavioral claims, prefer at least one passing neighbor and one confounder toggle.

# Operating contract

- Use repo-relative paths in outputs; resolve with `book.api.path_utils`.
- When evidence conflicts or is missing, say "we don't know yet" and point to the bounding artifacts.
- When in doubt, stop and read the nearest `AGENTS.md` and README in the subtree you touch.

# World model and world_id selection

- World baselines live in `book/world/*`; `world_id` is derived from the dyld manifest hash (see `book/world/README.md`) and stored in each baseline file.
- The active baseline is `book/world/sonoma-14.4.1-23E224-arm64/world.json`; generators and tools resolve it via `book/world/registry.json` or `book.api.world` unless explicitly overridden.
- Baseline overrides (when a tool supports them) are explicit CLI flags (for example `--world-id`); otherwise tools default to the baseline world from `book/world/registry.json`.

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
- **Lifecycle probes**: `book.api.lifecycle` (CLI: `python -m book.api.lifecycle`).
- **App Sandbox + entitlements witness**: `book.api.witness` wrapping `book/tools/witness/PolicyWitness.app` (guide: `book/tools/witness/PolicyWitness.md`).
- **Kernel/symbol work**: `book.api.ghidra` (CLI: `python -m book.api.ghidra`).

# Minimal routing

- Start with `README.md` and `AGENTS.md`, then the nearest `AGENTS.md` in the subtree you touch.
- For graph IR/mappings: `book/graph/AGENTS.md`, `book/graph/mappings/README.md`, `book/graph/mappings/AGENTS.md`.
- For experiments: `book/evidence/experiments/AGENTS.md` and `book/evidence/experiments/Experiments.md`.
- For API/CARTON: `book/api/AGENTS.md`, `book/api/README.md`, `book/integration/carton/README.md`.
- Single entrance test runner: `make -C book test`.

# Welcome aboard

You are not being asked to “explain macOS security in the abstract.” You are participating in a proposal-and-verification loop that is meant to turn local, host-bound observations into fixed understandings: concepts that actually line up with binaries and decoded tables, mappings that can be regenerated, and examples that a reader can rerun and inspect. Treat every step as work on the wiring diagram between theory and evidence: when you clarify something, the goal is to make it harder for the repo to drift back into self-consistent but ungrounded stories.

As you work, actively look for the promotion path from what you learned into durable repo structure: an experiment that produces a stable witness; validation IR that makes the observation queryable and statused; a mapping generator or mapping file that encodes the relationship; a CARTON refresh that makes it consumable; and an API surface that lets other agents retrieve it without re-deriving it. Prefer changes that reduce future discretion (compile-time relationships, schema-enforced records, guardrail tests, preflight checks) over changes that merely add prose. If something is blocked or inconsistent, that is still a useful result: record the boundary precisely (world_id, harness identity, minimal failing shape, where the evidence lives) so the ignorance is bounded and portable rather than implicit.
