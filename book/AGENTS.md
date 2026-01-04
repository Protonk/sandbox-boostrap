# Agents in `book/` (operational root)

Our mission is to generate a textbook on the macOS sandbox/Seatbelt from the host, by cementing code and data into testable configurations. What you see is a work in progress, aimed at the future. To make that future better, read on.

## Non-negotiable

Baseline: All claims are scoped to a host via a `world_id`, currently `sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`.

Discipline: If the honest answer is “we don’t know yet” or evidence conflicts, say so. 

Posture: Backwards compatibility is an anti-pattern. Cut shims away and fix only what complains by test. 

Environment: The working tree is intentionally dirty. Never chase working-tree diffs. Only report unexpected changes if they impact tests you depend on.

Documentation: Standalone `.md` files, line-level code comments, CLI help text, and test messages are **all** first class documentation objects. They should be useful, informative, and most importantly, present. 

## Tooling

> Work in a loop: build → decode → probe → persist → test → build. 

Compose and expand what exists: compile/decode SBPL, probe with tiny experiments, persist relationships with CARTON, then run `make -C book test`. Prefer canonical entrypoints over ad-hoc scripts.

- Baseline integrity: run [doctor](book/tools/doctor) early; treat mismatches as stop signs.
- Harness confinement: before any policy-facing runtime work, run [inside](book/tools/inside); if it reports `constrained`, do not narrate denials as sandbox semantics.
- Apply-gate avoidance: stage SBPL apply attempts with [preflight](book/tools/preflight) (`scan` first, `minimize-gate` only when you need a shrinkable boundary object).
- SBPL structure: use [profile](book/api/profile) (`python -m book.api.profile ...`) for compile/decode/inspect/op-table; reserve [sbpl tools](book/tools/sbpl) for corpus, wrapper runs, and oracle runners.
- Runtime harness: use [runtime](book/api/runtime) (`python -m book.api.runtime ...`) to run plan-based probes and emit canonical bundles; never invent output shapes by hand.
- `sandbox_check` pairing: use [validator](book/tools/validator) when you need an operation/filter check on a live pid; keep “permission-shaped failure” separate from “deny evidence”.
- App Sandbox + entitlements: use [witness](book/tools/witness) (PolicyWitness) for XPC probes and unified-log corroboration; treat it as a witness of execution, not an oracle of intent.
- PolicyGraph enumeration: use [policy tools](book/tools/policy) to enumerate node fields and manage promotion packets; don’t hand-edit promoted inventories.
- Path hygiene: resolve and serialize paths with [path_utils](book/api/path_utils.py); keep emitted artifacts repo-relative.

## Router

The below is a router of more important places.
- `book/world/` — world baselines + registry at `book/world/registry.json`.
- `book/evidence/` - Persisted results to rely on.
  - `book/evidence/syncretic/` - Artifacts reverse engineered from a variety of sources
  - `book/evidence/profiles/` - System and constructed profiles
- `book/tools/` — host-bound CLIs.
- `book/api/` — shared Python surfaces consumed by tools and tests.
- `book/integration/` — Putting everything together:
  - `book/integration/carton/` - Semantic intermediate representation for content.
  - `book/integration/tests/` - integration, smoke, and sanity tests, organized by suite.

- `book/dumps/` — private workspaces and oversized artifacts (not a place for new code/docs; never copy from `book/dumps/ghidra/private/aapl-restricted/`).
Nearest `AGENTS.md` wins; read it before editing.

## Outro

Find your world_id by calling the [doctor](book/tools/doctor) before proceeding. 
