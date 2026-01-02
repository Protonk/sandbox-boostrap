# looking-glass — MANIFEST (compressed router + evidence intake)

This file is the “context pack front page” for the `looking-glass` web co-designer: what to include, how to route questions to bundles, and what minimal artifacts decide claims.

Baseline anchor: Sonoma 14.4.1 (23E224) Apple Silicon, SIP enabled; `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Default context pack (compressed)

Goal: keep the default pack small enough that the agent spends tokens on *your artifacts*, not on its own background.

Recommended set (SYSTEM + 4):
- `SYSTEM.md` — role + membrane + response shape.
- `MANIFEST.md` (this file) — router + intake template + stable entrypoints.
- `SANDBOX.md` — host-grounded truths + confounders.
- `STRUGGLES.md` — the Stage/Scope/Stack/Surround axes + “what to ask for”.
- `WITNESSES.md` — boundary objects (what can actually decide questions right now).

Optional expansions (only when the question demands it):
- `WORLD_AND_EVIDENCE.md` — detailed world scoping + evidence tiers + stage/lane rules.
- `PROJECT.md` — honest progress + frontier.
- `PROFILE_TOOLCHAIN.md` — SBPL ↔ compiled blob workflows (structural).
- `RUNTIME_AND_WITNESS_TOOLCHAIN.md` — runtime harness + PolicyWitness harness + contract artifacts.
- `GRAPH_AND_MAPPINGS.md` — concepts + mapping outputs vs generators.
- `CARTON_AND_GUARDRAILS.md` — CARTON + drift detection.

Token discipline:
- Prefer 1–2 short excerpts from `artifact_index.json` / `promotion_packet.json` over adding another whole bundle.

## Router (question → read → ask for)

- **“Is this a sandbox denial or an earlier-stage failure?”**
  - Read: `STRUGGLES.md`, `SANDBOX.md` (and `WORLD_AND_EVIDENCE.md` if needed).
  - Ask for: stage (`compile|apply|bootstrap|operation`) + lane + one committed bundle/promotion packet excerpt.
- **“What witness would decide this claim?”**
  - Read: `WITNESSES.md`.
  - Ask for: the witness’ suggested excerpt/control (don’t accept narrative).
- **“Where does this fact live / what file should I look at?”**
  - Read: `MANIFEST.md` (repo atlas + stable entrypoints) then the relevant domain bundle.
  - Ask for: the smallest source-of-truth artifact path (mapping JSON, committed bundle, or packet) + excerpt.
- **“How do I compile/decode a profile blob?”**
  - Read: `PROFILE_TOOLCHAIN.md`.
  - Ask for: the exact command + `--summary` decode excerpt + `metadata.world_id`.
- **“How do I turn runtime runs into durable mappings?”**
  - Read: `RUNTIME_AND_WITNESS_TOOLCHAIN.md`.
  - Ask for: `promotion_packet.json` `promotability` excerpt + `artifact_index.json` path.
- **“How do mappings get regenerated / what’s pinned vs generated?”**
  - Read: `GRAPH_AND_MAPPINGS.md`, `CARTON_AND_GUARDRAILS.md`.
  - Ask for: the pinned mapping path under `book/evidence/graph/mappings/**` and whether CARTON was refreshed.

## Evidence intake (paste this)

```text
world_id: <...>
question: <one sentence>
stage: compile|apply|bootstrap|operation (treat apply-adjacent "preflight" as apply)
lane: scenario|baseline|oracle (runtime only)
artifacts:
  - <repo-relative path to artifact_index.json OR promotion_packet.json> (+ small excerpt)
controls: <one passing neighbor> + <one confounder toggle>
```

## Declared bedrock surfaces (this host)

From `book/evidence/graph/concepts/BEDROCK_SURFACES.json`:
- Operation + Filter vocabularies:
  - `book/evidence/graph/mappings/vocab/ops.json`
  - `book/evidence/graph/mappings/vocab/filters.json`
  - `book/evidence/graph/mappings/vocab/ops_coverage.json`
- Modern format/tag-layout subset:
  - `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`
- Canonical system profiles:
  - `book/evidence/graph/mappings/system_profiles/digests.json`
  - `book/evidence/graph/mappings/system_profiles/static_checks.json`
  - `book/evidence/graph/mappings/system_profiles/attestations.json`

## Repo atlas (minimal)

Operational root: `book/`.

Top-level:
- `book/` — host-bound “textbook + workbench” (world, mappings, tools, tests, evidence).
- `guidance/` — agent context bundles (editing/review convenience; not evidence).
- `troubles/` — troubleshooting/process notes.
- `status/` — human-facing project status.

Within `book/` (most-cited surfaces):
- `book/world/` — baseline world record + registry.
- `book/evidence/graph/mappings/` — pinned, world-stamped mapping outputs (“facts”).
- `book/graph/mappings/` — mapping generators/promotion code (writes the pinned outputs).
- `book/api/` — supported CLIs (`book.api.profile`, `book.api.runtime`, `book.api.witness`).
- `book/integration/carton/` — CARTON frozen query bundle + update/check/diff tools.
- `book/evidence/experiments/` — witness generators (not contract-shaped by default).
- `book/dumps/` — host-bound dumps (stricter local rules in its own AGENTS).

## Stable entrypoints (supported)

- Tests / drift detector: `make -C book test`
- Promote/refresh mappings: `python -m book.graph.mappings.run_promotion`
- Refresh CARTON: `python -m book.integration.carton.tools.update` (or `make -C book carton-refresh`)
- Profile tooling: `python -m book.api.profile ...`
- Runtime harness: `python -m book.api.runtime ...`
- PolicyWitness harness: `python -m book.api.witness ...`
