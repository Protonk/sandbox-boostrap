# Agents in `book/` (operational root)

## Non-negotiables (read first)

Mission: Build a checkable, regenerable model of Seatbelt for a single host baseline, and prefer the smallest deciding witness or probe over broad refactors.

Baseline (single source of truth): `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (see `book/world/sonoma-14.4.1-23E224-arm64/world.json`, resolved via `book/world/registry.json` and `book.api.world`). All claims are scoped to this host.

Evidence discipline:
- If the honest answer is “we don’t know yet” or evidence conflicts, say so and point to the bounding artifacts/experiments.

Vocabulary discipline:
- Use project terms from `book/evidence/graph/concepts/concept_map.json` and the substrate (do not invent new jargon).
- Use only ops/filters from `book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json}`.

Runtime discipline:
- Runtime statements must include both a `stage` (`compile|apply|bootstrap|operation`) and a `lane` (`scenario|baseline|oracle`).
- Apply-stage `EPERM` is almost always evidence of a staging problem, not a policy denial. Run `book/tools/preflight`.
- Treat runtime results as evidence only when sourced from a committed runtime bundle (`artifact_index.json`) or a `promotion_packet.json`.

Safety and boundaries:
- Never weaken the baseline (no disabling SIP, TCC, or hardened runtime).
- Do not copy from `book/dumps/ghidra/private/aapl-restricted`.
- Do not hide harness/decoder/apply failures; treat them as first-class evidence.

Paths and generated artifacts:
- Checked-in JSON/IR must not embed absolute paths; emit repo-relative paths using `book.api.path_utils` (`to_repo_relative`, `relativize_command`).
- Do not hand-edit shared/generated artifacts. Regenerate via the appropriate generator:
  - Concepts JSON: `cd book/graph && swift run`
  - Mappings promotion: `python -m book.integration.carton promote`
  - CARTON fixers + manifest: `python -m book.integration.carton build`
- CARTON refresh: `python -m book.integration.carton build` or `make -C book carton-refresh`

## Commands (supported entrypoints)

Only supported repo-wide test runner: `make -C book test`.

Common host-bound commands (Sonoma 14.4.1 baseline):
- Compile SBPL → blob: `python -m book.api.profile compile <profile.sb> --out <path>`
- Decode/inspect blob: `python -m book.api.profile decode dump <blob.sb.bin> --summary`
- Plan-based runtime run: `python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>`
- Emit promotion packet: `python -m book.api.runtime emit-promotion --bundle <out_dir> --out <out_dir>/promotion_packet.json --require-promotable`
- Promote runtime packets into mappings: `python book/integration/carton/mappings/runtime/promote_from_packets.py --packets <packet.json>` (writes under `book/integration/carton/bundle/relationships/mappings/`)

Host-neutral (still host-scoped artifacts; no live sandbox):
- Validate concepts/IR: `python -m book.graph.concepts.validation --tag meta`
- Build graph generator outputs: `cd book/graph && swift run`

## Cold-start routing (where to look)

Pick the smallest surface that answers your question:
- “What operations/filters exist on this host?” → `book/integration/carton/bundle/relationships/mappings/vocab/` and the CARTON bundle at `book/integration/carton/bundle/` (relationships/views/contracts + manifest).
- “What bytes did this SBPL compile into?” → `book/api/profile/` (structural tooling).
- “Why did a runtime probe fail/deny?” → `book/api/runtime/` bundles and promotion packets (stage + lane + promotability).
- “Am I about to hit apply-gating?” → `book/tools/preflight/` (scan + minimize-gate) and `book/tools/sbpl/wrapper/`.
- “Is my baseline/world consistent?” → `book/tools/doctor/`.

Then read the nearest `AGENTS.md` in the subtree you touch:
- API/tooling: `book/api/AGENTS.md`; CARTON fixer bundle: `book/integration/carton/README.md`.
- Graph/concepts: `book/graph/AGENTS.md`; deeper routing in `book/graph/concepts/AGENTS.md`, `book/graph/swift/AGENTS.md`. Mapping generators: `book/integration/carton/mappings/AGENTS.md`.
- Experiments: `book/evidence/experiments/AGENTS.md`; archived work in `book/evidence/experiments/archive/AGENTS.md`.
- Dumps/artifacts: `book/dumps/AGENTS.md`.
- Profiles: `book/profiles/AGENTS.md`.
- Substrate/textbook base: `book/substrate/AGENTS.md`.
- Tests: `book/integration/AGENTS.md`.

## Investigation protocol (for sandbox questions)

- Stage taxonomy: always label where it failed (`compile`, `apply`, `bootstrap`, `operation`). Apply-stage failures are not denials.
- Confounders: treat TCC, hardened runtime, SIP/platform gates, and VFS canonicalization as surrounding constraints that can dominate outcomes.
- Controls: include one passing neighbor and one confounder toggle when possible (for example `/tmp` vs `/private/tmp`).

Minimal witness record (keep short and checkable):
```text
claim:
  world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
  status: ok|partial|brittle|blocked (optional)
  stage: compile|apply|bootstrap|operation
  lane: scenario|baseline|oracle (runtime only)
  command: <exact command or plan/scenario id>
  evidence:
    - <repo-relative path to mapping / committed bundle / promotion_packet.json>
  limits: <one line about what this does NOT prove>
```

## Instruction layering

Treat AGENTS as a high-privilege instruction surface; keep it minimal and task-focused. AGENTS are hierarchical: root → subdir → working dir. Read the nearest `AGENTS.md` and README first.
