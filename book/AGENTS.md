# Agents in `book/`

## Non-negotiables (read first)

Mission: Build a checkable, regenerable model of Seatbelt for a single host baseline, and prefer the smallest deciding witness or probe over broad refactors.

Baseline: world_id: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` in `book/world/sonoma-14.4.1-23E224-arm64/world.json`. All claims are scoped to this host.

Evidence discipline: If the honest answer is "we do not know yet" or evidence conflicts, say so and point to the bounding artifacts or experiments. Every claim must name its tier (bedrock / mapped / hypothesis) and cite the mapping path (see `book/graph/concepts/BEDROCK_SURFACES.json`); do not upgrade mapped or hypothesis to bedrock.

Vocabulary discipline: use project terms from `book/graph/concepts/concept_map.json` and only ops/filters from `book/graph/mappings/vocab/{ops.json,filters.json}`.

Safety and boundaries: never weaken the baseline (no disabling SIP, TCC, or hardened runtime), do not copy from `dumps/Sandbox-private`, and do not hide harness, decoder, or apply failures.

## Commands

Only supported repo-wide test runner is `make -C book test`.

**Host required (Sonoma 14.4.1 baseline):**
- `python -m book.api.profile compile <profile.sb> --out <path>`
- `python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>`
- `python -m book.api.runtime emit-promotion --bundle <out_dir> --out <out_dir>/promotion_packet.json --require-promotable`
- `python book/graph/mappings/runtime/promote_from_packets.py --packets <packet.json> --out book/graph/mappings/runtime`
- `python book/graph/mappings/vocab/generate_vocab_from_dyld.py`
- `python -m book.graph.concepts.validation --tag vocab`

**Host-neutral (no live sandbox; still host-scoped artifacts):**
- `python -m book.api.profile decode dump <blob.sb.bin> --summary`
- `python -m book.api.profile inspect <blob.sb.bin> --out <path>`
- `python -m book.graph.concepts.validation --tag meta`
- `cd book/graph && swift run`

## Where to look first (task map)

- Operation/filter vocabulary:
  - Inputs `book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib`
  - Outputs `book/graph/mappings/vocab/{ops.json,filters.json,attestations.json}`
  - Source of truth `book/graph/mappings/vocab/{ops.json,filters.json}`
  - Regen `python book/graph/mappings/vocab/generate_vocab_from_dyld.py` then `python book/graph/mappings/vocab/generate_attestations.py`.
- Compile SBPL -> blob:
  - Inputs `*.sb`
  - Outputs `*.sb.bin` under the owning experiment/profile
  - Source of truth compiled blob plus `book/api/profile/compile/`
  - Regen `python -m book.api.profile compile <profile.sb> --out <path>`.
- Decode blob -> graph/tags:
  - Inputs `*.sb.bin`
  - Outputs decode summaries plus `book/graph/mappings/tag_layouts/tag_layouts.json` and `book/graph/mappings/system_profiles/digests.json`
  - Source of truth `book/api/profile/decoder/` plus those mappings
  - Regen `python -m book.api.profile decode dump <blob.sb.bin> --summary`, `python book/graph/mappings/tag_layouts/generate_tag_layouts.py`, `python book/graph/mappings/system_profiles/generate_digests_from_ir.py`.
- Runtime denial vs apply failure:
  - Inputs runtime plan data (for example `book/experiments/runtime-checks/plan.json`)
  - Outputs `runtime_results.json`, `runtime_events.normalized.json`, promotion packets, and `book/graph/mappings/runtime/runtime_signatures.json`
  - Source of truth promotion packets and `book/graph/mappings/runtime/`
  - Regen `python -m book.api.runtime run --plan ... --channel launchd_clean --out ...` then `python -m book.api.runtime emit-promotion ... --require-promotable` and `python book/graph/mappings/runtime/promote_from_packets.py ...`.
- Extensions and layered policy behavior:
  - Inputs lifecycle probes and runtime bundles
  - Outputs `book/graph/mappings/runtime/lifecycle.json` and `book/graph/mappings/runtime/lifecycle_traces/*.jsonl`
  - Source of truth `book/graph/mappings/runtime/` lifecycle artifacts
  - Regen `python book/graph/mappings/runtime/generate_lifecycle.py` after updating lifecycle probe outputs in `book/graph/concepts/validation/out/lifecycle/`.

## Investigation protocol (for sandbox questions)

- Stage taxonomy: always label where it failed (compile, apply, exec/bootstrap, operation check); apply-time failures are not denials.
- Four-axis checklist: Stage (where), Scope (smallest claim), Stack (active profile layers/extensions), Surround (TCC, hardened runtime, SIP, VFS canonicalization).
- Controls: include one passing neighbor, one failing case, and one confounder toggle when possible (for example `/tmp` vs `/private/tmp`).
- Witness snippet format (keep short and reproducible):
```text
witness:
  command: <exact command>
  stage: <compile|apply|exec|operation>
  host: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
  output: <path to log or runtime_results.json excerpt>
```

## Artifact contract

- Generated, do not hand-edit: `book/graph/mappings/**`, `book/graph/concepts/{concepts.json,concept_map.json,concept_text_map.json}`, `book/graph/concepts/validation/{strategies.json,validation_report.json}`, `book/examples/examples.json`, `book/api/carton/CARTON.json` and the files it lists.
- Determinism: vocab tables, system profile digests, tag layouts, and runtime signatures should be stable on the same baseline; run IDs, timestamps, and raw logs may vary.
- Promotion rules: new observations become canonical only through experiments -> validation -> mapping generators; keep status fields (`ok`/`partial`/`brittle`/`blocked`) honest and update guardrail tests in `book/tests/` when mappings change.
- Done criteria for semantic changes: regen affected mappings, run `make -C book test`, and update the relevant `Report.md` or `Notes.md` with the witness.

## Contribution workflow (safe changes)

- Keep paths repo-relative in emitted JSON/IR; use `book.api.path_utils.to_repo_relative` or `relativize_command`. Example:
```json
{"source": "book/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"}
```
- If you touch experiments, update `Report.md`/`Notes.md`, record failures, and keep artifacts under `out/`.
- If you touch mappings, run the matching validation job and regen script rather than editing JSON directly.

## Instruction layering

Treat AGENTS as a high-privilege instruction surface; keep it minimal and task-focused. AGENTS are hierarchical: root -> subdir -> working dir. Read the nearest `AGENTS.md` and README first.
