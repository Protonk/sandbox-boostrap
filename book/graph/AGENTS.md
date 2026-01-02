# Agents in `book/graph/`

These instructions apply to the entire `book/graph/` tree. Treat this directory as the shared “graph IR + concept inventory” layer that sits between experiments and the textbook: it defines concepts, ingests compiled profiles, and publishes stable mappings for this Sonoma host. Those mappings are then fed into CARTON fixers, which produce the frozen CARTON bundle (relationships/views/contracts + manifest) under `book/integration/carton/bundle/` for the textbook and tooling to read.

## Scope and router

High-level layout:

- `Package.swift`, `swift/`
  - Swift entrypoint(s) for graph-related tooling. Keep these thin wrappers over the Python/JSON IR: they should orchestrate, not re-implement, ingestion or mapping logic. Encode “always enforced” mapping invariants as Swift data structures here so drift is caught by the Swift build.

- `concepts/`
  - `CONCEPT_INVENTORY.md`, `concepts.json`, `concept_map.json`, `concept_text_map.json`:
    - Single source of truth for the Seatbelt concept set, their relationships, and how they map to text.
  - `EXAMPLES.md`:
    - Human-facing examples that witness concepts via specific artifacts.
  - `validation/`:
    - Python tooling and fixtures that ingest/parse compiled profiles, decode PolicyGraphs, and emit validation outputs under `validation/out/` (profile ingestion, decoder, vocab extraction, static/mapping metadata).
    - This is the only place new ingestion/decoder logic should live.

- `mappings/`
  - Stable host-specific mapping artifacts used across the repo (see `book/graph/mappings/README.md`); mapping generators read validation IR and write these before CARTON fixers normalize them into the CARTON bundle (relationships/views/contracts + manifest):
    - `vocab/` – Operation/Filter Vocabulary Maps.
    - `op_table/` – op-table buckets, signatures, and vocab alignment.
    - `anchors/` – anchor ↔ filter/field2 mappings.
    - `tag_layouts/` – per-tag node layouts.
    - `system_profiles/` – system profile digests.
    - `runtime/` – runtime expectations/traces that are “golden” enough to depend on.
    - `dyld-libs/` – trimmed dyld slices used to derive vocab.

## Bedrock navigation

The current bedrock surfaces for this world are recorded in `book/graph/concepts/BEDROCK_SURFACES.json`; use that as the registry and cite mapping paths when you rely on them. The promotion narrative in `status/first-promotion/post-remediation.md` explains the initial justification.

When in doubt:
- New *code* that ingests or validates compiled profiles → `concepts/validation/`.
- New *stable mappings* or “IR” that other code depends on → `mappings/` (with metadata and schema).
- Experiment-specific scratch outputs stay under `book/experiments/*/out`, not here.
- CARTON is the frozen, host-specific bundle (relationships/views/contracts + manifest); see `book/integration/carton/README.md` and use `python -m book.integration.carton.tools.check` / `python -m book.integration.carton.tools.diff` rather than ad-hoc JSON spelunking.

For **anchor/field2 structure** on this Sonoma world, use this stack as your entrypoint:
- Structural source (anchors + tags + `field2` per profile): `book/experiments/field2-final-final/probe-op-structure/Report.md` (tier: mapped, structural only).
- `field2` inventory and unknowns: `book/experiments/field2-final-final/field2-filters/Report.md` (bounded high/unknown IDs, experiment closed).
- Curated anchors and their Filter mappings:
  - Canonical (context-indexed): `book/graph/mappings/anchors/anchor_ctx_filter_map.json`
  - Compatibility view (literal-keyed, conservative): `book/graph/mappings/anchors/anchor_filter_map.json` (guarded by `book/integration/tests/graph/test_anchor_filter_alignment.py`).

## Swift generator loop (for agents)

Use this pattern to extend the Swift generator/validator:
- Pick one schema slice to cover (e.g., runtime expectations, vocab attestations, concept→text bindings).
- Add Swift types that mirror the JSON shape and small validators (status enums, required IDs).
- Parse inputs, reuse generated `concepts.json` for ID checks, and emit a report under `book/graph/concepts/validation/` instead of failing silently.
- Document the new coverage in `book/graph/README.md` and `book/graph/swift/README.md` (inputs/outputs, how to run).
- Run `swift run` (or `make -C book test`, which calls the Swift build; `make -C book build` does the same with a pinned module cache). `make -C book clean` wipes SwiftPM/.build/module caches if you need a fresh start.

---

## Concept and validation code

Within `concepts/` and `concepts/validation/`:

- **Concept inventory discipline**
  - Do not invent new concept names casually; align with `CONCEPT_INVENTORY.md` and `concepts.json`.
  - If you genuinely need a new concept, add it to the inventory with:
    - A short definition in substrate vocabulary.
    - Expected evidence types (static-format, semantic, vocab/mapping, lifecycle).
    - Pointers to witnesses or a clear placeholder stating that witnesses are still missing.

- **Validation tooling expectations**
  - New ingestion/decoder logic should:
    - Take raw artifacts (compiled profiles, SBPL, mappings) as input.
    - Emit small, well-typed JSON outputs under `concepts/validation/out/`.
    - Record host, OS/build, and format-variant metadata in outputs.
  - Prefer small, composable scripts (e.g., `profile_ingestion.py`, `node_decoder.py`, `vocab_extraction.py`) over monolithic tools.
  - If you change decoding or ingestion semantics, also:
    - Update `validation/README.md` or nearby docs.
    - Consider whether existing `mappings/` artifacts need to be regenerated and reversioned.

- **Fixtures and tests**
  - Keep fixtures under `concepts/validation/fixtures/` small and explicit (short blobs, curated examples, minimal SBPL).
  - Any new fixture or strategy should be referenced from `strategies.json` or equivalent routing, not hidden in ad-hoc scripts.

---

## Mapping artifacts

Within `mappings/`, treat files as shared IR:

- **General expectations**
  - Every mapping JSON (vocab, op_table, anchors, tag_layouts, system_profiles, runtime) should:
    - Carry host/OS/build metadata.
    - Include a `status` or similar field where appropriate (`ok`, `partial`, `brittle`, `blocked`).
    - Record provenance: which experiments, scripts, or source blobs produced it.
  - Keep schemas stable; if you must change a schema, adjust consumers and document the change in `mappings/README.md` or a nearby note.

- **Division of labor**
  - `mappings/` should contain only artifacts that are:
    - Host-specific.
    - Stable enough to be reused by multiple experiments and chapters.
    - Regenerable from the repo plus the fixed host baseline.
  - Do not put experiment-local scratch data here; that lives under `book/experiments/*/out`.

- **Alignment with experiments**
  - When an experiment “graduates” a mapping into `mappings/`:
    - Make sure the experiment’s `Report.md` points to the new file and describes its schema and status.
    - Prefer naming and shapes that match the concept inventory (e.g., Operation Vocabulary Map, Filter Vocabulary Map, PolicyGraph, tag layouts).

---

## Things to avoid

When working in `book/graph/`, agents should avoid:

- **Diverging from the concept inventory**
  - Do not introduce new concepts, fields, or vocab names that contradict `CONCEPT_INVENTORY.md` or existing vocab/mapping files without updating those sources.
  - Do not redefine core terms (Operation, Filter, PolicyGraph, Profile Layer, etc.) in local docs or code.

- **Unversioned or opaque changes**
  - Do not silently change the semantics or schema of mapping JSONs under `mappings/` without:
    - Updating metadata and documentation.
    - Checking (and, if needed, updating) consumers in `concepts/validation/`, `book/experiments/`, and `book/chapters/`.

- **Embedding experiments in `graph/`**
  - Do not put experiment scaffolds (`Plan`, `Notes`, large `out/` trees) under `book/graph/`; keep those under `book/experiments/` and publish only the stable outputs here.

- **Silent decoding failures**
  - Do not ignore decoder/ingestion failures or treat partial decodes as fully valid mappings.
  - If a mapping is based on brittle or partial decoding, mark it clearly (`status: partial`/`brittle`) and document the limitations in both the mapping file and any relevant conceptual documentation.

This directory is where the project’s “graph view of Seatbelt” becomes a shared, versioned IR. Keep it small, traceable, and tightly aligned with the concept inventory and the Sonoma host baseline.
