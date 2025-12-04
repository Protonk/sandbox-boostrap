# Agents in `book/graph/`

These instructions apply to the entire `book/graph/` tree. Treat this directory as the shared “graph IR + concept inventory” layer that sits between experiments and the textbook: it defines concepts, ingests compiled profiles, and publishes stable mappings for this Sonoma host.

## Scope and router

High-level layout:

- `Package.swift`, `Sources/`
  - Swift entrypoint(s) for graph-related tooling. Keep these thin wrappers over the Python/JSON IR: they should orchestrate, not re-implement, ingestion or mapping logic.

- `concepts/`
  - `CONCEPT_INVENTORY.md`, `concepts.json`, `concept_map.json`, `concept_text_map.json`:
    - Single source of truth for the Seatbelt concept set, their relationships, and how they map to text.
  - `EXAMPLES.md`:
    - Human-facing examples that witness concepts via specific artifacts.
  - `validation/`:
    - Python tooling and fixtures that ingest/parse compiled profiles, decode PolicyGraphs, and emit validation outputs under `validation/out/` (profile ingestion, decoder, vocab extraction, static/mapping metadata).
    - This is the only place new ingestion/decoder logic should live.

- `mappings/`
  - Stable host-specific mapping artifacts used across the repo (see `book/graph/mappings/README.md`):
    - `vocab/` – Operation/Filter Vocabulary Maps.
    - `op_table/` – op-table buckets, signatures, and vocab alignment.
    - `anchors/` – anchor ↔ filter/field2 mappings.
    - `tag_layouts/` – per-tag node layouts.
    - `system_profiles/` – system profile digests.
    - `runtime/` – runtime expectations/traces that are “golden” enough to depend on.
    - `dyld-libs/` – trimmed dyld slices used to derive vocab.

When in doubt:
- New *code* that ingests or validates compiled profiles → `concepts/validation/`.
- New *stable mappings* or “IR” that other code depends on → `mappings/` (with metadata and schema).
- Experiment-specific scratch outputs stay under `book/experiments/*/out`, not here.

## Swift generator loop (for agents)

Use this pattern to extend the Swift generator/validator:
- Pick one schema slice to cover (e.g., runtime expectations, vocab attestations, concept→text bindings).
- Add Swift types that mirror the JSON shape and small validators (status enums, required IDs).
- Parse inputs, reuse generated `concepts.json` for ID checks, and emit a report under `book/graph/validation/` instead of failing silently.
- Document the new coverage in `book/graph/README.md` (inputs/outputs, how to run).
- Run `swift run` to regenerate outputs and the validation report; review before committing.

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
