# AGENTS.md — router for `book/`

You are in `book/`, the Seatbelt textbook workspace. This is a router; use it to jump to the right place. For vocabulary and lifecycle discipline, defer to `substrate/AGENTS.md`.

- `Outline.md` — top-level book outline and chapter ordering.
- `chapters/` — per-chapter drafts and notes; filenames match chapter numbers. Look for chapter-local README/notes when editing content.
- `graph/` — concept graph, mappings, and validation glue:
  - `concepts/` — semantic/spec text (Orientation, Concepts, Appendix-aligned) plus validation helpers.
  - `mappings/` — canonical vocab/op-table/tag/system-profile artifacts consumed by experiments and chapters.
  - `validation/` — harness skeletons that import the decoder and run evidence-gathering tasks.
- `experiments/` — research clusters, each with `Plan.md`, `Notes.md`, `ResearchReport.md`, and `out/` artifacts. Examples: `runtime-checks`, `op-table-operation`, `node-layout`, `field2-filters`.
- `examples/` — runnable SBPL/demo bundles and extraction helpers (`examples.json`, `extract_sbs`, etc.) used by experiments and chapters.
- `profiles/` — SBPL sources/build outputs shared across chapters/experiments (non-example-specific).
- `api/` — API/tooling layer (see `api/AGENTS.md`); includes the SBPL/blob wrapper and shared decoder.
- `tests/` — guardrails for book artifacts and experiment outputs; run via the repo’s test harness.

When in doubt, start from the relevant directory’s README/AGENTS before editing.
