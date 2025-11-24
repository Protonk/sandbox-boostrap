# concepts/

This directory holds the **concept layer** of the repo: named ideas, cross-cutting abstractions, and shared tooling that sit between the high-level guidance docs and the concrete examples.

Use `guidance/` to understand the model; use `examples/` to see focused demos; use `concepts/` to find and evolve reusable pieces that multiple examples share.

---

## Contents

### `CONCEPT_INVENTORY.md`

A structured index of Seatbelt/XNUSandbox concepts:

- Defines each concept (SBPL Profile, Operation, Filter, PolicyGraph, etc.).
- Records initial status/epistemic tags (e.g. `[S:doc-only→code-partial][E:2011-heavy+14.x-sampled]`).
- Groups concepts along cross-cutting axes (profile ingestion, graph construction, vocabulary mapping, rendering/analysis).

This file is the anchor for concept names and for tracking which ideas have corresponding code in `concepts/cross/`.

---

### `cross/`

Home for **cross-cutting abstraction tooling and lessons**.

This is where we grow shared code and utilities that apply across multiple `examples/` folders. It is expected that early modules may wrap or borrow code from `examples/` until a refactor is complete; reuse across folders is a signal that work here is still in progress, not a bug.

Planned structure (subject to refinement):

- `cross/profile_ingestion/`  
  Core helpers for **Axis 4.1 Profile Ingestion**:
  - Reading compiled profile blobs from disk or memory.
  - Parsing binary headers.
  - Locating section ranges (op-pointer table, node array, regex/literal tables).
  - Normalizing differences between profile format variants.

- `cross/policy_graph/`  
  Core helpers for **Axis 4.2 Graph Construction**:
  - In-memory `PolicyGraph` / node representations.
  - Functions to build per-operation graphs from sections.
  - Hooks for interpreting filters, metafilters, decisions, and action modifiers at the node level.

- `cross/vocab/`  
  Core helpers for **Axis 4.3 Vocabulary Mapping**:
  - `OperationVocabulary` and `FilterVocabulary` mappings.
  - Version-aware naming and categorization of operations and filters.
  - Facilities for tracking known/legacy/unknown IDs and their provenance.

- `cross/render/`  
  Core helpers for **Axis 4.4 Rendering & Analysis**:
  - SBPL-ish pretty-printers over `PolicyGraph`.
  - DOT/Graphviz emitters for operations or subgraphs.
  - Tabular summaries of operations, filters, and decisions.

Each subdirectory should contain:

- A small `README.md` stating:
  - Which concepts from `CONCEPT_INVENTORY.md` it implements.
  - Which cross-cutting axis it belongs to.
  - Which `examples/` currently use it (as they are migrated).
- Minimal, focused code with clear, concept-aligned naming.
- No example-specific CLI or UX; those remain in `examples/`.

---

## Conventions

- If a concept in `CONCEPT_INVENTORY.md` has status `[S:doc-only→code-partial]` or `[S:code-partial→core]`, the corresponding shared code should live under `concepts/cross/`.
- When refactoring an example to use a `concepts/cross/` module:
  - Keep behavior the same where possible.
  - Update the example’s `lessons.md` or summary to reference the shared abstraction.
  - Consider updating the relevant concept’s status tags in `CONCEPT_INVENTORY.md`.

Over time, `concepts/` should make it clear which parts of the Seatbelt model are backed by reusable code and which remain purely documented or example-specific.