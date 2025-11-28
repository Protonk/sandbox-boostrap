# Op-table ↔ Operation Vocabulary Alignment Experiment (Sonoma host)

Goal: align the op-table “buckets” observed in synthetic profiles with a proper Operation Vocabulary Map on this host, using canonical vocab artifacts rather than guessing from bucket indices alone.

This experiment is a bridge between the existing `node-layout` and `op-table-operation` experiments and the vocabulary-mapping validation cluster under `book/graph/concepts/validation/`.

---

## 1. Setup and scope

- [x] Confirm host / OS baseline and record it in `ResearchReport.md`.
- [x] Inventory existing artifacts:
  - [x] `book/experiments/node-layout/out/summary.json`
  - [x] `book/experiments/op-table-operation/out/summary.json`
  - [x] `book/experiments/op-table-operation/out/op_table_map.json`
- [x] Locate vocabulary-mapping tasks and outputs:
  - [x] `book/graph/concepts/validation/tasks.py` (vocabulary cluster).
  - [x] Any existing `out/vocab/ops.json` / `filters.json` for this host (if present) — none found initially; placeholder “unavailable” artifacts created in `validation/out/vocab/` pending real extraction.

Deliverables for this phase:
- Clear note in `ResearchReport.md` describing the host baseline and which vocab artifacts (if any) are already available.

---

## 2. Vocabulary extraction hookup

- [x] If `out/vocab/ops.json` does not exist, describe (but do not yet implement here) the expected pipeline to generate it from canonical blobs (e.g., system profiles produced by existing extraction tools).
- [x] Define the contract this experiment will rely on:
  - [x] Expected JSON shape for `ops.json` (name ↔ id ↔ notes).
  - [x] How to associate a compiled profile blob with a specific vocabulary version (OS / build).
- [x] Record these expectations in `ResearchReport.md` as assumptions and requirements for future agents.
  - Status: real vocab extraction still missing; placeholder artifacts exist under `validation/out/vocab/`.
  - Once a decoder exists, vocabulary extraction should consume decoder outputs (op_table entries, node/tag structure) plus SBPL/profile metadata from static-format tasks, not raw blobs.

Deliverables for this phase:
- A stable description in `ResearchReport.md` of how vocabulary artifacts will be consumed, without overloading this experiment with full vocab extraction responsibilities.

---

## 3. Alignment of synthetic profiles with vocab

- [x] Reuse ingestion helpers from `node-layout` / `op-table-operation` to:
  - [x] Read headers, op-table, and operation_count for all `op-table-operation/sb/*.sb` compiled blobs (via existing `summary.json`).
  - [x] For each profile, list SBPL operations present, observed `op_entries`, and `operation_count`.
- [x] Define a small alignment format:
  - [x] For each profile, record:
    - SBPL operations (names).
    - Operation IDs (once vocab is available).
    - Observed op-table indices (4,5,6, …).
  - [x] Emit a JSON artifact (e.g., `out/op_table_vocab_alignment.json`) capturing this mapping (with Operation IDs placeholders until vocab exists).
- [x] Summarize the alignment method and current status in `ResearchReport.md`.

Deliverables for this phase:
- Alignment JSON artifact (even if operation IDs are still placeholders).
- Updated sections in `ResearchReport.md` explaining alignment logic and limitations.
- Status update (2025-11-28): partial vocab scaffold added (`vocab_extraction.py`) that emits decoder-derived `ops.json`/`filters.json` with `status: partial`; alignment refreshed to carry the new vocab version while keeping `operation_ids=null`.

---

## 4. Interpretation and limits

- [ ] Once a vocabulary file exists, perform a cautious interpretation:
  - [ ] For each bucket (4,5,6, …), list which Operation IDs appear across profiles.
  - [ ] Highlight stable patterns (e.g., “bucket 5 always includes mach-lookup’s ID on this host”).
- [ ] Explicitly document:
  - [ ] Which claims are hard facts (directly from vocab and blobs).
  - [ ] Which claims are hypothesis-level (patterns seen only in these synthetic profiles).
- [ ] Update `ResearchReport.md` with a clear “What we can and cannot infer” section.

Deliverables for this phase:
- Textual interpretation in `ResearchReport.md` framed in terms of the Operation, Operation Pointer Table, and Operation Vocabulary Map concepts.

---

## 5. Turnover and integration

- [x] Keep dated, detailed notes in `Notes.md` for every meaningful step or decision.
- [x] Maintain `ResearchReport.md` as the main narrative:
  - [x] Motivation, design, methods, findings, limits, and next steps.
- [ ] Make sure this experiment feeds back into:
  - [ ] `book/graph/concepts/EXPERIMENT_FEEDBACK.md` (as a short summary and pointer).
  - [ ] Any `validation/tasks.py` entries that use op-table and vocab data.

Open questions to track:

- [ ] How should we represent “buckets” in a way that stays stable across OS builds while still tying to concrete Operation IDs?
- [ ] How much of the alignment logic belongs here versus in shared validation tooling under `book/graph/concepts/validation/` (for example, a dedicated `vocabulary-mapping` script that reads decoder output from canonical blobs)?
- [ ] Once vocab is available, do we see any contradictions between the bucket behavior observed in `op-table-operation` (decoder-backed signatures) and the canonical Operation Vocabulary Map?
