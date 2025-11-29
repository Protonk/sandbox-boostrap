# Op-table ↔ Operation Vocabulary Alignment Experiment (Sonoma host)

Goal: align the op-table “buckets” observed in synthetic profiles with a proper Operation Vocabulary Map on this host, using canonical vocab artifacts rather than guessing from bucket indices alone.

This experiment is a bridge between the existing `node-layout` and `op-table-operation` experiments and the vocabulary-mapping validation cluster under `book/graph/concepts/validation/`.

---

## 1. Setup and scope

**Done**

- Recorded host / OS baseline in `ResearchReport.md`.
- Inventoried upstream structural artifacts from `node-layout` and `op-table-operation`.
- Located and documented vocabulary-mapping tasks and outputs (`book/graph/mappings/vocab/ops.json`, `filters.json` with status ok).

**Upcoming**

- None for this section.

Deliverables for this phase:
- Clear note in `ResearchReport.md` describing the host baseline and which vocab artifacts (if any) are already available.

---

## 2. Vocabulary extraction hookup

**Done**

- Defined the expected JSON contracts for `ops.json` / `filters.json` and how alignment ties them to specific OS/builds.
- Recorded assumptions and requirements for vocabulary artifacts in `ResearchReport.md` for future agents.

**Upcoming**

- None for this section (real vocab extraction now lives in `vocab-from-cache`).

Deliverables for this phase:
- A stable description in `ResearchReport.md` of how vocabulary artifacts will be consumed, without overloading this experiment with full vocab extraction responsibilities.

---

## 3. Alignment of synthetic profiles with vocab

**Done**

- Reused upstream summaries to build `out/op_table_vocab_alignment.json`, recording per-profile operations, op-table indices, and, once vocab became available, operation IDs and filter IDs.
- Summarized the alignment method and status in `ResearchReport.md`.

**Upcoming**

- Refresh alignment only when vocab or upstream experiments change.

Deliverables for this phase:
- Alignment JSON artifact (even if operation IDs are still placeholders).
- Updated sections in `ResearchReport.md` explaining alignment logic and limitations.
- Status update (2025-11-28): partial vocab scaffold added (`vocab_extraction.py`) that emits decoder-derived `ops.json`/`filters.json` with `status: partial`; alignment refreshed to carry the new vocab version while keeping `operation_ids=null`.

---

## 4. Interpretation and limits

**Done (initial)**

- Performed a first-pass interpretation of bucket↔Operation ID relationships (e.g., mach-lookup in buckets {5,6}, file-read*/write*/network in {3,4}) and recorded them in `ResearchReport.md`.

**Upcoming**

- Refine and expand the interpretation as more operations/filters are exercised, keeping hard facts vs hypotheses clearly separated.

Deliverables for this phase:
- Textual interpretation in `ResearchReport.md` framed in terms of the Operation, Operation Pointer Table, and Operation Vocabulary Map concepts.

---

## 5. Turnover and integration

**Done**

- Kept detailed notes in `Notes.md` and maintained `ResearchReport.md` as the main narrative for this alignment layer.

**Upcoming**

- Add a short summary and pointer into `book/graph/concepts/EXPERIMENT_FEEDBACK.md` and any validation tasks that consume op-table/vocab data.

Open questions to track (Upcoming):

- How best to represent “buckets” in a way that stays stable across OS builds while still tying to concrete Operation IDs.
- How much alignment logic should live here versus shared validation tooling under `book/graph/concepts/validation/`.
- Whether future data reveals contradictions between bucket behavior in `op-table-operation` and the canonical Operation Vocabulary Map.
