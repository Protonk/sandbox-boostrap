# Experiment Feedback and Next-Step Hooks

This file collects cross-cutting feedback and proposed next steps for experiments under `book/experiments/`, organized by concept cluster. It is meant as a handoff point: future agents can be pointed here and asked to “talk through these next steps” without hunting through individual experiment reports.

Feedback is descriptive, not authoritative; the substrate (`substrate/*.md`) and the concept inventory remain the normative references. Use this file to see how experiments are informing validation plans and where further work is recommended.

---

## Operation / Operation Pointer Table / Operation Vocabulary Map

**Related experiments**

- `book/experiments/node-layout/`
  - Focus: slicing modern compiled profiles into preamble/op-table/node/literal segments; probing node layout via stride heuristics and SBPL deltas.
  - Key outcome: confirmed presence and rough placement of the operation pointer table and literal/regex pools; identified non-uniform op-table patterns like `[6,…,5]` in some mixed-operation profiles without resolving which operations those entries correspond to.
- `book/experiments/op-table-operation/`
  - Focus: mapping SBPL operation names to op-table entry “buckets” (small indices like 4, 5, 6) using synthetic profiles and shared ingestion helpers.
  - Key outcome: showed that unfiltered `file-read*`, `file-write*`, and `network-outbound` share a uniform bucket (4) while `mach-lookup` lives in another (5); adding filters/literals to read moves it to the mach-style bucket (5), and combinations of mach + filtered reads produce non-uniform `[6,6,6,6,6,6,5]` patterns.

**What we’ve learned so far**

- The operation pointer table is observable and behaves in a structured way even for tiny synthetic profiles:
  - Single-op and simple mixed-op profiles often collapse into a uniform op-table (all 4s or all 5s) across all entries.
  - Profiles that mention `mach-lookup` tend to use a different op-table value (5) and a higher `operation_count` than profiles without mach, even when the set of SBPL rules is small.
  - Adding certain filters/literals to `file-read*` (subpath, literal `/etc/hosts`) can move read into the mach-like bucket.
  - Specific combinations (mach + filtered read) can produce genuinely non-uniform tables like `[6,6,6,6,6,6,5]` with `operation_count=7`.
- Node-region tag counts and literal pools change in ways that correlate with these buckets:
  - “Bucket 4” profiles use one pattern of tags (e.g., {0,2,3,4}) and have empty or minimal literal pools.
  - “Bucket 5” and “bucket 6/5” profiles introduce tags {0,1,4,5,6} and carry path-like and mach-name literals with type prefixes.
  - This matches the substrate’s view that compiled profiles pool literals/regexes and route operations through different graph entry families depending on structure.
- Critically, we still lack:
  - A vocabulary-aware mapping from operation names to numeric operation IDs on this host.
  - An assignment of specific SBPL operations to the individual table entries in non-uniform patterns such as `[6,…,5]`.

**Why this aligns with the substrate**

- The substrate defines:
  - **Operation** as a symbolic class of kernel action in SBPL and its numeric ID in compiled profiles.
  - **Operation Pointer Table** as an indirection from operation IDs to PolicyGraph entry nodes.
  - **Operation Vocabulary Map** as a versioned map from names ↔ IDs ↔ argument schemas.
- The experiments respect these roles by:
  - Treating op-table entries as opaque indices (4/5/6) and only inferring **relative** behavior (which buckets appear, how they shift) rather than guessing absolute IDs.
  - Using SBPL deltas to see how changing operations and filters perturbs the op-table and node/literal structure, without over-claiming about hidden fields.
  - Producing structured artifacts (`summary.json`, `op_table_map.json`) that match the “validation pattern” described in Concepts (compile simple profiles; decode headers/op-tables; check structural invariants).

**Recommended next steps (for future agents)**

These steps are ordered from “stay within the current experiment” to “integrate with broader validation tasks”:

1. **Finish targeted SBPL deltas (within op-table-operation)**
   - Add single-op literal profiles and compare buckets:
     - `file-read*` with only `(literal "/etc/hosts")` (no mach, no subpath).
     - Mach-only profiles with and without associated literals (but no extra read rules).
   - Design profiles that:
     - keep literals but toggle mach on/off, and
     - keep mach but toggle filters (subpath vs literal) on/off.
   - Goal: determine whether the non-uniform `[6,…,5]` pattern is fundamentally:
     - “mach + filtered read”,
     - “read+filter complexity regardless of mach”, or
     - an artifact of `operation_count` and the profile’s internal layout.

2. **Connect to the vocabulary-mapping validation cluster**
   - Use or extend the `vocabulary-mapping` tasks in `book/graph/concepts/validation/tasks.py`:
     - Ensure that `out/vocab/ops.json` and `out/vocab/filters.json` exist for this Sonoma host by extracting vocab tables from known system blobs (e.g., `extract_sbs` outputs).
     - Once those tables exist, revisit the op-table-operation artifacts and interpret 4/5/6 as actual operation IDs where possible.
   - This is the step where the experiment transitions from “bucket behavior” to a real **Operation Vocabulary Map** anchored in canonical artifacts.

3. **Add a cautious correlation pass (after vocab exists)**
   - Extend `book/experiments/op-table-operation/analyze.py` or add a sibling tool to:
     - Align op-table indices across all synthetic profiles.
     - Annotate which indices are consistently present in “mach-only” vs “read-only” vs “filtered read” profiles.
     - Use the operation vocabulary table to hypothesize which ID corresponds to each index on this host.
   - Keep this clearly documented as hypothesis-generating: the final word on vocab comes from canonical tables, not just these small experiments.

4. **Optional runtime cross-checks**
   - Run selected semantic probes (`network-filters`, `mach-services`) under specific synthetic profiles and:
     - Log SBPL operation names and observed decisions.
     - Cross-check that profiles in the “mach bucket” behave as expected for mach-lookup (and differently for non-mach ops).
   - This ties the static op-table buckets back to observable runtime behavior, strengthening the Operation concept across SBPL, binary, and runtime layers.

5. **Surface these results in concept/validation docs**
   - When updating concept or validation docs, reference these experiments as:
     - concrete evidence that op-table structure is sensitive to both operations and filters,
     - a template for SBPL-driven static validation of binary structures,
     - and a boundary marker: beyond simple bucket behavior, vocabulary mapping should defer to the dedicated `vocabulary-mapping` tasks and canonical artifacts.

Agents picking up this area of work can start from:

- `book/experiments/op-table-operation/Plan.md`, `Notes.md`, `ResearchReport.md`,
- this feedback section,
- and the `vocabulary-mapping` entries in `book/graph/concepts/validation/tasks.py`,

and then decide whether to deepen the SBPL delta experiments, wire in vocab extraction, or add runtime probes, depending on what the overall validation effort needs next.

---

## Vocabulary extraction (Operation/Filter)

**Related experiments**

- `book/experiments/vocab-from-cache/`
  - Focus: pull Operation/Filter vocab tables from the Sonoma dyld cache (Sandbox framework/libsandbox).
  - Key outcome: harvested `ops.json` (196 entries) and `filters.json` (93 entries) with `status: ok`, host/build metadata, and provenance; added a guardrail (`check_vocab.py`) to assert counts/status.
- `book/experiments/op-table-vocab-alignment/`
  - Focus: align op-table buckets from synthetic profiles with vocab IDs.
  - Key outcome: alignment artifact now populated with `operation_ids`, `filters`, and `filter_ids` per profile; `vocab_status: ok` recorded from the harvested vocab.

**What we’ve learned so far**

- The cache-derived vocab resolves the earlier “partial/unavailable” gap; operation_count is 196 (decoder heuristics that suggested 167 were incomplete).
- Op-table summaries can now carry concrete operation IDs and filter IDs, enabling bucket interpretation on this host.

**Recommended next steps**

1. Interpret bucket patterns with IDs: summarize, per bucket (4/5/6), which operation IDs appear across the synthetic profiles; record host/build/vocab hash.
2. Thread filter IDs into bucket shifts: use filtered profiles to note which filters (by ID) coincide with bucket changes, even if field2 mapping is pending.
3. Keep vocab guardrails in CI: run `check_vocab.py` to catch drift; regenerate alignment when vocab changes.
4. Feed concise findings back into the concept docs as evidence for versioned Operation/Filter Vocabulary Maps.

---

## Field2 / Node decoding / Anchor probes

**Related experiments**

- `book/experiments/field2-filters/`
- `book/experiments/node-layout/`
- `book/experiments/probe-op-structure/`

**Current state**

- Field2 mapping remains blocked by modern node decoding: stride-12 heuristics expose small filter-ID-like values but no literal/regex references.
- Anchor scans now include an `offsets` field and list anchors; with decoder literal_refs and prefix normalization, simple probes now produce node hits for anchors (e.g., `/tmp/foo` → nodes in `v1_file_require_any`). Literal/regex operand decoding is still heuristic and needs proper tag-aware layouts.
- Tag-aware decoder scaffold exists; literal references and per-tag layouts remain to be reverse-engineered.
- Anchor→field2 hints are published under `book/graph/mappings/anchors/anchor_field2_map.json` for reuse.

**Recommended next steps**

1. Prioritize a tag-aware node decoder: per-tag variable-length layouts with operands wide enough to carry literal/regex indices.
2. Once literals are exposed, rerun anchor scans to map anchors → nodes → field2 → filter IDs; add guardrails for key anchors.
3. Use system profiles (strong anchors) as cross-checks; document evidence tiers in the respective ResearchReports.
