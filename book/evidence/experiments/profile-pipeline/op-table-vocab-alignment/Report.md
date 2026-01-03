# Op-table ↔ Operation Vocabulary Alignment – Research Report

## Purpose
The substrate distinguishes three closely-related concepts:

- **Operation** – symbolic SBPL operation name (e.g., `file-read*`, `mach-lookup`, `network-outbound`).
- **Operation Pointer Table** – array in each compiled profile that maps numeric Operation IDs to entry nodes in the PolicyGraph.
- **Operation Vocabulary Map** – versioned mapping from symbolic operation names to numeric IDs and argument schemas for a given OS build.

Two experiments already probe this structure from different angles:

- **node-layout**:
  - inspects synthetic profiles and platform blobs,
  - recovers the broad layout (preamble, op-table, node region, literal/regex pool),
  - tracks how Filters and literals perturb the node region.
- **op-table-operation**:
  - uses SBPL variants to see how op-table entries (buckets 4/5/6/…) change with Operations and Filters,
  - treats bucket values as opaque equivalence classes, not Operation IDs.

What is still missing is the **vocabulary layer**:

- a host-specific Operation Vocabulary Map (with IDs, names, and argument schemas),
- a Filter Vocabulary Map (filter key codes and argument schemas),
- and a way to connect the bucket-level findings from the experiments to these vocabularies in a stable, versioned way.

This experiment sits between the structural experiments and the validation tooling:

- It does **not** build the vocabulary maps itself.
- Instead, it:
  - defines the expected JSON contracts for vocabulary artifacts,
  - produces a host-specific alignment file that merges SBPL operation lists, op-table data, and (eventually) vocabulary IDs,
  - records how to tie alignment records to OS/build metadata and vocabulary versions.

---

## Baseline & scope
**Host / baseline**

- Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (macOS 14.4.1 / 23E224, kernel 23.4.0, Apple Silicon, SIP enabled).
- This matches the environment used by the node-layout and op-table-operation experiments.

**Upstream artifacts reused**

- From `book/evidence/experiments/profile-pipeline/node-layout/`:
  - `out/summary.json` – structural summaries of node/layout behavior.
- From `book/evidence/experiments/profile-pipeline/op-table-operation/`:
  - `out/summary.json` – per-profile operations, op-table entries, decoder snapshots.
  - `out/op_table_map.json` – per-profile op_entries plus single-op hints.
  - `out/op_table_signatures.json` – per-bucket structural signatures.
- Shared tooling: when regenerating alignments, prefer `book/api/profile/` (`op-table` CLI or `book.api.profile.op_table` in Python) or the batch runner `book/tools/sbpl/op_table_runner.py` over experiment-local scripts.

**Validation tooling**

- `book/integration/carton/validation/profile_ingestion` and `decoder` – establish how we slice and decode modern profiles.
- `book/evidence/graph/concepts/validation/out/metadata.json` – records host/OS baseline and static-format metadata.

---

## Deliverables / expected outcomes
- This experiment assumes the existence of two vocabulary artifacts under `book/integration/carton/bundle/relationships/mappings/vocab/`:
  
  1. `ops.json` – **Operation Vocabulary Map**
  
     - `metadata`:
       - OS product/version/build (e.g., `"macOS 14.4.1 (23E224)"`),
       - profile format variant(s) covered (e.g., `"modern-heuristic"`),
       - source blobs used to derive the mapping (e.g., system profiles from `extract_sbs` and curated synthetic profiles),
       - a content hash for the vocab file (so experiments can refer to a specific version).
     - `entries`: list of records, each with at least:
       - `name`: SBPL operation name (string),
       - `id`: numeric Operation ID (integer),
       - `arg_schema` (optional): human-readable summary of arguments (e.g., path, global-name, etc.),
       - `provenance`: description of how this mapping was inferred (which blobs/tools).
  
  2. `filters.json` – **Filter Vocabulary Map**
  
     - `metadata` and `versioning` similar to `ops.json`.
     - `entries`: list of records with:
       - `name`: filter key (string, e.g., `subpath`, `literal`, `global-name`),
       - `id`: numeric filter key code (int),
       - `arg_schema` / `notes` (optional),
       - `provenance`.
  
  Current status (Sonoma host):
  
  - `ops.json` and `filters.json` are harvested from the dyld cache (`status: ok`, 196 ops, 93 filters) with OS/build metadata and provenance in place.
  
  ---

## Plan & execution log
### Completed
- **Current status**
  The main artifact produced by this experiment is:
  
  - `book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json`
  
  Its role is to capture, for each synthetic profile in `op-table-operation`, the information needed to later attach Operation IDs and vocabulary versions without recomputing everything.
  
  **Current JSON schema (per top-level alignment file):**
  
  - Top-level keys:
    - `vocab_present`: whether any `out/vocab/ops.json` was found at alignment time.
    - `vocab_version`: a stable hash of the ops vocab entries used for alignment.
    - `source_summary`: path to the op-table-operation `out/summary.json` used as input.
    - `records`: list of per-profile alignment records.
  
  **Per-profile alignment record:**
  
  - `profile`: profile name (e.g., `"v11_read_subpath"`).
  - `ops`: list of SBPL operation symbols in this profile (e.g., `["file-read*"]`).
  - `op_entries`: the op-table entries (bucket values) from `out/summary.json`.
  - `op_count`: the `operation_count` (heuristic) from header/decoder.
  - `operation_ids`: list of numeric Operation IDs corresponding to `ops`.
  - `filters` / `filter_ids`: filter symbols present in the SBPL and their vocab IDs.
  - `vocab_version`: the specific vocabulary version/hash used for this record.
  
  **Current status:**
  
  - The alignment file covers all profiles from `op-table-operation/out/summary.json`, now with `operation_ids`, `filters`, and `filter_ids` populated from the harvested vocab.
  - `vocab_version` reflects the hash of the ops vocab entries (`1ea1be04243c2d229f71ba12562e7c826ef6a15bcbccbd0b8f1d469cbe5d7b8e` on this baseline); `vocab_status: ok` and `filter_vocab_present: true` are recorded at the top level.
  - The file stays conservative: it captures SBPL ops/filters, op-table buckets, op_count, host baseline, and vocab provenance without inventing mappings beyond the vocab artifacts.
  
  ---
- **1. Setup and scope**
  - Recorded host / OS baseline in `ResearchReport.md`.
  - Inventoried upstream structural artifacts from `node-layout` and `op-table-operation`.
  - Located and documented vocabulary-mapping tasks and outputs (`book/integration/carton/bundle/relationships/mappings/vocab/ops.json`, `filters.json` with status ok).
- **2. Vocabulary extraction hookup**
  - Defined the expected JSON contracts for `ops.json` / `filters.json` and how alignment ties them to specific OS/builds.
  - Recorded assumptions and requirements for vocabulary artifacts in `ResearchReport.md` for future agents.
- **3. Alignment of synthetic profiles with vocab**
  - Reused upstream summaries to build `out/op_table_vocab_alignment.json`, recording per-profile operations, op-table indices, and, once vocab became available, operation IDs and filter IDs.
  - Summarized the alignment method and status in `ResearchReport.md`.
- **4. Interpretation and limits**
  - Performed a first-pass interpretation of bucket↔Operation ID relationships (e.g., mach-lookup (op ID 96) in buckets {5,6} with filters driving bucket 6; file-read*/write*/network in {3,4}) and recorded them in `ResearchReport.md`.
- **5. Turnover and integration**
  - Kept detailed notes in `Notes.md` and maintained `ResearchReport.md` as the main narrative for this alignment layer.

### Planned
- **1. Setup and scope**
  - None for this section.
  Deliverables for this phase:
  - Clear note in `ResearchReport.md` describing the host baseline and which vocab artifacts (if any) are already available.
  ---
- **2. Vocabulary extraction hookup**
  - None for this section (real vocab extraction now lives in `vocab-from-cache`).
  Deliverables for this phase:
  - A stable description in `ResearchReport.md` of how vocabulary artifacts will be consumed, without overloading this experiment with full vocab extraction responsibilities.
  ---
- **3. Alignment of synthetic profiles with vocab**
  - Refresh alignment only when vocab or upstream experiments change.
  Deliverables for this phase:
  - Alignment JSON artifact (even if operation IDs are still placeholders).
  - Updated sections in `ResearchReport.md` explaining alignment logic and limitations.
  - Status update (2025-11-28): partial vocab scaffold added (`vocab_extraction.py`) that emits decoder-derived `ops.json`/`filters.json` with `status: partial`; alignment refreshed to carry the new vocab version while keeping `operation_ids=null`.
  ---
- **4. Interpretation and limits**
  - Refine and expand the interpretation as more operations/filters are exercised, keeping hard facts vs hypotheses clearly separated.
  Deliverables for this phase:
  - Textual interpretation in `ResearchReport.md` framed in terms of the Operation, Operation Pointer Table, and Operation Vocabulary Map concepts.
  ---
- **5. Turnover and integration**
  - Add a short summary and pointer into `book/evidence/graph/concepts/EXPERIMENT_FEEDBACK.md` and any validation tasks that consume op-table/vocab data.
  Open questions to track (Upcoming):
  - How best to represent “buckets” in a way that stays stable across OS builds while still tying to concrete Operation IDs.
  - How much alignment logic should live here versus shared validation tooling under `book/integration/carton/validation/`.
  - Whether future data reveals contradictions between bucket behavior in `op-table-operation` and the canonical Operation Vocabulary Map.

## Evidence & artifacts
- `book/integration/carton/bundle/relationships/mappings/vocab/ops.json` and `filters.json` harvested from the dyld cache for this host (status: ok).
- `book/evidence/experiments/profile-pipeline/op-table-operation/out/summary.json`, `op_table_map.json`, and `op_table_signatures.json` as upstream structural inputs.
- `book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json` capturing per-profile operations, op-table buckets, and (when present) vocabulary IDs and versions.
- Host/format metadata in `book/evidence/graph/concepts/validation/out/metadata.json` that tie alignment runs to the Sonoma baseline.

## Blockers / risks
- Alignment logic is currently scoped to the synthetic profiles exercised in `op-table-operation`; operations not present there are outside this experiment’s coverage.
- Vocabulary artifacts are host/build-specific; changes to `ops.json`/`filters.json` or to decoder behavior may invalidate older alignment files if not regenerated carefully.
- Bucket interpretations remain structural; even with IDs attached, mislabeling is possible if upstream vocab extraction or op-table decoding is wrong.

## Next steps
- Refresh `out/op_table_vocab_alignment.json` whenever vocabulary artifacts or op-table experiment outputs change for this host.
- Refine bucket and Operation-ID interpretations as more operations and filters are exercised in upstream experiments.
- Coordinate with validation tooling under `book/integration/carton/validation/` so that long-term vocabulary and alignment logic lives in shared code rather than being duplicated here.

## Appendix
### 5. Updated findings (with vocab present)
With the Sonoma vocab harvested (`book/integration/carton/bundle/relationships/mappings/vocab/ops.json` / `filters.json`, status: ok), we can attach numeric Operation IDs to the SBPL operation names present in the synthetic profiles from `op-table-operation`.

This does **not** imply that op-table slot indices correspond to operation IDs in these blobs: the synthetic profiles’ op tables are small (typically `op_count` 5–7), and slot semantics remain under exploration. This experiment therefore treats the vocab as an annotation layer (SBPL op name → op ID) and treats `op_entries` patterns as the bucket evidence.

Static facts for this host (from vocab + `op-table-operation` outputs):

- Operation IDs (selected, from vocab):
  - `file-read*` → 21, `file-write*` → 29, `mach-lookup` → 96, `network-outbound` → 112.
- Bucket patterns by profile family (from `op-table-operation`):
  - Unfiltered single-op reads/writes/network (`v1_read`, `v2_write`, `v4_network`) and the deny-default baseline (`v0_empty`) use `op_entries == [4,4,4,4,4]` (`op_count=5`).
  - Mach-only (`v3_mach`) uses `op_entries == [5,5,5,5,5,5]` (`op_count=6`).
  - Filtered read-only (`v11_read_subpath`) also uses `op_entries == [5,5,5,5,5,5]` (`op_count=6`), so bucket 5 is not “mach-only”.
  - Mixed mach + filtered read (`v12_read_subpath_mach`, `v16_subpath_mach_literal`) use the non-uniform pattern `[6,6,6,6,6,6,5]` (`op_count=7`); bucket 6 appears only in these mixed profiles in the current suite.

Bucket→Operation-ID summary (coarse; profile-scoped, not per-slot):

- Bucket 4 appears in profiles whose SBPL op sets include file read/write/network without the “mach + filtered read” combination.
- Bucket 5 appears in mach-only profiles and in filtered-read-only profiles.
- Bucket 6 appears only in profiles that combine `mach-lookup` with a filtered `file-read*` in this synthetic suite.

### Status summary
- Vocab artifacts are `status: ok` (ops=196, filters=93); alignment regenerates cleanly after decoder updates. What remains is a witness-backed model for op-table slot semantics in these synthetic blobs (i.e., how slots relate to Operation IDs, if at all).

---

### 6. What remains to be done
This experiment can treat “SBPL op name → Operation ID” as complete for the synthetic suite; the remaining work is slot-semantics and filter-aware annotation:

1. **Filter-level alignment (new)**
   - Correlate bucket changes with filter IDs from `filters.json` (e.g., `subpath`, `literal`) using the filtered variants.
   - Record any stable filter-driven bucket patterns in this report and in node-layout notes.

2. **Maintenance**
   - Keep `op_table_vocab_alignment.json` in sync with future vocab versions (regenerate if `ops.json` changes).
   - If additional operations/filters are exercised in new SBPL variants, extend the alignment records accordingly.
   - Tooling already loads `ops.json`/`filters.json` and fills operation_ids/filter_ids; keep the vocab hash/version current when regenerating.

3. **Sanity-check buckets vs IDs**

   With IDs in hand, we can perform checks like:

	   - “Across all synthetic profiles, which SBPL ops (and their IDs) co-occur with bucket 6, and what filter structures are shared?”
   - “Does the ID for `mach-lookup` always appear in bucket 5 in these datasets?”
   - “Do Operation IDs for filtered read variants appear in both bucket 5 and 6, or is 6 reserved for certain combinations?”

   Any such claims must be:

   - explicitly scoped to this host and set of profiles,
   - recorded as facts only when the data is clear,
   - otherwise framed as hypotheses for further testing.

4. **Feed results back into concept and experiment layers**

   Once some Operation↔bucket relationships are firm:

   - update this report and `Plan.md` with a concise summary,
   - cross-link to:
     - `node-layout` (e.g., “tag6-heavy regions correlate with Operation IDs X, Y, Z in bucket 6”),
     - `op-table-operation` (e.g., “bucket 5 is where mach-lookup and filtered read IDs land in these synthetic profiles”),
     - `book/evidence/graph/concepts/EXPERIMENT_FEEDBACK.md` with a short note and pointers.

   This will turn the current bucket-level observations into properly versioned vocabulary evidence.

---

### 7. Practical guidance for future agents
If you pick up this experiment, the recommended workflow is:

1. **Read the upstream experiments**
   - Skim `book/evidence/experiments/profile-pipeline/node-layout/ResearchReport.md` and `Plan.md`.
   - Skim `book/evidence/experiments/profile-pipeline/op-table-operation/ResearchReport.md` and `Plan.md`.
   - Confirm that op-table buckets 4/5/6 and tag/field patterns are still as described (re-run analyzers if needed).

2. **Confirm current alignment state**
   - Inspect `book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json` to see:
     - which profiles are covered,
     - which fields are populated (ops, operation_ids, filters, filter_ids).
   - Verify `ops.json` / `filters.json` status is `ok` (ops=196, filters=93) and note the `generated_at` stamp being used.

3. **Refine interpretation**
   - With vocab in place, focus on interpreting bucket↔operation/filter patterns rather than plumbing.
   - Record any stable bucket assignments in `ResearchReport.md`, scoped to this host/build and vocab version.

5. **Keep changes small and well-documented**
   - When you adjust alignment logic or vocab contracts:
     - capture the rationale in `Notes.md`,
     - keep this report and `Plan.md` in sync,
     - run `make -C book test` to ensure the experiment’s sanity checks remain green.

---

### 8. Role in the larger project
This experiment:

- encodes the **interface** between bucket-level structural experiments and vocabulary-oriented validation:
  - it defines how to consume Operation/Filter vocabularies,
  - it specifies how to version alignment records by OS/build and vocab hash,
  - it provides a single JSON artifact (`op_table_vocab_alignment.json`) that downstream tools can read.
- respects the substrate’s discipline:
  - no ungrounded Operation-ID guesses,
  - clear separation between structural observations and vocabulary claims,
  - explicit versioning requirements for high-churn surfaces like Operation and Filter catalogues.

Once vocabulary artifacts and alignment are in place, future work can use this experiment as a foundation for:

- capability catalog entries expressed in terms of underlying Seatbelt constructs,
- cross-version comparisons of Operation and Filter vocabularies,
- and more ambitious debugging stories that connect SBPL text, binary profiles, and runtime traces through a single, stable conceptual IR.***
