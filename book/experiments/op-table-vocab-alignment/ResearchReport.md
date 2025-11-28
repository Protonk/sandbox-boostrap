# Op-table ↔ Operation Vocabulary Alignment – Research Report (Sonoma / macOS 14.4.1)

This document is the unified report for the **op-table-vocab-alignment** experiment under `book/experiments/op-table-vocab-alignment/`. It explains why this experiment exists, what artifacts it produces, and what is still needed before we can align op-table buckets (4/5/6/…) with a proper **Operation Vocabulary Map** and **Filter Vocabulary Map** on this host.

A new agent should be able to read this file plus `Plan.md` and `Notes.md` and immediately see where to pick up the work.

---

## 1. Motivation and scope

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

## 2. Environment and dependencies

**Host / baseline**

- macOS 14.4.1 (23E224), kernel 23.4.0, Apple Silicon, SIP enabled.
- This matches the environment used by the node-layout and op-table-operation experiments.

**Upstream artifacts reused**

- From `book/experiments/node-layout/`:
  - `out/summary.json` – structural summaries of node/layout behavior.
- From `book/experiments/op-table-operation/`:
  - `out/summary.json` – per-profile operations, op-table entries, decoder snapshots.
  - `out/op_table_map.json` – per-profile op_entries plus single-op hints.
  - `out/op_table_signatures.json` – per-bucket structural signatures.

**Validation tooling**

- `book/graph/concepts/validation/profile_ingestion` and `decoder` – establish how we slice and decode modern profiles.
- `book/graph/concepts/validation/out/metadata.json` – records host/OS baseline and static-format metadata.

---

## 3. Vocabulary artifacts: expected contracts

This experiment assumes the existence of two vocabulary artifacts under `book/graph/concepts/validation/out/vocab/`:

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

## 4. Alignment artifact: shape and current status

The main artifact produced by this experiment is:

- `book/experiments/op-table-vocab-alignment/out/op_table_vocab_alignment.json`

Its role is to capture, for each synthetic profile in `op-table-operation`, the information needed to later attach Operation IDs and vocabulary versions without recomputing everything.

**Current JSON schema (per top-level alignment file):**

- Top-level keys:
  - `vocab_present`: whether any `out/vocab/ops.json` was found at alignment time.
  - `vocab_version`: a timestamp or version string for the vocab file used.
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
- `vocab_version` reflects the `generated_at` stamp in `ops.json`; `vocab_status: ok` and `filter_vocab_present: true` are recorded at the top level.
- The file stays conservative: it captures SBPL ops/filters, op-table buckets, op_count, host baseline, and vocab provenance without inventing mappings beyond the vocab artifacts.

---

## 5. Updated findings (with vocab present)

With the Sonoma vocab harvested (`ops.json`/`filters.json` status: ok), we can now anchor bucket patterns to concrete Operation IDs:

- Operation IDs (selected):
  - `file-read*` → 21, `file-write*` → 29, `mach-lookup` → 96, `network-outbound` → 112.
- Single-op profiles (op_table length 196):
  - `v1_read` (file-read*) uses bucket 3 at index 21.
  - `v2_write` (file-write*) uses bucket 3 at index 29.
  - `v3_mach` (mach-lookup) uses bucket 5 at index 96.
  - `v4_network` (network-outbound) uses bucket 3 at index 112.
  - `v0_empty` remains uniform bucket 4.
- Mixed profiles:
  - Unfiltered mixes (`v5_read_write`, `v7_read_network`) keep bucket 3 for file/net ops.
  - Mach-inclusive mixes (`v6_read_mach`, `v8_write_mach`, `v10_mach_network`) show buckets {3,5} depending on op: mach stays 5; file/net stay 3.
  - Filtered read variants (subpath/literal) elevate file-read* to bucket 5 in these synthetic profiles, indicating filter-driven bucket changes.
- Filter IDs are available and recorded per profile; correlating bucket shifts with specific filter IDs remains open analysis work.

---

## 6. What remains to be done

This experiment can now close the Operation-ID alignment; the remaining work is filter-aware annotation and cross-linking:

1. **Filter-level alignment (new)**
   - Correlate bucket changes and decoder `field2` values with filter IDs from `filters.json` (e.g., `subpath`, `literal`) using the filtered variants.
   - Record any stable field2 ↔ filter-ID patterns in this report and in node-layout notes.

2. **Maintenance**
   - Keep `op_table_vocab_alignment.json` in sync with future vocab versions (regenerate if `ops.json` changes).
   - If additional operations/filters are exercised in new SBPL variants, extend the alignment records accordingly.
   - Tooling already loads `ops.json`/`filters.json` and fills operation_ids/filter_ids; keep the vocab hash/version current when regenerating.

3. **Sanity-check buckets vs IDs**

   With IDs in hand, we can perform checks like:

   - “Across all synthetic profiles, which Operation IDs appear in bucket 4 vs 5 vs 6?”
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
     - `node-layout` (e.g., “field2=6 and tag6-heavy regions correlate with Operation IDs X, Y, Z in bucket 6”),
     - `op-table-operation` (e.g., “bucket 5 is where mach-lookup and filtered read IDs land in these synthetic profiles”),
     - `book/graph/concepts/EXPERIMENT_FEEDBACK.md` with a short note and pointers.

   This will turn the current bucket-level observations into properly versioned vocabulary evidence.

---

## 7. Practical guidance for future agents

If you pick up this experiment, the recommended workflow is:

1. **Read the upstream experiments**
   - Skim `book/experiments/node-layout/ResearchReport.md` and `Plan.md`.
   - Skim `book/experiments/op-table-operation/ResearchReport.md` and `Plan.md`.
   - Confirm that op-table buckets 4/5/6 and tag/field patterns are still as described (re-run analyzers if needed).

2. **Confirm current alignment state**
   - Inspect `book/experiments/op-table-vocab-alignment/out/op_table_vocab_alignment.json` to see:
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
     - run `pytest book/tests` to ensure the experiment’s sanity checks remain green.

---

## 8. Role in the larger project

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
