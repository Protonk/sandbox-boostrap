# Op-table vs Operation Mapping – Research Report (Sonoma baseline)

## Purpose
In the substrate:

- An **Operation** is a class of kernel action (e.g., `file-read*`, `mach-lookup`, `network-outbound`).
- The **Operation Pointer Table** maps numeric Operation IDs to entry nodes in the compiled **PolicyGraph**.
- The **Operation Vocabulary Map** is a versioned mapping between SBPL operation names and those numeric IDs.

The **node-layout** experiment established that modern profiles have:

- a 16‑byte preamble,
- an Operation Pointer Table section,
- a node region (12‑byte nodes at the front),
- and a literal/regex pool.

However, it did not answer:

- which SBPL operations end up in which op-table “bucket” (indices like 4, 5, 6),
- how filters and literals change those buckets,
- and how non-uniform patterns such as `[6,6,6,6,6,6,5]` should be interpreted.

This experiment focuses on that gap:

- Use **synthetic SBPL profiles** to probe how op-table entries change as we add and remove operations and filters.
- Treat raw op-table entries as **opaque bucket labels**, not Operation IDs.
- Use decoder-backed per-entry “signatures” (tag/literal patterns) as structural fingerprints.
- Prepare the ground for later vocabulary-mapping work that will supply real Operation IDs.
- Shared tooling: for new blob summaries (op_table entries, tag counts, literals, entry signatures), prefer `book/api/op_table` (CLI or Python) over extending `analyze.py`.

We intentionally avoid guessing a full Operation Vocabulary Map; that belongs to `book/graph/concepts/validation` once canonical artifacts exist.

---

## Baseline & scope
**Host / baseline**

- Sonoma baseline from `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json` (macOS 14.4.1 / 23E224), Apple Silicon, SIP enabled.

**Directory contents**

- `Plan.md` – experiment plan and open questions.
- `Notes.md` – dated notes on variants, analyzer changes, and findings.
- `sb/` – SBPL variants for this experiment.
- `sb/build/*.sb.bin` – compiled profile blobs (written by the analyzer).
- `analyze.py` – the main tool here:
  - compiles all `sb/*.sb` using `libsandbox.dylib` and `sandbox_compile_string`,
  - parses SBPL to recover the list of allowed operation symbols per profile,
  - tokenizes SBPL to recover filter symbols and map them to filter vocab IDs,
  - uses `profile_ingestion.parse_header` and `slice_sections` to recover `operation_count` and section boundaries,
  - calls `decoder.decode_profile_dict` to get node counts, tag counts, literal strings, and sections,
  - extracts op-table entries from the blob,
  - computes simple tag counts over the node region (stride‑12),
  - derives per-entry structural **signatures** by walking from each unique op-table index over the decoder node list,
  - writes:
    - `out/summary.json` – per-profile details,
    - `out/op_table_map.json` – per-profile op_entries + single-op hints,
    - `out/op_table_signatures.json` – per-profile entry signatures.

**Shared dependencies**

- `book.graph.concepts.validation.profile_ingestion` – header parsing, section slicing.
- `book.graph.concepts.validation.decoder` – modern-profile decoder (preamble, op-table, nodes, literal pool).

---

## Deliverables / expected outcomes
- SBPL probe profiles under `sb/` and compiled blobs under `sb/build/*.sb.bin` covering key operation combinations (file-read*/write*, mach-lookup, network-outbound, baselines).
- `book/experiments/op-table-operation/out/summary.json` with per-profile op-table entries, decoder snapshots, and structural statistics.
- `book/experiments/op-table-operation/out/op_table_map.json` recording op_entries, unique buckets, and operation sets (plus filter annotations) per profile.
- `book/experiments/op-table-operation/out/op_table_signatures.json` capturing per-entry structural signatures (tags, `field2` distributions, reachable literals).
- Narrative notes and this report summarizing bucket behavior and remaining unknowns on this host.

## Plan & execution log
### Completed
- **Current status**
  - Bucket behavior and vocab alignment are stable on this host: unfiltered read/write/network live in buckets {3,4}; mach lives in {5,6}; bucket 6 appears only in mach+filtered-read mixes. Alignment artifacts and summaries are current.
  - Remaining work is optional: runtime probes or filter-level annotation once field2 decoding matures. Runtime spot-checks are now feasible via the SBPL wrapper if we want to add behavioral evidence.
- **1. Setup and scope**
  - Defined the core operation set to probe (file-read*, file-write*, mach-lookup, network-outbound, and a baseline profile).
  - Created single-op and paired-op SBPL profiles under `sb/` covering these operations.
  - Added `analyze.py` to compile all variants and emit op_count, op_entries, stride-12 tag counts, remainders, and literal summaries.
- **2. Data collection and correlation**
  - Compiled all `sb/*.sb` variants and produced `out/summary.json`.
  - Built `out/op_table_map.json` capturing op_entries, unique buckets, and operation sets per profile, including filter annotations.
- **3. Cross-check with semantic probes (optional stretch)**
  - Reused the shared decoder to walk from each op-table entrypoint and record per-entry signatures (tag_counts, field2 distributions, reachable literals), stored in `out/op_table_signatures.json`.
  - Added an in-process runtime spot-check for the `[6,…,5]` profile (`v12_read_subpath_mach`) via `runtime_probe.c`: `sandbox_init` succeeded; `mach-lookup` (`com.apple.cfprefsd.agent`) returned `kr=0`; file reads of both the allowed subpath and `/etc/hosts` returned `EPERM`. Runtime results recorded in `out/runtime_signatures.json` (schema `provisional`).
  - Added a control runtime probe for `v11_read_subpath` (bucket {5}): `sandbox_init` succeeded; both reads returned `EPERM`; `mach_lookup` returned `kr=1100`. Also recorded as provisional in `out/runtime_signatures.json`.
  - Consolidated static data plus provisional runtime hints into `out/op_table_catalog_v1.json` via `build_catalog.py`. Each record includes bucket pattern, op entries, ops/filters, decoder signatures, and optional `runtime_signature` flagged as provisional for future `ops.json` joins.
- **4. Documentation and reporting**
  - Kept dated notes in `Notes.md`.
  - Summarized findings and open questions in `ResearchReport.md`.
  - Ensured outputs are scoped to the Sonoma host/build.
  ---

### Planned
- The `Plan.md` file contains an up-to-date checklist; this section highlights the most important actions for continuing the experiment.
  
  1. **Maintain bucket-level discipline**
    - Treat `op_entries` values (4, 5, 6, …) as **opaque buckets** until a versioned Operation Vocabulary Map exists.
     - Update this report, `Plan.md`, and `Notes.md` if new buckets appear (e.g., 7, 8, …), making clear how they arise and in which SBPL patterns.
  
  2. **Targeted deltas around mach and literals**
     - Design new SBPL profiles to answer questions like:
       - Does a single-op `file-read*` with both `subpath` and `literal` but **no** mach produce bucket 5 or 6?
       - Does mach-only plus a literal (without any extra `file-read*` rules) bring in bucket 6, or stay uniform `[5,…]`?
       - If we keep both subpath and literal but remove mach, does the `[6,…,5]` pattern disappear?
     - For each new variant:
       - regenerate `out/summary.json` and `out/op_table_signatures.json`,
       - record observations in `Notes.md`,
       - extend this report if a new pattern emerges.
  
  3. **Integrate with vocabulary-mapping once available**
     - Once `graph/mappings/vocab/ops.json` exists:
       - write a small script (either here or in `validation`) that:
         - reads `summary.json` and `op_table_signatures.json`,
         - maps SBPL operation names to numeric Operation IDs via the vocabulary file,
         - annotates each bucket (4/5/6) with the set of Operation IDs that ever use it in these synthetic profiles.
       - explicitly distinguish:
         - facts (IDs and table entries from canonical vocab + blobs),
         - hypotheses (patterns that might not generalize beyond these profiles).
     - Update this report with any firm Operation↔bucket relationships established by that mapping.
  
  4. **Optional runtime probes**
     - If it fits within `book/graph/concepts/validation`:
       - run a tiny app or harness under selected synthetic profiles (e.g., “bucket‑4 only”, “bucket‑5 only”, “[6,…,5]”),
       - exercise operations like `mach-lookup` and `network-outbound`,
       - log which SBPL operations and kernel operations appear in traces.
       - The new `book/api/SBPL-wrapper/wrapper` (SBPL and blob) plus the runtime-checks harness can drive these probes without `sandbox-exec`.
       - When probing file-read/write behavior, create fixtures in `/tmp` first to avoid “No such file or directory” denials that mask policy decisions.
     - Use these logs to validate that:
       - “mach bucket” profiles really gate mach behavior as expected,
       - read/write/network behavior is consistent between bucket 4 and 5 where allowed by SBPL.
  
  5. **Coordinate with node-layout and vocab-alignment experiments**
     - Use node-layout’s findings on node tags and the “field2” key to interpret entry signatures:
       - bucket 4 signatures should align with tag/field patterns found in unfiltered profiles,
       - bucket 5 signatures with filtered/mach patterns,
       - bucket 6 signatures with tag6-heavy, multi-filter branches.
     - When a Filter Vocabulary Map (`filters.json`) exists, try to connect field-level keys in node-layout to filter-level interpretations in this experiment.
  
  6. **Keep artifacts and documentation aligned**
     - Whenever you add or modify SBPL variants:
       - describe the intent in `Notes.md`,
       - ensure `analyze.py` still compiles everything and updates all three outputs,
      - run `make -C book test` to keep the experiment’s tests green.
     - If you add new buckets or signatures, consider extending `book/tests/test_experiments.py` with sanity checks (e.g., verifying that specific profiles still have expected bucket shapes).
  
  ---
- **1. Setup and scope**
  - Only extend the operation set if new structural questions arise.
  - `sb/*.sb` variants + compiled blobs under `sb/build/`.
  - `out/summary.json` (per-variant structured data).
  - A correlation artifact `out/op_table_map.json` that attempts to map op names → op-table index guess.
  ---
- **2. Data collection and correlation**
  - Re-run the analyzer only when vocab or decoder behavior changes.
  ---
- **3. Cross-check with semantic probes (optional stretch)**
  - Optionally run existing semantic probes via `book/api/SBPL-wrapper/wrapper` (SBPL or blob) and annotate runtime traces with op-table slots and structural signatures, writing any such results to `out/runtime_usage.json`.
  - If running spot checks, ensure probe targets exist (e.g., create `/tmp/op_table_probe.txt`) so read/write paths exercise the allow/deny rules meaningfully.
  ---
- **5. Open questions to resolve**
  - Use decoder-backed signatures and vocab alignment to pin specific op names to the distinct op-table entries in non-uniform patterns (e.g., `[6,…,5]` profiles).
  - Study how non-uniform entries move when adding/removing particular operations, and whether node/tag deltas can provide secondary evidence for op→entry mapping.
  - Explore the interaction between filters/literals and op-table buckets (e.g., why filtered `file-read*` shifts buckets and how mach/literal/subpath combinations produce `[6,…,5]`).

## Evidence & artifacts
- SBPL variants under `sb/` and compiled profiles in `sb/build/*.sb.bin`.
- Analyzer script `book/experiments/op-table-operation/analyze.py`.
- `out/summary.json`, `out/op_table_map.json`, and `out/op_table_signatures.json` as described above.
- Consolidated catalog: `out/op_table_catalog_v1.json` (schema `op_table_catalog_v1`) with bucket patterns, ops/filters, decoder signatures, and provisional runtime hints.
- Shared decoder/ingestion helpers under `book/graph/concepts/validation/` used to derive op_count, sections, and node lists.

## Blockers / risks
Despite the structural progress, several key questions are still open:

1. **Which Operation maps to which bucket?**
   - We know patterns like:
     - “unfiltered read/write/network → bucket 4”,
     - “mach-only and filtered read-only → bucket 5”,
     - “mach + filtered read (with `op_count=7`) → buckets 6 and 5 mixed”.
   - But we do **not** know:
     - which numeric Operation IDs live in those buckets,
     - or which specific SBPL operation symbol occupies the lone `5` entry in `[6,…,5]`.

2. **Per-slot assignment in `[6,…,5]` profiles**
   - In `[6,6,6,6,6,6,5]`, multiple op-table entries share each bucket.
   - Without a known Operation vocabulary ordering, we cannot map op-table index positions (0..op_count‑1) to specific Operation IDs.
   - Entry signatures show that both entries have similar tag/field2 patterns, so structure alone does not yet pin down which slot is “mach” vs “filtered read” vs “helper”.

3. **Interaction of Filters and bucket shifts**
   - We have empirical evidence that:
     - adding a subpath or literal filter moves `file-read*` from bucket 4 to 5,
     - combining mach with filtered read introduces bucket 6.
   - We do not yet have a principled explanation (per-profile or per-format-variant) of **why** these buckets shift, beyond “compiled profile structure changes”.

4. **Connection to Operation Vocabulary Map**
   - There is no `graph/mappings/vocab/ops.json` yet for this host. This is the blocking element for promotion: without it we cannot label bucket 4/5/6 with concrete Operation IDs or verify bucket observations against a canonical vocabulary.

5. **Runtime cross-check**
   - No semantic probes (`network-filters`, `mach-services`) have been run under these synthetic profiles to connect buckets to runtime behavior. A minimal next step would be to run a tiny harness under a “mach bucket” profile vs a “network bucket” profile to confirm the expected allow/deny patterns.

---

## Next steps
- Maintain bucket-level discipline by treating op-table entries as opaque bucket labels until Operation IDs are supplied by vocabulary artifacts.
- Refresh analyzer outputs only when the decoder, vocab, or SBPL variants change in ways that affect op-table structure.
- (Optional) add runtime spot-checks via the SBPL wrapper for a few “mach bucket” and “read/write bucket” profiles once a harness is stable.
- Coordinate with `op-table-vocab-alignment` and `vocab-from-cache` as Operation Vocabulary Maps evolve, so bucket observations can be anchored to concrete Operation IDs where justified.

## Appendix
### 3. SBPL profiles and method
The SBPL variants are built around a small operation set:

- **Filesystem operations**: `file-read*`, `file-write*`.
- **IPC**: `mach-lookup` on a fixed global-name (`"com.apple.cfprefsd.agent"`).
- **Network**: `network-outbound`.

They fall into three main families:

1. **Unfiltered, single-op and multi-op profiles**

   - Baseline/no-op:
     - `v0_empty`: `(deny default)` only (no explicit allow).
   - Single-op:
     - `v1_read`: `file-read*`,
     - `v2_write`: `file-write*`,
     - `v3_mach`: `mach-lookup` (cfprefsd),
     - `v4_network`: `network-outbound`.
   - Unfiltered mixes:
     - `v5_read_write`,
     - `v6_read_mach`,
     - `v7_read_network`,
     - `v8_write_mach`,
     - `v9_write_network`,
     - `v10_mach_network`.

2. **Filtered read profiles (subpath, literal) and mixes**

   - Single filtered:
     - `v11_read_subpath`: `file-read*` with `(subpath "/tmp/foo")`.
   - Filtered + mach / write / network:
     - `v12_read_subpath_mach`,
     - `v13_read_subpath_write`,
     - `v14_read_subpath_network`.
   - Mach + literal variants:
     - `v15_mach_literal`: mach plus `file-read*` with `(literal "/etc/hosts")`,
     - `v16_subpath_mach_literal`: mach plus read+subpath and read+literal.

3. **Additional literal and mixed cases (via node-layout experiment)**

   - Some “node-layout” variants (e.g., dual subpath / dual literal `require-any`) inform how we reason about filter structure; the op-table behavior is mirrored here when similar mixes are used.

**Method**

For each profile, `analyze.py`:

1. Parses SBPL to list operation symbols (e.g., `["file-read*", "mach-lookup"]`).
2. Compiles SBPL via `libsandbox`, producing a modern profile blob.
3. Uses `profile_ingestion` to recover:
   - `operation_count` (heuristic, from the header),
   - op-table bytes,
   - node bytes,
   - literal/regex pool bytes.
4. Calls the decoder to obtain:
   - `node_count`, `tag_counts`, decoder `literal_strings`, and sections.
5. Reads op-table as an array of 16‑bit indices (`op_entries`).
6. Builds per-entry **signatures**:
   - For each unique entry index `e` in `op_entries`:
     - depth-first walk over decoder nodes, interpreting the first two fields as edges,
     - record:
       - reachable node indices count,
       - tags encountered,
       - the third field (`fields[2]`, “field2”) values seen,
       - a truncation flag if the visit limit is exceeded.

The analysis then compares:

- single-op vs multi-op profiles,
- filtered vs unfiltered reads,
- mach vs non-mach combinations,
- profiles with uniform vs non-uniform op-table entries.

All interpretations treat op-table entries (4, 5, 6, …) as opaque bucket labels.

---

### 4. Structural findings: buckets and operations


### 4.1 Uniform op-tables without filters
From the baseline and unfiltered profiles:

- `v0_empty`, `v1_read`, `v2_write`, `v4_network`, and multi-op mixes **without** mach (`v5_read_write`, `v7_read_network`, `v9_write_network`, `v16_read_and_network`, `v17_read_write_network`) all show:
  - `operation_count = 5`,
  - `op_entries = [4,4,4,4,4]`.

- `v3_mach` (mach-only) and any unfiltered mixes **with** mach (`v6_read_mach`, `v8_write_mach`, `v10_mach_network`, `v14_mach_and_network`, `v18_read_mach_network`, `v19_mach_write_network`) show:
  - `operation_count = 6`,
  - `op_entries = [5,5,5,5,5,5]`.

Interpretation:

- On these tiny profiles, the op-table collapses operations into **coarse buckets**:
  - bucket `4`: “ordinary” operations (read/write/network) and the empty baseline,
  - bucket `5`: operations that involve `mach-lookup`.
- No differentiation among individual operations within these buckets is visible yet; all op-table entries are identical per profile.

### 4.2 Filters move reads between buckets
Introducing Filters on `file-read*`:

- `v11_read_subpath` (read with `(subpath "/tmp/foo")`), `v20_read_literal` (read with a single literal, from node-layout), and similar filtered read-only profiles:
  - `operation_count = 6`,
  - `op_entries = [5,5,5,5,5,5]`,
  - decoder tag counts align with other “bucket 5” profiles (tags {0,1,4,5}).

Key contrast:

- Unfiltered `file-read*` lives in bucket `4` (along with write/network/baseline).
- Filtered `file-read*` moves into bucket `5`, alongside mach profiles, even when mach is absent.

Interpretation:

- The op-table bucket for a given Operation depends not only on the Operation symbol but also on the presence of certain Filters and the overall profile shape (`operation_count` and node layout).
- Bucket membership (4 vs 5) is a structural property of the compiled profile, not a direct encoding of the SBPL operation name.

### 4.3 Non-uniform op-tables: `[6,6,6,6,6,6,5]`
The most informative cases are mixed profiles where both mach and filtered reads are present and `operation_count` rises to 7:

- `v12_read_subpath_mach`: `file-read*` with `(subpath "/tmp/foo")` plus `mach-lookup`.
- `v15_mach_literal`: `mach-lookup` plus `file-read*` with `(literal "/etc/hosts")`.
- `v16_subpath_mach_literal`: mach plus read+subpath plus read+literal.

These all produce:

- `operation_count = 7`,
- `op_entries = [6,6,6,6,6,6,5]`,
- decoder tag counts that include `tag6` in addition to `tag5` and others.

In contrast:

- Profiles that combine filtered read with write or network (e.g., `v13_read_subpath_write`, `v14_read_subpath_network`) remain uniform `[5,…]`.
- Profiles that combine mach with write/network alone (no filtered read) also remain `[5,…]`.

Interpretation:

- Non-uniform op-tables (`[6,…,5]`) appear when both:
  - mach-lookup is present, and
  - there is at least one filtered `file-read*` (subpath or literal).
- Bucket `6` represents a new family of entrypoints that only appears in these more complex, filtered-mix profiles.
- The lone `5` entry coexists with six `6` entries, but we cannot yet assign specific operations to “the `5` slot” vs “the `6` slots”.

---

### 5. Decoder-backed entry signatures
To attach some structure to each bucket, we compute **entry signatures** using the shared decoder:

- For each unique op-table entry index `e` in a profile:
  - we walk the decoder node list starting from `e`,
  - treat the first two `fields` words as candidate edges,
  - record:
    - number of reachable nodes,
    - the set of `tag` values seen,
    - the set of `fields[2]` values (“field2” keys) seen,
    - whether the walk truncated due to a visit limit.

These signatures are stored:

- per-profile inside `out/summary.json` (as `entry_signatures`),
- aggregated in `out/op_table_signatures.json`.

Early observations:

- Bucket `4` entries (baseline/read/write/network) tend to:
  - reach a very small region (often a single node),
  - see only `tag4`,
  - see `field2` in the {3,4} range.

- Bucket `5` entries (mach-only and filtered read-only families) tend to:
  - reach a small region,
  - see `tag5` (sometimes `tag6` in mixed cases),
  - see `field2` values `{4,5}`.

- In `[6,…,5]` profiles:
  - both entries `5` and `6` appear in signatures with tags `{5,6}`,
  - both see `field2` values that include 5 and 6,
  - walks are shallow (often just 1–2 nodes), reflecting both the limited depth of the heuristic and the small profiles.

Bucket→operation IDs (with vocab from `vocab-from-cache`):

- `file-read*` (ID 21), `file-write*` (ID 29), and `network-outbound` (ID 112) land in buckets {3,4} across these profiles (unfiltered vs filtered/mach mixes).
- `mach-lookup` (ID 96) lands in buckets {5,6}, with bucket 6 appearing only in the mach+filtered-read mixes that produce the `[6,…,5]` op-table.

These signatures:

- reinforce the notion that buckets are associated with distinct node/tag/field families,
- but they do not yet disambiguate which bucket corresponds to which SBPL Operation symbol,
- and they remain heuristic (we are not decoding the full graph semantics).

---

### 8. Role in the broader project
Within the project’s conceptual stack:

- This experiment provides **evidence** that:
  - the Operation Pointer Table is sensitive to both Operations and Filters,
  - small, well-defined SBPL changes cause predictable shifts in bucket patterns,
  - non-uniform op-tables arise even in tiny profiles when mach and filtered reads are combined.
- It supplies artifacts that:
  - `op-table-vocab-alignment` can use once Operation Vocabulary Maps exist,
  - the concept docs can reference when explaining the relationship between Operation, Operation Pointer Table, and Operation Vocabulary Map.

The key outcome is not a finished mapping from SBPL names to numeric IDs, but a disciplined, reproducible set of bucket-level observations and structured signatures that future vocabulary-mapping and runtime experiments can build on.***
