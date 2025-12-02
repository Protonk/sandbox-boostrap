# Agent readout — repo status (Sonoma host, macOS 14.4.1 / 23E224)

This report is for a human or agent arriving “cold” at the Seatbelt textbook repo. It explains what has been established so far, what artifacts you can rely on, and where the open problems still are.

All vocabulary is aligned to the substrate (`substrate/Orientation.md`, `substrate/Concepts.md`, `substrate/State.md`): **Operation**, **Filter**, **PolicyGraph**, **Profile Layer**, **Sandbox Extension**, etc. The current host baseline for most artifacts is:

- macOS 14.4.1 (23E224), kernel 23.4.0
- Apple Silicon, SIP enabled

---

## 1. Big picture

- **Static profile format and vocab are in good shape.**
  - We have a shared decoder, system-profile digests, Operation/Filter vocab tables from the dyld cache, and per-tag node layouts for literal/regex-bearing nodes.
- **Graph-level structure is partially decoded.**
  - Node tags, op-table “buckets”, and the `field2` key are understood well enough to support experiments and mapping files, but not yet down to every Filter key and tail-layout detail.
- **Runtime behavior and lifecycle are only partially validated.**
  - SBPL microprofiles run via a local wrapper, but currently show mismatches between expected and observed allow/deny outcomes. Platform profile blobs are gated by `sandbox_apply` and `sandbox_init` on this host.
- **Concept inventory and validation harness exist, but semantic/lifecycle clusters remain provisional.**
  - Static-format and vocabulary clusters are wired to real artifacts; semantic and lifecycle clusters have scaffolding and some runs, but cannot yet be treated as strong evidence.
- **Kernel dispatcher reverse-engineering is in progress.**
  - Ghidra scripts and scans are in place; strong candidates for the PolicyGraph dispatcher have not yet been pinned down.

The rest of this document gives you a more detailed map: what each experiment proved, how the concept inventory and validation wiring look, and which tools and mappings you can safely treat as “reference”.

---

## 2. Experiments: what they have established

This section walks through the `book/experiments/` tree in logical clusters rather than alphabetically.

### 2.1 Static structure and vocabulary

- **`anchor-filter-map`**  
  Binds concrete anchor strings (paths, names) to Filter IDs, using outputs from `probe-op-structure`, `field2-filters`, system profiles, and the Filter vocab.
  - Final map: `book/graph/mappings/anchors/anchor_filter_map.json`.
  - High-confidence mappings:
    - `/tmp/foo`, `/etc/hosts` → `path` (filter id 0) for file probes.
    - `/var/log` → `ipc-posix-name` (4).
    - `idVendor` → `local-name` (6).
    - `preferences/logging` → `global-name` (5).
  - Ambiguous anchors are kept as such. Guardrail: `tests/test_mappings_guardrail.py` checks that at least one anchor has a resolved `filter_id`.

- **`system-profile-digest`**  
  Produces stable digests for curated system profile blobs (`airlock`, `bsd`, `sample`) using the shared decoder.
  - Output: `book/graph/mappings/system_profiles/digests.json` with host/build metadata, op-table entries, node/tag counts, literal counts, and section offsets.
  - Guardrail: `tests/test_mappings_guardrail.py` asserts presence and basic shape for `sys:airlock`, `sys:bsd`, `sys:sample`.

- **`tag-layout-decode`**  
  Reconstructs per-tag layouts for nodes that reference literal/regex pools.
  - Output: `book/graph/mappings/tag_layouts/tag_layouts.json` with entries like:
    - `record_size_bytes = 12`, `edge_fields = [0,1]`, `payload_fields = [2]` for tags `0,1,3,5,7,8,17,26,27,166`.
  - Decoder (`book.api.decoder`) uses these layouts to parse node arrays. Guardrail: tests assert presence and minimal fields.

- **`vocab-from-cache`**  
  Extracts Operation and Filter vocab tables (name ↔ ID) from the dyld shared cache (Sandbox.framework / libsandbox).
  - Outputs:
    - `book/graph/mappings/vocab/ops.json` — 196 operations.
    - `book/graph/mappings/vocab/filters.json` — 93 filters.
    - Name lists under `book/graph/mappings/vocab/{operation_names.json,filter_names.json}`.
  - These files are treated as `status: ok` in `book/graph/concepts/validation/out/vocab/*.json`; `check_vocab.py` enforces counts and status.

### 2.2 Operation pointer table and buckets

- **`op-table-operation`**  
  Uses synthetic SBPL profiles to understand how the Operation Pointer Table (op-table) behaves as Operations and Filters change.
  - Confirms a structured op-table over 196 Operation IDs (from vocab).
  - Observed patterns (per `book/graph/mappings/op_table/op_table_map.json` and `.../op_table_signatures.json`):
    - Unfiltered `file-read*`, `file-write*`, `network-outbound` cluster in buckets `{3,4}`.
    - Profiles that introduce `mach-lookup` use buckets `{5,6}`.
    - Non-uniform patterns like `[6,6,6,6,6,6,5]` arise when mach and filtered reads coexist; bucket 6 appears only in these mach+filtered-read mixtures.
  - Structural entry signatures (tags and `field2` histograms) support these bucket distinctions, but do not yet give a full Operation ID → bucket semantics map on their own.

- **`op-table-vocab-alignment`**  
  Bridges op-table buckets and the Operation Vocabulary Map, using the vocab artifacts above.
  - Alignment file: `book/graph/mappings/op_table/op_table_vocab_alignment.json`.
  - For each synthetic profile, records:
    - `ops` (SBPL operation names),
    - `operation_ids` (numeric IDs from `ops.json`),
    - `op_entries` (bucket values),
    - `filters` and `filter_ids` when applicable.
  - The alignment confirms, for this host:
    - `file-read*` (21), `file-write*` (29), `network-outbound` (112) use buckets in `{3,4}` across the probed profiles.
    - `mach-lookup` (96) uses buckets in `{5,6}`, with 6 only in complex profiles with filtered reads.

### 2.3 Node layout and `field2`

- **`node-layout`**  
  Explores the compiled PolicyGraph layout for modern profiles on this host.
  - Confirms the structural shape used throughout the repo:
    - 16-byte preamble.
    - Operation Pointer Table.
    - Node region (primarily 12-byte records at the “front”).
    - Literal/regex pool at the tail.
  - `field2` (the third 16-bit word in many node records) behaves like a compact “branch/filter key”:
    - Values `{3,4}` dominate unfiltered profiles.
    - Values `{5,0,6}` appear in profiles with Filters and `require-any` shapes.
    - Changing literal content leaves node bytes untouched; changing filters/metafilters changes nodes and `field2`.
  - Tail layout and exact tag semantics are still not fully decoded; this experiment documents hypotheses and open questions rather than final formats.

- **`field2-filters`**  
  Focuses specifically on mapping `field2` values to Filter IDs.
  - Output: `book/experiments/field2-filters/out/field2_inventory.json` combining:
    - Canonical system profiles (`airlock`, `bsd`, `sample`).
    - Synthetic single-filter probes.
  - Results:
    - System profiles support the idea that many low `field2` values match known filter IDs (`path`, `mount-relative-path`, `socket-type`, `global-name`, etc.).
    - Small synthetic probes are dominated by generic path/name scaffolding, so filter-specific `field2` signals are masked; no stable `field2` ↔ Filter ID map yet.
  - This experiment feeds into `anchor-filter-map` and `probe-op-structure`, but remains explicitly “partial”.

- **`probe-op-structure`**  
  Adds anchor-aware probes with richer SBPL shapes (files, mach names, network, iokit) and tries to bind anchors → nodes → `field2`.
  - Slicing/decoder improvements:
    - Segment-aware slicing for complex blobs.
    - Decoder emits `literal_strings_with_offsets` and per-node `literal_refs`.
  - Anchors:
    - For simple probes, anchors (e.g., `/tmp/foo`) now resolve to node indices and `field2` values.
    - Those nodes still carry generic `field2` keys (`global-name`, `local-name`, `path`-like values), so filter-specific mapping is not yet achieved.
  - Next steps recorded in `ResearchReport.md`: complete tag-aware node decode, then rerun anchor scans to get a more precise `field2` ↔ Filter mapping.

### 2.4 Runtime behavior (provisional)

- **`runtime-checks`**  
  Attempts to validate bucket-level expectations at runtime for selected profiles.
  - Targets:
    - Bucket-4 and bucket-5 synthetic profiles from `op-table-operation`.
    - System profiles (`airlock`, `bsd`, `sample`).
  - Harness:
    - Evolved from `sandbox-exec` to local shims (`sandbox_runner`, `sandbox_reader`), and now uses `book/api/SBPL-wrapper/wrapper` in `--sbpl` and `--blob` modes.
  - Current state:
    - For bucket profiles and system profiles, runs are heavily affected by `sandbox_init`/`sandbox_apply` returning `EPERM` on this host, especially for platform blobs in blob mode.
    - `out/expected_matrix.json` records the intended probe matrix; `out/runtime_results.json` captures what actually happened.
  - Interpretation:
    - This is not yet a reliable semantic evidence set; it is primarily a record of harness behavior and platform gating.

- **`sbpl-graph-runtime`**  
  Aims to produce “golden triples” (SBPL source, decoded graph, runtime outcomes) for canonical shapes.
  - Profiles: `allow_all`, `deny_all`, `deny_except_tmp`, `metafilter_any`, `param_path` (parameterized).
  - Decoding:
    - Compiled via libsandbox and decoded through `profile_ingestion.py`; headers and sections captured in `out/ingested.json`.
  - Runtime:
    - Runs via `book/api/SBPL-wrapper/wrapper --sbpl` and `book/api/file_probe/file_probe`.
    - `allow_all` behaves as expected.
    - Strict `(deny default)` shapes currently **do not** produce the expected denies: probes succeed where denies were expected.
  - Conclusion:
    - The triples exist structurally, but semantic behavior does not yet match expectations; these runs are not safe to treat as ground truth until profiles or harness are revised.

### 2.5 Entitlements and lifecycle

- **`entitlement-diff`**  
  Starts to connect entitlements to compiled profiles and behavior.
  - A small C sample (`entitlement_sample.c`) is built and signed in two variants:
    - One with `com.apple.security.network.server`.
    - One with an empty entitlement set.
  - Entitlements are extracted to `out/entitlement_sample.entitlements.plist` and `..._unsigned.entitlements.plist`.
  - Blocker:
    - The experiment still lacks a clean pipeline to derive App Sandbox SBPL for each variant and apply those profiles via the wrapper; no entitlement-driven runtime deltas are recorded yet.

Lifecycle/extension behavior is more fully tracked in the validation harness (see below), but this experiment is the main concrete starting point for entitlement-driven profile differences.

### 2.6 Kernel reverse engineering

- **`symbol-search`**  
  Uses Ghidra to hunt for the kernel-side PolicyGraph dispatcher and related helpers in `BootKernelExtensions.kc`.
  - Pivots:
    - String/import searches (AppleMatch, sandbox identifiers).
    - MACF `mac_policy_conf` / `mac_policy_ops` structures.
    - Profile-structure signatures based on decoded `.sb.bin` headers.
  - Current status:
    - Several candidate pointer tables and constant sites have been identified, but no function yet satisfies all the expected properties of the dispatcher (operation → node walks, AppleMatch calls, MACF hook linkage).
  - This work feeds future improvements to the static-format cluster and low-level understanding of PolicyGraph evaluation.

---

## 3. Concept inventory and validation state

The conceptual “truth” lives under `book/graph/concepts/`, with the substrate definitions as the ultimate reference. Validation harness code and evidence live under `book/graph/concepts/validation/`.

- **Concept inventory**  
  - `book/graph/concepts/CONCEPT_INVENTORY.md` enumerates concepts and groups them into four evidence clusters:
    - Static-Format.
    - Semantic Graph and Evaluation.
    - Vocabulary and Mapping.
    - Runtime Lifecycle and Extension.
  - `validation/Concept_map.md` repeats the substrate definitions and tags each concept with its clusters (e.g., `Operation` belongs to Semantic and Vocabulary clusters).

- **Validation harness** (`book/graph/concepts/validation/`)  
  - `README.md` describes the intended model: tasks per cluster, recording OS/build/SIP, using shared ingestion and probes rather than ad-hoc scripts.
  - `tasks.py` lists the validation tasks (which examples to run, which artifacts to expect) for each cluster.
  - `out/` contains:
    - `metadata.json` — host baseline and profile format variant (`modern-heuristic`).
    - `static/` — ingested `sample.sb`, system profiles, and mapping pointers.
    - `vocab/` — Operation/Filter vocab files (mirroring `book/graph/mappings/vocab/`) and a `runtime_usage.json` stub marked blocked.
    - `semantic/` — runtime results from wrappers and legacy sandbox-exec runs, all flagged as brittle/provisional in `index.json`.
    - `lifecycle/` — entitlement and extension probe notes (partial).
    - `index.json` — an index of all of the above, including cluster status and artifact paths.

- **Cluster status (summarized)**
  - Static-Format:
    - Largely validated for this host. Ingestion of `sample.sb` and system profiles works and is linked to mapping artifacts (op_table, tag_layouts, anchors).
  - Vocabulary and Mapping:
    - Operation/Filter vocab tables are harvested and aligned; runtime usage is still blocked (no trusted runtime IDs).
  - Semantic Graph and Evaluation:
    - Harness is present and runs exist, but evidence is not yet trusted:
      - SBPL microprofiles show mismatches between expected and actual behavior.
      - Bucket/system runtime-checks runs are dominated by apply failures.
  - Runtime Lifecycle and Extension:
    - Partial: entitlements-evolution probes exist; extension/container/platform-policy probes are either not rerun or blocked by the same apply gate.

---

## 4. Tooling and datasets you can rely on

From the perspective of an agent or human wanting to do further work, these are the core tools and mappings that are currently dependable on this host:

- **Decoder (`book.api.decoder`)**
  - Python module that decodes modern compiled profiles into a `DecodedProfile`:
    - Preamble words and header bytes.
    - `op_count` and `op_table` (using the shared Operation vocabulary length).
    - Node list with tags and fields, using tag layouts from `tag_layouts/tag_layouts.json`.
    - Literal pool bytes and printable `literal_strings`.
    - Section offsets and basic edge sanity checks.
  - CLI helper: `python -m book.api.decoder dump <blob>`.

- **SBPL wrapper (`book/api/SBPL-wrapper/wrapper`)**
  - Small C helper that applies SBPL or compiled blobs to a process:
    - `--sbpl <profile.sb> -- <cmd> ...` uses `sandbox_init`.
    - `--blob <profile.sb.bin> -- <cmd> ...` uses `sandbox_apply` via `libsandbox.1.dylib`.
  - Works reliably for non-platform SBPL profiles used in experiments.
  - On this host, applying platform blobs (e.g., `airlock`, `bsd`) in blob mode leads to `sandbox_apply: Operation not permitted`; these calls are recorded but not treated as successful evidence.

- **Ghidra connector (`book/api/ghidra`)**
  - Provides a `TaskRegistry` and `HeadlessConnector` for running Seatbelt-focused Ghidra scripts against kernel and userland artifacts under `dumps/`.
  - Enforces that:
    - Inputs come from `dumps/Sandbox-private/...`.
    - Outputs stay under `dumps/ghidra/out/` and `dumps/ghidra/projects/`.
    - `HOME`, `GHIDRA_USER_HOME`, and temp dirs are pinned inside `dumps/ghidra/` to stay inside the project’s sandbox.

- **File probe (`book/api/file_probe/file_probe`)**
  - Tiny helper used in runtime probes:
    - Supports `read`/`write` operations on paths.
    - Emits JSON lines with `op`, `path`, `rc`, and `errno`.
  - Used together with the SBPL wrapper in `sbpl-graph-runtime` and some validation runs.

- **Graph/mapping artifacts (`book/graph/mappings/`)**
  - Vocab:
    - `vocab/ops.json`, `vocab/filters.json`, and name lists (treated as canonical for Sonoma).
  - Op-table:
    - `op_table/op_table_map.json` and `op_table/op_table_signatures.json` (bucket values and structural signatures).
    - `op_table/op_table_vocab_alignment.json` (bucket ↔ Operation ID alignment per synthetic profile).
  - Tag layouts:
    - `tag_layouts/tag_layouts.json` (per-tag layouts for literal/regex-bearing nodes).
  - Anchors:
    - `anchors/anchor_filter_map.json` (anchor → Filter ID, with status and provenance).
  - System profiles:
    - `system_profiles/digests.json` (op-table, nodes, literals, sections for `sys:airlock`, `sys:bsd`, `sys:sample`).
  - Guardrails:
    - Tests in `tests/test_mappings_guardrail.py` and `tests/test_runtime_matrix_shape.py` ensure these files remain present and minimally well-formed.

---

## 5. Gaps and suggested next actions

The high-value open areas, if you are picking up this work, are:

- **Semantic validation of PolicyGraph behavior**
  - Problem:
    - Platform blobs (`airlock`, `bsd`) are gated by `sandbox_apply` / `sandbox_init` on this host.
    - SBPL microprofiles (`sbpl-graph-runtime`) currently disagree with their expected denies, even though they apply.
  - Next steps:
    - Run the same profiles on a more permissive host or under different credentials.
    - Simplify or adjust profiles and harness to isolate where expectations diverge from Seatbelt behavior.
    - Once stable, feed “golden triples” back into the concept inventory as semantic witnesses.

- **Completing `field2` and tag-aware node decoding**
  - Problem:
    - `field2` is clearly a key for filters/branches, but we do not yet have a direct `field2` ↔ Filter ID map.
    - Tail layout and some tags are still opaque.
  - Next steps:
    - Extend tag-aware node decoding using `tag_layouts` and system-profile anchors.
    - Rerun `probe-op-structure` and `field2-filters` to bind anchors → nodes → Filter IDs with confidence and guardrails.

- **Entitlement-driven profile derivation and probes**
  - Problem:
    - We know how to extract entitlement sets and have sample binaries, but do not yet have a pipeline from entitlements → App Sandbox SBPL → compiled profile → runtime probes.
  - Next steps:
    - Derive or synthesize App Sandbox SBPL per entitlement variant and exercise them via the SBPL wrapper.
    - Record how specific entitlements change Operations, Filters, and Decisions in compiled profiles and in runtime behavior.

- **Kernel dispatcher and low-level PolicyGraph evaluation**
  - Problem:
    - The in-kernel dispatcher that walks PolicyGraphs is not yet located on this host; AppleMatch interactions and MACF hook linkages are still hypotheses.
  - Next steps:
    - Continue the symbol-search work: mac_policy_ops pivot, improved ARM64 ADRP/ADD scanning, and profile-anchored signature searches for embedded graphs.
    - Once found, use it to cross-check assumptions about op-table indices, node semantics, and action modifiers.

These gaps are deliberate: the project’s design is to make missing pieces visible and local, not to pretend the model is already complete. The artifacts listed above give you a stable base from which to push the frontier.***
