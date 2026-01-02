# SANDBOX_LORE

What follows is a report on a synthetic textbook built in collaboration between humans and software agents as a technical resource that has to be checkable, not just plausible. Instead of letting an automated system “explain” macOS security in the abstract, the project starts from a deliberately narrow, well-understood slice of reality—a single macOS configuration and a fixed set of source materials—and has agents propose structure, mappings, and examples that are only accepted when they can be tied back to concrete files, experiments, or decoded binaries. Over time, this loop of proposal and verification is meant to produce a textbook whose prose, diagrams, and code are all anchored in artifacts that a reader (or another tool) can regenerate and inspect, rather than in the internal associations of any one model.

What exists now is SANDBOX_LORE, a work-in-progress textbook that explains how modern macOS fences in programs—what they can touch on disk, which services they can talk to, and how the system decides “allow” or “deny” for each action—on one specific Sonoma-era Mac configuration. Underneath it sits a fixed technical picture of how this security machinery is supposed to work: a deliberately chosen snapshot of macOS’s sandbox rules, terminology, and moving parts on this one Sonoma-era Mac, which the project treats as the “world” the textbook is about. The project’s current focus is a “concept inventory”—a disciplined checklist that forces those ideas to line up with real binary files, tables, and observed behavior, so the book can’t drift off into self-consistent nonsense. When that inventory is complete, it becomes the wiring diagram between theory and evidence that lets the textbook’s chapters, examples, and code stay tightly coupled to what actually happens on the machine.

The “static” side of that story—file formats, operation and filter catalogs, how policy graphs are laid out in memory, and host-specific mapping tables—is already in good shape and backed by tests, so it can serve as a reliable atlas of what the sandbox looks like on this machine. The dynamic side—how those policies actually play out at runtime, how app permissions and entitlements feed into them, and how the kernel walks these graphs—is still mostly scaffolding and partial experiments, with some runs blocked by system protections and others not yet matching their expected allow/deny patterns. In practical terms, the project can speak with confidence about structure and vocabulary, but has to treat behavioral stories and end-to-end “from entitlement to decision” examples as hypotheses rather than settled fact. A major part of the remaining work is tightening those experiments until a small, well-understood set of runtime case studies can be promoted into the textbook as stable, repeatable examples.

# The big picture

In the narrowest sense, a finished SANDBOX_LORE would be the thing that Seatbelt has never really had: a single, inspectable, end-to-end account of how sandbox policy is represented and enforced on real machines, with every definition, diagram, and worked example pinned to artifacts you can regenerate. That has obvious value for anyone who has to reason about macOS security seriously—reverse-engineers, exploit mitigators, product security engineers, tool authors—because it replaces a mix of folklore, blog posts, and scattered RE notes with a coherent model you can actually test, diff, and extend.

Because it is plaintext and API-exposed, it is also a substrate for tools and agents, not just humans. A concept-aware DSL/API around the textbook lets you build debuggers, visualizers, and analysis assistants that ask questions like “show me the policy stack and effective file permissions for this process on host X” in terms of the book’s concepts, and get back answers that are guaranteed to be consistent with the written story. That gives you a safer way to use AI or automation in security work: the agent is forced to route its reasoning through a constrained, versioned model of the world rather than free-associating over the entire internet or its own weights.

A host-extension pipeline is where this becomes more than a one-off reference. If one can reliably add “Sonoma host Y” or “Sequoia host Z” by running a defined probe and mapping pipeline, you get a comparative atlas of Seatbelt across releases: which operations and filters appeared or vanished, how platform profiles changed, where kernel dispatch or lifecycle behavior shifted. That is valuable both for longitudinal security analysis (what actually hardened over time, what regressed) and for anyone building tools that need to support multiple macOS generations without guessing.

Finally, there is meta-value in the method. A finished, verifiable, agentically co-written textbook is a concrete demonstration that you can take a messy, underspecified system, pick a frozen slice of reality, and have humans plus models converge on a high-fidelity, reusable representation without giving up falsifiability. Even if someone never cares about Seatbelt itself, the pattern—substrate → concept inventory → experiments/mappings → narrative + API—becomes a template for building similar “synthetic textbooks” in other hard domains where you want AI to help but refuse to trade away grounding and testability.

# Agent readout

At the code and data level, the repo now holds a coherent first pass on the static story: how compiled profiles are laid out, which Operations and Filters exist on this host, how node tags and tag layouts work, and how all of that is tied back to concrete IDs, offsets, and literals. Those mappings—from substrate concepts to real bytes—are stable in shape and provenance and are guarded by tests, but they are not yet complete. In particular, coverage for the `field2` key and for anchors (human-meaningful paths and names) is still patchy and explicitly marked as such.

Graph-level structure and the concept inventory sit in an intermediate state between “sketch” and “finished chapter.” Experiments under `book/evidence/experiments/` establish the shape of the Operation Pointer Table, the layout of graph nodes and `field2`, and the anchors that bind paths and names to Filters. The concept inventory and validation harness then organize those results into four evidence clusters: Static-Format, Vocabulary/Mapping, Semantic Graph, and Runtime Lifecycle. The static-format and vocabulary clusters are backed by shared decoders, system-profile digests, and guarded mapping files and are treated as solid for this host. The semantic and lifecycle clusters are scaffolded—there are microprofiles, harnesses, and some runs—but are still labeled provisional, with their limitations recorded in the validation output.

The main uncertainties are about how the whole system behaves when it is actually running: the runtime allow/deny behavior, the way entitlements shape app sandbox policy over time, and the kernel’s internal dispatcher that walks the policy graph. SBPL microprofiles and the wrapper tooling can be applied, but on this host platform profile blobs are gated by `sandbox_init` / `sandbox_apply`, and several “deny-default” profiles do not yet produce the expected Decisions. Entitlement experiments can extract contrasting entitlement sets, but they stop short of a full entitlements → SBPL → compiled profile → runtime pipeline, and kernel reverse engineering has found promising structures without pinning down a definitive PolicyGraph dispatcher. The sections that follow walk through the experiments, the validation state, the supporting tools and datasets, and the next actions against that backdrop.

## Scope and method

This report was assembled through several passes by different agents over the same repo. An initial, code-oriented agent produced two status documents (`agent-readout.md` and `validation-status.md`) based on the experiment tree, mapping datasets, and validation harness. A second, chat-style agent then re-read the substrate and primary artifacts, wrote a cross-check (`agent-crosscheck.md`), and used it to correct inaccuracies and tighten the scope of the original reports.

The text here includes that cross-check loop and aims to stand on its own. Descriptions of experiments, mappings, and validation state are grounded in `book/evidence/experiments/*/Plan.md` and `ResearchReport.md`, in the mapping files under `book/evidence/graph/mappings/*`, and in the validation outputs under `book/evidence/graph/concepts/validation/out/*`, rather than inferred from code alone. Machine-generated drafts and human edits have been interleaved to make the prose smoother while keeping every status claim tied to an explicit artifact. All status statements are specific to the Sonoma baseline recorded in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world.json)` (macOS 14.4.1 / 23E224 on Apple Silicon with SIP enabled), and to the profile-format variant recorded in `book/evidence/graph/concepts/validation/out/metadata.json`.

The vocabulary throughout matches the substrate (`book/substrate/Orientation.md`, `book/substrate/Concepts.md`, `book/substrate/State.md`): terms like **Operation**, **Filter**, **PolicyGraph**, **Profile Layer**, and **Sandbox Extension** are used with those definitions. The host baseline for almost all artifacts is:

* macOS 14.4.1 (23E224), kernel 23.4.0
* Apple Silicon, SIP enabled

## The littler picture

At a high level, this repo is the scaffolding for a synthetic textbook about the macOS Seatbelt sandbox on one concrete machine. The substrate files fix the world the book is allowed to talk about; the experiments, mappings, and validation harnesses are the evidence the book is allowed to lean on. Right now, the “first pass” static story is in good shape and can support early chapters, while the runtime, lifecycle, and kernel stories are under active construction.

Roughly, the project is now at the stage where:

* The static profile format, vocabulary tables, and mapping datasets are stable enough to act as shared reference for this Sonoma host and are marked `status: ok` in the validation index.
* Graph-level structure (node tags, op-table buckets, `field2`, tag layouts) is decoded well enough to drive experiments and mappings, but not yet down to every Filter key and detail in the tail layout.
* Runtime behavior and lifecycle pipelines exist (SBPL microprofiles, wrappers, file probes), but expectation mismatches and `sandbox_init` / `sandbox_apply` gates mean they cannot yet be treated as strong semantic evidence.
* The concept inventory and validation harness are in place: static-format and vocabulary clusters are backed by real artifacts and marked `ok`, while the semantic and lifecycle clusters are still `blocked` or `partial` in the validation index.
* Kernel dispatcher reverse-engineering is underway in Ghidra; there are candidate structures and signatures, but the concrete PolicyGraph dispatcher has not yet been identified with enough confidence to be treated as fact.

The rest of this document fills in that outline: what each experiment actually established, how the concept inventory and validation wiring are structured, and which tools and mappings are treated as reference material going forward.

## Experiments

This section walks through the `book/evidence/experiments/` tree in clusters that make conceptual sense, rather than alphabetically.

### Static structure and vocabulary

This cluster answers the question “What does a modern compiled sandbox profile look like on disk, and how are its operations and filters wired in?” It anchors concepts such as **Binary Profile Header**, **Operation Pointer Table**, **Regex/Literal Table**, **PolicyGraph**, and the **Operation/Filter Vocabulary Maps** in real blobs and tables. The outputs here are the backbone for the Static-Format and Vocabulary/Mapping clusters in the concept inventory: later experiments and textbook chapters can assume that op-counts, table offsets, tag layouts, and vocabulary IDs are stable and correctly interpreted for this host.

* **`anchor-filter-map`**
  This experiment binds concrete anchor strings (paths, names) to Filter IDs by combining outputs from `probe-op-structure`, `field2-filters`, curated system profiles, and the Filter vocabulary.

  * Final map: `book/evidence/graph/mappings/anchors/anchor_filter_map.json`.
  * High-confidence examples include:

    * `/tmp/foo`, `/etc/hosts` → `path` (filter id 0) for file probes.
    * `/var/log` → `ipc-posix-name` (4).
    * `idVendor` → `local-name` (6).
    * `preferences/logging` → `global-name` (5).
  * Ambiguous anchors are deliberately kept ambiguous rather than forced. As a guardrail, `tests/test_mappings_guardrail.py` checks, among other things, that at least one anchor has a resolved `filter_id`.

* **`system-profile-digest`**
  This experiment produces stable digests for a small set of curated system profiles (`airlock`, `bsd`, `sample`) using the shared decoder.

  * Output: `book/evidence/graph/mappings/system_profiles/digests.json`, which records host/build metadata, op-table entries, node/tag counts, literal counts, and section offsets.
  * Guardrail: `tests/test_mappings_guardrail.py` asserts that entries for `sys:airlock`, `sys:bsd`, and `sys:sample` exist and have the expected basic shape.

* **`tag-layout-decode`**
  Here the focus is on reconstructing the per-tag layout for nodes that reference literal/regex pools.

  * Output: `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`, with entries such as:

    * `record_size_bytes = 12`, `edge_fields = [0,1]`, `payload_fields = [2]` for tags `0,1,3,5,7,8,17,26,27,166`.
  * The decoder (`book.api.profile_tools.decoder`) uses these tag layouts to parse node arrays correctly. Tests assert that the file is present and that key fields exist, acting as a guardrail against accidental format drift.

* **`vocab-from-cache`**
  This experiment extracts the Operation and Filter vocabulary tables (name ↔ ID) from the dyld shared cache (Sandbox.framework / libsandbox) for this host.

  * Outputs:

    * `book/evidence/graph/mappings/vocab/ops.json` — 196 operations.
    * `book/evidence/graph/mappings/vocab/filters.json` — 93 filters.
    * Name lists under `book/graph/mappings/vocab/{operation_names.json,filter_names.json}`.
  * These files are treated as canonical for this host and tagged `status: ok` under `book/evidence/graph/concepts/validation/out/vocab/*.json`. The `check_vocab.py` script enforces counts and status to catch accidental changes.

### Operation pointer table and buckets

This cluster explains how SBPL **Operations** connect to entry points in the compiled **PolicyGraph** through the **Operation Pointer Table**, and how those entry points line up with the **Operation Vocabulary Map**. It gives concrete evidence for concepts like Operation, Operation Pointer Table, and Operation Vocabulary Map in the concept inventory by showing that, on this host, specific operation IDs (for example, `file-read*` or `mach-lookup`) consistently land in certain op-table buckets, and that those buckets have distinct structural signatures.

* **`op-table-operation`**
  This experiment uses synthetic SBPL profiles to see how the op-table behaves as Operations and Filters are added or changed.

  * It confirms that there is a structured op-table spanning 196 Operation IDs (matching the vocabulary).
  * Observed patterns, as recorded in `book/evidence/graph/mappings/op_table/op_table_map.json` and `.../op_table_signatures.json`, include:

    * Unfiltered `file-read*`, `file-write*`, and `network-outbound` clustering in buckets `{3,4}`.
    * Profiles that introduce `mach-lookup` using buckets `{5,6}`.
    * Non-uniform sequences such as `[6,6,6,6,6,6,5]` when mach operations and filtered reads coexist; bucket 6 appears only in these mach+filtered-read mixtures.
  * Structural entry signatures (in terms of node tags and `field2` histograms for each bucket) reinforce the distinction between these buckets. However, the data does not yet support a full “Operation ID → bucket → semantics” mapping on its own.

* **`op-table-vocab-alignment`**
  This experiment explicitly links op-table buckets to the Operation Vocabulary Map using the vocabulary artifacts above.

  * Alignment file: `book/evidence/graph/mappings/op_table/op_table_vocab_alignment.json`.
  * For each synthetic profile it records:

    * `ops` (SBPL operation names),
    * `operation_ids` (numeric IDs from `ops.json`),
    * `op_entries` (bucket values),
    * `filters` and `filter_ids` where applicable.
  * The alignment confirms, for this host, that:

    * `file-read*` (21), `file-write*` (29), and `network-outbound` (112) use buckets in `{3,4}` across the probed profiles.
    * `mach-lookup` (96) uses buckets in `{5,6}`, with 6 only seen in the richer profiles that mix mach operations with filtered reads.

### Node layout and `field2`

This cluster looks closely at the shape of **PolicyGraph** nodes and the role of the `field2` key, tying together concepts like **Policy Node**, **Filter**, **Metafilter**, **Regex/Literal Table**, and (eventually) the **Filter Vocabulary Map**. It does not yet classify every node type, but it nails down important structural facts: where node arrays sit in the blob, how tags and small integer keys change when Filters and Metafilters change, and how literal/regex pools are referenced. All of this feeds into the Static-Format and Semantic Graph clusters in the concept inventory.

* **`node-layout`**
  This experiment explores the layout of the compiled PolicyGraph in modern profiles on this host.

  * It confirms the structural template used throughout the repo:

    * A 16-byte preamble.
    * The Operation Pointer Table.
    * A node region (mainly 12-byte records at the “front” of the blob).
    * A literal/regex pool at the tail.
  * The `field2` word (the third 16-bit field in many node records) behaves like a compact “branch/filter key”:

    * Values `{3,4}` dominate unfiltered profiles.
    * Values `{5,0,6}` appear in profiles that involve Filters and `require-any`-style constructs.
    * Changing the literal content leaves node bytes untouched, while changing filters or metafilters changes the nodes and their `field2` values.
  * The exact layout of the tail region and the full semantics of all tags are not yet decoded. The experiment records hypotheses and open questions rather than claiming a final format.

* **`field2-filters`**
  This experiment focuses specifically on relating `field2` values to Filter IDs.

  * Output: `book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json`, which aggregates:

    * Canonical system profiles (`airlock`, `bsd`, `sample`).
    * Synthetic single-filter probes.
  * Results:

    * The system profiles support the idea that many low `field2` values correspond to known Filter IDs (`path`, `mount-relative-path`, `socket-type`, `global-name`, etc.).
    * In small synthetic probes, generic path/name scaffolding dominates, so filter-specific `field2` signals are largely masked; there is not yet a stable, one-to-one `field2` ↔ Filter ID map.
  * This experiment feeds into `anchor-filter-map` and `probe-op-structure`, but is explicitly tagged as “partial” pending deeper decoding.

* **`probe-op-structure`**
  This experiment adds richer, anchor-aware probes with SBPL shapes that cover files, mach names, network, and IOKit, and tries to link anchors → nodes → `field2`.

  * It introduces slicing and decoder improvements:

    * Segment-aware slicing for more complex blobs.
    * Decoder output that includes `literal_strings_with_offsets` and per-node `literal_refs`.
  * For simple probes, anchors such as `/tmp/foo` can now be traced to specific node indices and `field2` values.
  * Those nodes, however, still carry fairly generic `field2` keys (`global-name`, `local-name`, `path`-like values), so a clean, filter-specific mapping is not yet achieved.
  * The recorded next steps in `ResearchReport.md` are to complete tag-aware node decoding and then rerun the anchor scans to push towards a precise `field2` ↔ Filter mapping.

### Runtime behavior

This cluster attempts to connect SBPL and compiled **PolicyGraphs** to actual runtime **Decisions** (allow or deny) for specific **Operations** and **Filters**, exercising concepts such as Decision, Metafilter, Action Modifier, and Profile Layer in the Semantic Graph and Runtime Lifecycle clusters. On this host, the evidence is still tentative: profile-apply gates and mismatches between expected and observed behavior mean these runs cannot yet be treated as definitive. Still, the harnesses and microprofiles built here are the starting point for future, trusted semantic witnesses.

* **`runtime-checks`**
  This experiment tries to validate bucket-level expectations at runtime for selected profiles.

  * Targets:

    * Bucket-4 and bucket-5 synthetic profiles from `op-table-operation`.
    * System profiles (`airlock`, `bsd`, `sample`).
  * Harness:

    * The machinery evolved from using `sandbox-exec` to local shims (`sandbox_runner`, `sandbox_reader`), and now centers on `book/tools/sbpl/wrapper/wrapper` in both `--sbpl` and `--blob` modes.
  * Current state:

    * For both bucket profiles and system profiles, runs are strongly affected by `sandbox_init` / `sandbox_apply` returning `EPERM` on this host, especially when attempting to apply platform blobs in blob mode.
    * `out/expected_matrix.json` records the intended probe matrix; `out/runtime_results.json` records what actually happened.
  * Interpretation:

    * At present this is mainly a record of harness behavior and platform gating, not a clean semantic dataset. It is kept as scaffolding rather than used as core evidence.

* **`sbpl-graph-runtime`**
  This experiment aims to build “golden triples” of SBPL source, decoded graph, and runtime outcomes for a small set of canonical profile shapes.

  * Profiles include: `allow_all`, `deny_all`, `deny_except_tmp`, `metafilter_any`, and `param_path` (a parameterized profile).
  * Decoding:

    * Profiles are compiled via libsandbox and decoded through `profile_ingestion.py`; headers and sections are stored in `out/ingested.json`.
  * Runtime:

    * Probes are run via `book/tools/sbpl/wrapper/wrapper --sbpl` and `book/api/file_probe/file_probe`.
    * The `allow_all` profile behaves as expected.
    * Strict `(deny default)` shapes currently do **not** behave as expected: probes that should be denied are instead succeeding.
  * Conclusion:

    * The structural part of the triples exists, but the runtime behavior does not yet line up with expectations. These runs are therefore not yet safe to treat as ground truth until either the profiles or the harness (or both) are revised.

### Entitlements and lifecycle

This cluster is the beginning of the Runtime Lifecycle and Extension story. It focuses on **Entitlements**, **Profile Layers**, and **Policy Lifecycle Stage**, rather than raw graph structure. By comparing binaries signed with different entitlements, it sets up the future pipeline that will show how app metadata feeds into App Sandbox SBPL templates, compiled profiles, and effective policy—tying entitlement-driven behavior back into the lifecycle concepts in the inventory.

* **`entitlement-diff`**
  This experiment starts to connect entitlements to compiled profiles and runtime behavior.

  * A small C sample (`entitlement_sample.c`) is compiled and signed in two variants:

    * One with the entitlement `com.apple.security.network.server`.
    * One with an empty entitlement set.
  * The resulting entitlements are extracted to:

    * `out/entitlement_sample.entitlements.plist`
    * `out/entitlement_sample_unsigned.entitlements.plist` (name abbreviated here for clarity; exact path in repo).
  * Blocker:

    * The experiment does not yet have a clean pipeline to derive the corresponding App Sandbox SBPL for each variant and apply those profiles through the wrapper. As a result, there are no recorded entitlement-driven runtime differences yet.
  * Lifecycle and extension behavior is tracked in more detail in the validation harness, but this experiment is the main concrete starting point for entitlement-based profile differences.

### Kernel reverse engineering

This cluster looks under the hood of the profile format into the kernel’s implementation of **PolicyGraph evaluation**, searching for the dispatcher that walks nodes and calls into AppleMatch, and for the MACF hooks that connect syscalls to Operation IDs. Once complete, it should provide low-level witnesses for concepts like Operation, PolicyGraph, Decision, and Policy Stack Evaluation Order, tying the Static-Format and Semantic Graph clusters back to real kernel code on this host.

* **`symbol-search`**
  This experiment uses Ghidra to hunt for the kernel-side PolicyGraph dispatcher and related helpers in `BootKernelExtensions.kc`.

  * It pivots on:

    * String and import searches (AppleMatch, sandbox-related identifiers).
    * MACF `mac_policy_conf` and `mac_policy_ops` structures.
    * Structural signatures derived from decoded `.sb.bin` headers and other profile artifacts.
  * Current status:

    * Several candidate pointer tables and constant sites have been found, but no function has yet been shown to satisfy all the expected properties of the dispatcher (mapping operations to node walks, calling AppleMatch in the right places, and tying into MACF hooks).
  * This work is feeding future improvements to the static-format understanding and to the low-level model of PolicyGraph evaluation.

---

## Concept inventory and validation state

The concept inventory is the part of the project that tries to turn “Seatbelt knowledge” from a fuzzy mental model into a set of named, testable ideas. For each concept (Operation, Filter, PolicyGraph, Profile Layer, Sandbox Extension, and so on) it aims to fix a canonical definition, list concrete “witnesses” (profiles, probes, logs, mapping entries), and spell out which kinds of evidence constrain it: static structure, runtime behavior, vocabulary alignment, or lifecycle scenarios. Concepts are grouped into four clusters—Static-Format, Semantic Graph and Evaluation, Vocabulary and Mapping, and Runtime Lifecycle and Extension—so that validation work can be structured around what can actually be observed.

As recorded in `validation/out/index.json`, the Static-Format and Vocabulary/Mapping clusters are `ok` for this host: there is a working decoder, system-profile digests, op-table and tag-layout mappings, and host-specific Operation/Filter vocab tables tied back to the dyld cache. The Semantic Graph cluster is `blocked`, and the Runtime Lifecycle and Extension cluster is `partial`. Microprofiles and runtime harnesses exist, and some runs have been recorded, but apply gates and expectation mismatches mean that runtime evidence cannot yet be used as firm support for concepts like Decision, Metafilter, or Policy Stack Evaluation Order. Within the `blocked` and `partial` clusters, individual artifacts are also labeled “brittle” where they depend on legacy `sandbox-exec` behavior.

The conceptual “truth” lives under `book/graph/concepts/`, with the substrate definitions as the ultimate reference. The validation harness code and its evidence live under `book/graph/concepts/validation/`.

### Contents

* **Concept inventory**

  * `book/evidence/graph/concepts/CONCEPT_INVENTORY.md` lists the concepts and assigns each to one or more of the four evidence clusters:

    * Static-Format
    * Semantic Graph and Evaluation
    * Vocabulary and Mapping
    * Runtime Lifecycle and Extension
  * `validation/Concept_map.md` restates the substrate definitions and tags each concept with its cluster memberships (for example, `Operation` belongs to both the Semantic and Vocabulary clusters).

* **Validation harness** (`book/graph/concepts/validation/`)

  * `README.md` lays out the intended model: validation tasks per cluster, recording OS/build/SIP state, and using shared ingestion and probe tooling rather than ad-hoc scripts.
  * `tasks.py` enumerates the validation tasks: which examples to run and which artifacts to expect for each cluster.
  * `out/` contains:

    * `metadata.json` — the host baseline and the profile format variant (`modern-heuristic`).
    * `static/` — ingested `sample.sb`, system profiles, and mapping pointers, all marked `status: ok` in the index.
    * `vocab/` — Operation/Filter vocabulary files (mirroring `book/graph/mappings/vocab/`) and a `runtime_usage.json` stub marked `status: blocked`.
    * `semantic/` — runtime results from the wrappers and from legacy `sandbox-exec` runs; the semantic-graph cluster is `status: blocked`, with notes on each artifact (apply failures, “legacy sandbox-exec (brittle)”, etc.).
    * `lifecycle/` — notes from entitlement and extension probes; the lifecycle/extension cluster is `status: partial`.
    * `index.json` — an index tying all of the above together, including cluster status and artifact paths.

* **Cluster status (summarized)**

  * Static-Format:

    * `status: ok` for this host. Ingestion of `sample.sb` and system profiles works and is linked to mapping artifacts (op_table, tag_layouts, anchors).
  * Vocabulary and Mapping:

    * Vocabulary tables are harvested and aligned (`status: ok`); runtime usage is still `status: blocked` because there are no trusted runtime Operation IDs.
  * Semantic Graph and Evaluation:

    * Cluster is `status: blocked`. The harness exists and runs have been executed, but the evidence is not yet trusted:

      * SBPL microprofiles show mismatches between expected and actual behavior.
      * Runtime-check runs for bucket and system profiles are dominated by apply failures.
  * Runtime Lifecycle and Extension:

    * Cluster is `status: partial`. There are probes for entitlements and extension/container/platform-policy behavior, but many have either not been rerun in the current harness or are blocked by the same apply gate issues.

---

## Tooling and datasets

### Tooling

This section summarizes the core tools under `book/api/` that decode profiles, apply SBPL and blobs at runtime, drive Ghidra, and run simple probes. These tools support both the experiments and the validation harness and are the main mechanisms for regenerating or extending the evidence recorded in the repo.

* **Decoder (`book.api.profile_tools.decoder`)**

  * A Python module that decodes modern compiled profiles into a `DecodedProfile` structure, including:

    * Preamble words and raw header bytes.
    * `op_count` and the `op_table` (using the shared Operation vocabulary length).
    * A node list with tags and fields, using tag layouts from `tag_layouts/tag_layouts.json`.
    * Literal-pool bytes and printable `literal_strings`.
    * Section offsets and basic edge sanity checks.
  * CLI helper: `python -m book.api.profile_tools decode dump <blob>` to inspect profiles from the command line.

* **SBPL wrapper (`book/tools/sbpl/wrapper/wrapper`)**

  * A small C helper that applies SBPL or compiled blobs to a process:

    * `--sbpl <profile.sb> -- <cmd> ...` uses `sandbox_init`.
    * `--blob <profile.sb.bin> -- <cmd> ...` uses `sandbox_apply` via `libsandbox.1.dylib`.
  * It works reliably for the non-platform SBPL profiles used in experiments.
  * On this host, attempting to apply platform blobs (such as `airlock` or `bsd`) in blob mode yields `sandbox_apply: Operation not permitted`. Those calls are recorded but are not treated as successful evidence.

* **Ghidra connector (`book/api/ghidra`)**

  * Provides a `TaskRegistry` and `HeadlessConnector` for running Seatbelt-focused Ghidra scripts against kernel and userland artifacts stored under `book/dumps/`.
  * It enforces basic hygiene:

    * Inputs are taken from `book/dumps/ghidra/private/aapl-restricted/...`.
    * Outputs are written under `book/evidence/dumps/ghidra/out/` and `book/dumps/ghidra/projects/`.
    * `HOME`, `GHIDRA_USER_HOME`, and temporary directories are pointed inside `book/dumps/ghidra/` to keep Ghidra’s side effects inside the project’s own sandbox.

* **File probe (`book/api/file_probe/file_probe`)**

  * A small helper used in runtime probes:

    * Supports simple `read` / `write` operations on filesystem paths.
    * Emits JSON lines with `op`, `path`, `rc`, and `errno`.
  * It is used together with the SBPL wrapper in `sbpl-graph-runtime` and in some validation runs to record concrete allow/deny outcomes.

### Mapping datasets

This section covers the host-specific mapping datasets under `book/graph/mappings/`. Taken together, they act as a knowledge base for this Sonoma build, capturing the Operation and Filter vocabularies, op-table bucket behavior, tag layouts, anchor bindings, and system-profile digests. The files are stable in shape and provenance and guarded by tests, but are not yet exhaustive: some relationships—especially between `field2` and specific Filter IDs, and in overall anchor coverage—remain partial and are documented that way in the experiments.

* **Graph/mapping artifacts (`book/graph/mappings/`)**

  * Vocab:

    * `vocab/ops.json`, `vocab/filters.json`, and their corresponding name lists, treated as canonical vocabulary tables for this Sonoma host.
  * Op-table:

    * `op_table/op_table_map.json` and `op_table/op_table_signatures.json` record op-table bucket values and their structural signatures.
    * `op_table/op_table_vocab_alignment.json` connects buckets to Operation IDs for each synthetic profile.
  * Tag layouts:

    * `tag_layouts/tag_layouts.json` captures per-tag layouts for nodes that reference literal/regex pools.
  * Anchors:

    * `anchors/anchor_filter_map.json` maps anchors to Filter IDs and records the status and provenance of each mapping.
  * System profiles:

    * `system_profiles/digests.json` records op-table entries, node counts, literal counts, and section offsets for curated system blobs (`sys:airlock`, `sys:bsd`, `sys:sample`).
  * Guardrails:

    * Tests in `tests/test_mappings_guardrail.py` and `tests/test_runtime_matrix_shape.py` ensure that these files remain present and minimally well-formed and that the expected shapes of runtime matrices do not drift silently.

## Gaps and suggested next actions

From the point of view of the eventual book, the most important next steps are the ones that turn today’s strong static story into trustworthy dynamic evidence. The Static-Format and Vocabulary/Mapping clusters already give a stable language for talking about compiled profiles, Operations, Filters, and PolicyGraphs on this host. What is missing is a small set of “golden” runtime examples and lifecycle case studies that can be cited in chapters without hand-waving. That, in turn, suggests prioritizing work that either repairs the existing runtime harnesses or moves them to a friendlier environment where they can produce reliable Decisions for a carefully chosen set of profiles.

A second priority is to complete the bridge from high-level metadata to effective policy. The entitlement experiments and the lifecycle cluster outline how a binary’s entitlements ought to feed into App Sandbox profiles and, eventually, into profile layers and extensions in the running system. They do not yet form a full end-to-end pipeline. Wiring up “entitlements → SBPL → compiled PolicyGraph → observed runtime Decisions” for even one or two realistic cases would provide a concrete chapter’s worth of narrative about Profile Layers, Sandbox Extensions, and Runtime Lifecycle, grounded in the same artifacts the inventory already tracks.

Finally, there is a structural frontier that supports both of those stories: finishing `field2` / tag-aware decoding and locating the kernel dispatcher. A sharper map from `field2` to Filters and a richer understanding of tag layouts would clean up remaining ambiguities in how Filters and branches are encoded. The kernel work would then provide low-level witnesses for PolicyGraph evaluation and operation dispatch. Those are longer-horizon tasks, but even partial progress—stronger `field2` guardrails and a few well-understood dispatcher candidates—would tighten the feedback loop between the substrate, the concept inventory, and the experiments.

High-value open areas are:

### Semantic validation of PolicyGraph behavior

* Problem:

  * Platform blobs (`airlock`, `bsd`) are gated by `sandbox_apply` / `sandbox_init` on this host.
  * SBPL microprofiles in `sbpl-graph-runtime` currently disagree with their expected denies, even though they can be applied.
* Next steps:

  * Run the same profiles on a more permissive host or under different credentials.
  * Simplify or adjust profiles and the harness to isolate where expectations diverge from actual Seatbelt behavior.
  * Once stable runs exist, feed the resulting “golden triples” back into the concept inventory as semantic witnesses.

### Completing `field2` and tag-aware node decoding

* Problem:

  * `field2` is clearly a key for filters and branches, but there is not yet a direct, reliable `field2` ↔ Filter ID map.
  * The tail layout and some tags remain opaque.
* Next steps:

  * Extend tag-aware node decoding using the `tag_layouts` mappings and anchors from system profiles.
  * Rerun `probe-op-structure` and `field2-filters` to bind anchors → nodes → Filter IDs with enough confidence to install guardrails and promote these mappings into the textbook.

### Entitlement-driven profile derivation and probes

* Problem:

  * Entitlement sets can be extracted and sample binaries exist, but there is not yet a pipeline from entitlements → App Sandbox SBPL → compiled profile → runtime probes.
* Next steps:

  * Derive or synthesize App Sandbox SBPL for each entitlement variant and exercise them via the SBPL wrapper.
  * Record how specific entitlements change the set of Operations, Filters, and Decisions in both the compiled profiles and their observed runtime behavior.

### Kernel dispatcher and low-level PolicyGraph evaluation

* Problem:

  * The in-kernel dispatcher that walks PolicyGraphs has not yet been located on this host; the exact AppleMatch interactions and MACF hook linkages are still hypotheses.
* Next steps:

  * Continue the symbol-search work: pivot on `mac_policy_ops`, refine ARM64 ADRP/ADD scanning, and use profile-derived signatures to search for embedded graph structures.
  * Once a convincing dispatcher candidate is found, use it to cross-check assumptions about op-table indices, node semantics, and action modifiers, and to ground the semantic story in concrete kernel code.
