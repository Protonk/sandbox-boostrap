# CONCEPT_INVENTORY.md

## Purpose

Make the core Seatbelt concepts explicit and enumerable. Provide one canonical “home” per concept to link, track, and validate: 
- Definitions
- Evidence
- Shared abstractions

## Win condition

Concretely, “success” means that each concept has:
1. **Witnesses**
- One or more *witnesses* where a witness is something concrete that constrains how the concept can be implemented or argued about: a parsed profile, a small SBPL snippet, a probe run, a log, etc.
2. **Explicit evidence types**
- We know which kinds of evidence are relevant:
  - Static structure (what we can see in compiled profiles or binaries).
  - Dynamic behavior (what happens when we run code under a sandbox).
  - Cross-references (how names and IDs line up across sources).
3. **Stable and tractable mappings**
- We can fix in a machine-readbale form:
  - How concepts map to example code.
  - How concepts map to shared abstractions.

## Concept Clusters by Evidence Type

To keep validation manageable, we group concepts by the kind of evidence that most naturally supports them. These *concept clusters* are not philosophical categories; they are “how can we actually see this?” categories.

### Static-Format Cluster

**Purpose**

These concepts are about how profiles look when compiled and stored: the concrete bytes and structures that the kernel and libraries consume, and the canonical binary IR that ingestion produces.

**Representative concepts**

- Binary Profile Header  
- Operation Pointer Table  
- Regex/Literal Table  
- Profile Format Variant

**Primary evidence**

- Captured compiled profiles (system profiles, small hand-compiled profiles, profiles emitted by tooling).
- Parsers that map blobs into typed structures.
- Structural invariants:
  - Offsets and sizes line up.
  - Operation tables and their indices are consistent.
  - String/regex tables are referenced correctly.

**Validation implications**

- A single “profile ingestion” spine can serve the entire static-format cluster:
  - Input: raw profile blobs.
  - Output: typed structures (a canonical PolicyGraph / node IR) plus a set of invariant checks.
- For each static-format concept, the concept inventory should point to:
  - The relevant parser or ingest module.
  - The invariants that are asserted.
  - The example profiles that are used as witnesses (e.g., specific system profiles, minimal synthetic profiles).
- All static-format evidence should record the profile format variant and OS/build it was taken from, so that later clusters can key vocab and behavior against the same versioned formats.

**Current experiment status**

- **Operation / Operation Pointer Table / Operation Vocabulary Map**
  - `book/experiments/node-layout/` and `book/experiments/op-table-operation/` slice modern compiled profiles into preamble/op-table/node/literal segments and probe how op-table “bucket” values (4/5/6) shift as SBPL operations and filters change.
  - Small synthetic profiles confirm a structured operation pointer table: profiles that mention `mach-lookup` move into a distinct bucket, and adding literals/filters to `file-read*` can move it toward the mach-style bucket, matching the substrate view of operations selecting different graph entry families.
  - Open questions remain around assigning concrete operation IDs to these buckets on this host and understanding non-uniform patterns such as `[6,…,5]` beyond relative behavior.
- **Field2 / node decoding / anchor probes**
  - `book/experiments/field2-filters/`, `node-layout/`, and `probe-op-structure/` have established a tag-aware decoder scaffold and produced anchor→node hints (e.g., `/tmp/foo` → nodes in `v1_file_require_any`), but literal/regex operand decoding and stable `field2`→filter-ID mapping are still incomplete.
  - Next steps are to finish tag-aware node decoding (per-tag variable-width layouts carrying literal/regex indices), rerun anchor scans to map anchors→nodes→filter IDs with guardrails for key anchors, and cross-check against strong anchors in system profiles.
- **Stable mapping artifacts**
  - Static witnesses for this host/build are published under `book/graph/mappings/`: system profile digests (`system_profiles/digests.json`), op-table buckets/signatures and vocab alignment (`op_table/*`), per-tag literal/regex layouts (`tag_layouts/tag_layouts.json`), and anchor→filter bindings (`anchors/anchor_filter_map.json`). These can be cited directly for Binary Profile Header, Operation Pointer Table, Profile Format Variant, PolicyGraph/Policy Node, and Filter evidence without rerunning probes.
  - `system_profiles/attestations.json` ties those static snapshots to tag-layout/vocab versions, anchor coverage, blob hashes, and runtime links (when available), giving a mechanically checkable bridge from compiled profile → literals/anchors → runtime expectations on this host.

---

### Semantic Graph and Evaluation Cluster

**Purpose**

These concepts describe how the sandbox decides what to allow or deny: operations, filters, decisions, and the structure of the policy graph.

**Representative concepts**

- Operation  
- Filter  
- Metafilter  
- Decision  
- Action Modifier  
- Policy Node  
- PolicyGraph

**Primary evidence**

- Small, focused profiles or profile fragments that encode particular semantic shapes:
  - Allow-all / deny-all.
  - “Deny except X.”
  - “Allow only if regex/path filter matches.”
- Probes that:
  - Run under those profiles.
  - Attempt a small, explicit set of operations (file opens, network calls, IPC, etc.).
  - Record which actions succeed or fail.

**Validation implications**

- We want a “microprofile + probe” pattern:
  - For each semantic scenario, there is a tiny profile and a tiny test program/script.
  - The probe logs the attempted operations and outcomes in a structured way (e.g., JSON).
- A single evaluation harness can run these microprofiles and collect evidence:
  - For each run, we know which operations were attempted, which filters were relevant, which decision node in the ingested PolicyGraph was reached, and how that path maps back to SBPL structure.
- For each semantic concept, the concept inventory should point to:
  - Which scenarios (profiles + probes) witness the behavior.
  - What invariants are being tested (e.g., “filters of type X must cause Y under condition Z”).
- When probe outcomes are used as semantic evidence, they should distinguish Seatbelt decisions from adjacent controls (TCC, SIP, hardened runtime) so we do not mis-attribute denials to the policy graph.

A single well-designed microprofile can often witness multiple concepts at once (operation, filter, decision, action modifier, policy node shape).

**Current experiment status**

- **Runtime-checks (golden triple)**
  - Wrapper-based probes for `allow_all`, `metafilter_any`, and bucket4 profiles succeed and are captured under `book/graph/mappings/runtime/{expectations.json,traces/*}` with `status: ok`. Bucket5 `v11_read_subpath` is `partial` (mismatch vs expected allow), and platform blobs are still skipped due to apply gates.
  - These runs are the primary semantic witnesses; each probe row carries vocab IDs and commands for reproducibility.
- **Legacy sandbox-exec traces**
  - Older logs in `book/graph/concepts/validation/out/semantic/*.jsonl` remain `brittle` (sandbox-exec harness) but can provide shape hints until replaced by wrapper-based runs.
- **Regeneration**
  - Use `book/experiments/runtime-checks/run_probes.py` or `book/api/golden_runner` to refresh `runtime_results.json`, then normalize into `book/graph/mappings/runtime/` for mapping-grade consumption.

---

### Vocabulary and Mapping Cluster

**Purpose**

These concepts are about naming and alignment: how symbolic names and argument shapes relate to on-disk IDs and observed behavior.

**Representative concepts**

- Operation Vocabulary Map  
- Filter Vocabulary Map

**Primary evidence**

- Enumerations of operations and filters from multiple sources:
  - Documentation (Apple Sandbox Guide, etc.).
  - Reverse-engineering sources.
  - Live system profiles (extracted operation/filter tables).
  - Runtime logs from probes (which operation IDs / names actually get used).
- Cross-checks between:
  - Our canonical vocab tables.
  - Tables extracted from compiled profiles.
  - The operation and filter names referred to by examples and probes.

**Validation implications**

- A “vocabulary survey” pipeline can consolidate and check vocab knowledge:
  - Gather all op/filter names and IDs from available sources.
  - Normalize them into canonical tables keyed by OS/build and, where applicable, profile format variant.
  - Mark each entry with status (known, deprecated, unknown, 14.x-only, etc.) and with provenance (which sources and artifacts support it).
- Example folders do not need to implement vocab logic themselves:
  - They should record which operations/filters they believe they are exercising (using canonical names).
  - A shared vocab-mapper can reconcile those names with IDs and on-disk representations.
- For each vocab-related concept, the concept inventory should point to:
  - The canonical vocab tables.
  - Any discrepancies or unknowns.
  - Tests or reports that compare different sources.
- Where possible, vocab entries should also point to microprofiles and probes that exercise a given operation or filter, tying names and IDs to concrete behavior.

This cluster ensures that when we say “operation X” or “filter Y,” we can trace that name from source snippets, to IDs in compiled profiles, to behavior observed at runtime.

**Current experiment status**

- **Vocabulary extraction (Operation/Filter)**
  - `book/experiments/vocab-from-cache/` harvests operation and filter vocab tables from the Sonoma dyld cache (Sandbox framework/libsandbox), yielding `ops.json` (196 entries) and `filters.json` (93 entries) with provenance and a guardrail script (`check_vocab.py`) to assert counts/status.
  - `book/experiments/op-table-vocab-alignment/` aligns op-table buckets from synthetic profiles with these vocab IDs, populating per-profile alignment artifacts with `operation_ids`, `filters`, and `filter_ids` and recording `vocab_status: ok`.
  - Recommended next steps: summarise which operation IDs appear in each observed bucket (4/5/6), thread filter IDs into bucket shifts observed in filtered profiles, keep vocab guardrails in CI, and feed stable findings back into the versioned vocab tables and concept docs.
- **Stable vocab artifacts**
  - Canonical vocab tables live under `book/graph/mappings/vocab/` (`ops.json`, `filters.json`, name lists) and are mirrored into `book/graph/concepts/validation/out/vocab/`. Op-table ↔ vocab alignment for this host is published at `book/graph/mappings/op_table/op_table_vocab_alignment.json` and listed in `validation/out/static/mappings.json` for reuse.
  - Runtime vocab usage remains `blocked` when `sandbox_init`/apply gates prevent observing live IDs; see `book/graph/mappings/runtime/expectations.json` for the current runtime coverage and `status` fields.
- **Link back to op-table experiments**
  - Once the vocab tables are in place for a given OS/build, the op-table buckets from the static-format experiments can be re-interpreted in terms of concrete operation IDs rather than opaque indices, tying the Operation, Operation Pointer Table, and Operation Vocabulary Map concepts together across SBPL, binary structure, and runtime behavior.

---

### Runtime Lifecycle and Extension Cluster

**Purpose**

These concepts concern when and how profiles apply over a process lifetime, how layers compose into an effective policy stack, and how extensions and adjacent controls modify effective policy.

**Representative concepts**

- Sandbox Extension  
- Policy Lifecycle Stage  
- Profile Layer (in the sense of system/global/app layering)  
- Policy Stack Evaluation Order  
- Compiled Profile Source  
- Container  
- Entitlement  
- Seatbelt label / credential state  
- Adjacent controls (TCC service, Hardened runtime, SIP) insofar as they intersect with sandbox outcomes

**Primary evidence**

- Scenario-style probes that:
  - Launch processes through different paths (launchd services, GUI app launch, sandbox-exec, etc.).
  - Observe system behavior at distinct lifecycle points (e.g., pre-init, post-init, after extensions are granted).
  - Track how access changes over time in response to extensions and profile changes.
  - Inspect which compiled profiles and extensions are attached to a process label at each stage, and which containers and adjacent controls are in play.

**Validation implications**

- These concepts likely require fewer, more complex examples:
  - Each scenario can witness multiple lifecycle concepts simultaneously.
- They can reuse:
  - The same static ingestion tools (to see what profiles/extensions exist).
  - The same operation/decision probes from the semantic cluster (but applied at different lifecycle stages).
- For each lifecycle concept, the concept inventory should point to:
  - Which scenarios illustrate the lifecycle transitions.
  - What kinds of extensions or profile layering are being exercised.
  - Which compiled profile sources, containers, entitlements, and adjacent controls were active for that scenario, with OS/build recorded so that behavior can be tied back to specific platform states.

This cluster is more “macro” than the others, but aligning it with shared ingestion and probe tooling keeps it from becoming a separate universe.

**Current experiment status**

- **Runtime expectations (golden triple)** — `book/graph/mappings/runtime/expectations.json` captures wrapper-based probes for selected profiles with `status` per profile/operation; bucket5 remains `partial`, platform blobs are still gated.
- **Lifecycle probes** — `entitlements-evolution` runs (unsigned baseline) and emits `validation/out/lifecycle/entitlements.json`; `extensions-dynamic` currently crashes/returns NULL tokens (see `extensions_dynamic.md`); platform/containers probes not rerun yet.
- **Apply gates** — `sandbox_init`/`sandbox_apply` still return `EPERM` for platform blobs on this host; treat apply failures as data points, not absence of policy.

## Process

The validation plan ties the examples in `book/examples/` to the four clusters. All harness code and task metadata live under `book/concepts/validation/` (see `validation/README.md` and `validation/tasks.py`). Each run should record OS/build and profile format variant so evidence stays versioned.

Current manifests to consult:
- `book/graph/concepts/validation/out/index.json` – cluster-level summary of produced evidence (static/semantic/vocab/lifecycle) for the Sonoma baseline.
- `book/graph/mappings/runtime/expectations.json` – runtime probe expectations/traces normalized for mapping use.
- `book/graph/mappings/runtime/lifecycle.json` – normalized lifecycle probe manifest (entitlements, extensions) with status per scenario.
- `book/graph/mappings/system_profiles/attestations.json` – compiled-profile attestations (blob hashes, tag layout/vocab versions, anchor hits, runtime links).
- `book/graph/mappings/vocab/attestations.json` – vocab attestation (counts, dyld source slices, hashes) for Operation/Filter vocab tables on this host/build.
- `book/graph/mappings/system_profiles/static_checks.json` – decoder-backed structural checks (op_count, section sizes, tag_layout hash) for canonical blobs.

**Stage 0 — Setup and metadata**
- Record host OS/build, hardware, SIP/TCC state, and profile format variant cues before collecting evidence.
- Use the shared ingestion spine (`book/concepts/validation/profile_ingestion.py`) for all blob parsing to keep IR consistent across clusters.

**Stage 1 — Static-Format validation**
- Run `sb/run-demo.sh`, `extract_sbs/run-demo.sh`, and `sbsnarf`/`apple-scheme` as needed to produce modern compiled blobs; ingest them to JSON under `validation/out/static/` with headers/op-table/node/regex/literal sections plus variant tags.
- For legacy blobs, use `sbdis` + `resnarf` to slice headers, op tables, and regex blobs; note the early decision-tree variant explicitly.
- Assert structural invariants (offsets/lengths, table indices) via ingestion; failures get logged alongside the artifact.

**Stage 2 — Semantic Graph and Evaluation**
- Prefer wrapper-based `runtime-checks` runs (golden triple) and normalize results into `book/graph/mappings/runtime/` for reuse. Legacy sandbox-exec probes (`metafilter-tests`, `sbpl-params`, `network-filters`, `mach-services`) remain available but are `brittle`.
- For each run, capture inputs (profile text/params), attempted operations, resolved paths/addresses, allow/deny outcomes, and map outcomes back to ingested PolicyGraph nodes where possible. Annotate TCC/SIP/platform interference explicitly.

**Stage 3 — Vocabulary and Mapping**
- From Stage 1 blobs, extract operation/filter vocab (name↔ID↔arg schema) into versioned tables under `graph/mappings/vocab/ops.json` and `.../filters.json`.
- From Stage 2 logs, collect observed operation/filter names and map them to IDs using the tables; flag unknown/mismatched entries. Store results in `graph/mappings/vocab/runtime_usage.json`.
- Each vocab entry should carry provenance (which blob/log) and OS/build/variant.

**Stage 4 — Runtime Lifecycle and Extension**
- Run scenario probes: `entitlements-evolution` (signed variants), `platform-policy-checks`, `containers-and-redirects`, `extensions-dynamic`, and `libsandcall` apply attempts. Expect apply gates (`EPERM`) on platform blobs.
- Capture entitlements/signing IDs, container roots and symlinks, extension issuance/consumption results, and apply failures with error codes. Log under `validation/out/lifecycle/` with OS/build and profile sources (platform/app/custom); promote stable results into `book/graph/mappings/runtime/` when they reach “golden” status.
- Correlate observed behavior with attached profiles/extensions (e.g., via ingestion or `system_profiles/attestations`) and note adjacent control involvement (TCC prompts, SIP denial).

**Stage 5 — Evidence index**
- Summarize produced artifacts per cluster in a machine-readable index (e.g., JSON manifest under `validation/out/index.json`) pointing to the static/semantic/vocab/lifecycle outputs and their provenance.
- Link concept entries to their witnesses by referencing this manifest, closing the loop from concepts → examples → evidence.

**Stage 6 — Prepare for handoff**
- Build a stateless summary of the content in `validation/` for an agent who will audit your work. They do not need explanation, context, or reasoning--they need a rich router to the code and linkages. Place this summary and routing alongside the example/cluster map (see `book/graph/concepts/EXAMPLES.md` and the “Inventory Summary” section there).

**Cross-cutting experiment hooks**
- `book/experiments/sbpl-graph-runtime/`: “golden” triples tying SBPL → decoded graph → runtime probes for canonical shapes. Graph leg exists (compiled + ingested); runtime leg now runs via `sandbox_runner`/`sandbox_reader` for simple shapes (including metafilter); system profile inclusion still pending.
- `book/experiments/entitlement-diff/`: signed variants with/without selected entitlements (e.g., `com.apple.security.network.server`) with extracted entitlements; profile extraction/runtime probes to be wired once an App Sandbox pipeline or permissive harness is available.


---

## Misconceptions

The point of building a concept inventory and a validation plan is straightforward: every important idea about the sandbox needs something concrete under it. For each “operation,” “filter,” “policy graph,” or “extension,” we want to be able to say what artifacts and behaviors show that we understand it correctly on current macOS. That is why we bothered to group concepts and sketch validation modes at all—static ingestion to see how profiles are really encoded; microprofiles and probes to see how decisions are really made; vocabulary surveys to see how names and IDs really line up; lifecycle scenarios to see when and how policies really apply.

Once we take that stance—“a concept is only as good as the evidence that constrains it”—a problem appears. We are not just challenged by ignorance; hallucinating something false about the sandbox can be more troublesome than admitting we do not know. A clean-looking test, table, or diagram built on the wrong mental model will happily “confirm” that model. If you quietly assume that the SBPL text you see is the whole policy, or that each syscall matches one operation, or that layers simply intersect as “most restrictive wins,” you can design validation that seems careful and still leads you away from how the system actually behaves.

The next examples walk through a small set of “fair” misconceptions—plausible, technically informed ways to be wrong about profiles, operations, filters, layers, and extensions—and show the kinds of errors they produce. Each one looks sensible in isolation, lines up with how other systems work, and can be reinforced by partial evidence—yet they will assuredly lead you astray.

### SBPL Profile

**Misconception**

“An SBPL profile is *the* policy for a process: if I read the profile text, I see the full effective sandbox.”

This treats the SBPL file (or snippet) as a self-contained, complete description of the sandbox, ignoring that:

* The effective policy can be a composition of multiple profiles (system base profile, app/container profile, service-specific overlays).
* Some behavior comes from implicit or generated rules (e.g., containerization, platform defaults), not explicitly written SBPL.

**Resulting error**

You might confidently claim:

> “If operation X is allowed in this SBPL, the process can always perform X.”

Then you design a probe that:

* Runs under a containerized app profile that is layered on top of the SBPL you’re looking at, or
* Picks a system service whose effective policy has extra hidden constraints.

Your probe reports “denied,” and you incorrectly attribute that denial to a failure in your understanding of the SBPL syntax, rather than to stacked profiles and implicit rules you never accounted for.

---

### Operation

**Misconception**

“Each syscall maps to exactly one sandbox ‘operation’, and those names are just thin labels over syscalls.”

This flattens the abstraction:

* Operations can be broader than a single syscall (e.g., multiple syscalls hitting the same operation).
* A single syscall can trigger multiple operations, or an operation can be consulted in contexts that don’t look like a single obvious syscall boundary.
* Operations sometimes correspond to higher-level notions (e.g., `file-read-data`, `mach-lookup`) rather than raw kernel entry points.

**Resulting error**

You assume:

> “If `open(2)` fails due to the sandbox, that means the `file-read-data` operation is denied.”

Then you:

* Design probes and documentation that equate “open denied” ⇔ “operation A denied,” and “open allowed” ⇔ “operation A allowed.”
* Use that equivalence to build a capabilities table.

Later you discover cases where:

* `open` fails for reasons tied to different operations (e.g., metadata-only access, path resolution, or a Mach-right precondition), or
* A different syscall hitting the same operation gives a different denial pattern.

Your whole mapping from “observed syscall outcomes” to “operation-level policy” ends up misleading, and you over- or under-estimate the scope of particular operations.

---

### Filter

**Misconception**

“Filters are simple ‘if-conditions’ that are checked once per rule; if the key/value matches, the rule fires, otherwise it’s ignored.”

This treats filters as a one-shot guard on a flat rule list, instead of:

* Nodes and edges in a graph where unmatched filters can route evaluation to other nodes.
* Something that can be evaluated in multiple stages, with default branches and combinations, not just “test and drop rule.”

**Resulting error**

You explain filters as:

> “Think of filters like `if (path == "/foo") then allow; else ignore this rule`.”

Then you:

* Try to “prove” that a certain dangerous path is unreachable because every rule with that path filter looks safely denying/allowing in isolation.
* Ignore how non-matching filters might send evaluation along a default edge that reaches a permissive decision for broader paths.

You miss an allow-path that emerges from graph structure (default edges, metafilters, fall-through) and state in your write-up:

> “Path /foo/bar is definitely denied in all cases,”

when in reality the graph structure allows it via a non-obvious route.

---

### Profile Layer / Policy Stack Evaluation Order

**Misconception**

“Multiple sandbox layers just combine as ‘most restrictive wins’ (a simple logical AND over allows/denies).”

This is an intuitive model, but:

* Real composition includes ordering, default paths, and sometimes explicit overrides.
* Some layers might introduce new operations/filters or default behavior that is not a pure subset of another.
* Extensions and dynamic changes can alter the stack in ways that do not look like a straightforward meet of policies.

**Resulting error**

You teach:

> “If any layer denies an operation, it’s denied overall; if all allow it, it’s allowed. Just think of layers as intersecting sets of permissions.”

Then you:

* Analyze a system profile + app profile + extension scenario under this AND model.
* Conclude that a certain sensitive operation is impossible because “layer B denies it.”

In practice, the effective evaluation order or an extension changes the decision path so that the deny in layer B is never reached (or is overridden). Your risk assessment or example explanation claims “this cannot happen,” when in fact it does under real evaluation order.

---

### Sandbox Extension

**Misconception**

“A sandbox extension is basically a ‘turn off sandbox here’ token; once you have one, the sandbox doesn’t really apply to that resource anymore.”

This conflates:

* Scoped, capability-like grants (often tied to a path or specific operation types) with a global disable.
* The idea that extensions can be time- or context-limited, or only affect certain operations, with a blanket exemption.

**Resulting error**

You describe extensions as:

> “If an app gets an extension for `/private/foo`, it can do anything there, sandbox be damned.”

On that basis you:

* Design probes that simply check “with extension present, can we read/write/delete everything under that path?” and treat any failure as “extension is broken” or “my understanding is wrong.”
* Overstate threat models in your teaching material (“leak one extension and the whole sandbox collapses”), ignoring narrower semantics.

You mischaracterize the scope of extensions (and thus both overestimate and misdescribe certain attacks), and you design validation that expects full removal of constraints, misinterpreting partial, correctly scoped behavior as surprising or inconsistent.

---

### Dangers

All of these misconceptions share a pattern: they compress a layered, data-structure-heavy, evaluation-order-sensitive system into something almost like a static ACL with a few predicates. That compression makes the sandbox seem easy to reason about and tempting to summarize with a few diagrams, tables, or one-off probes. That's a coherent but wrong model of the sandbox, and coherent wrong models are hard to dislodge.

If you believe “the SBPL I’m looking at is the whole story,” you will design both attacks and defenses around that single text artifact. For a defender, that can mean auditing one app’s profile and concluding an operation is safely denied, without realizing that a system base profile, a container profile, or a per-service override is also in play. For an attacker, it can mean over-focusing on clever SBPL tricks in one layer while ignoring a weaker, more permissive layer that is actually controlling the decision path. In both cases, you are not just missing details—you are steering your entire project around the wrong object.
