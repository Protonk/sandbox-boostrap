# CONCEPT_INVENTORY.md

## Purpose

Make the core Seatbelt concepts explicit and enumerable. Provide one canonical “home” per concept to link, track, and validate:
- Definitions
- Evidence
- Shared abstractions

The inventory is a *spec for validation*, not a replacement for the substrate docs, mapping JSONs, or CARTON. Every important concept should have:
- A definition in substrate vocabulary.
- One or more concrete witnesses on this host.
- A clear path from concept → example → artifact → mapping.

## Win condition

Concretely, “success” means that each concept has:

1. **Witnesses**  
   One or more *witnesses* where a witness is something concrete that constrains how the concept can be implemented or argued about: a parsed profile, a small SBPL snippet, a probe run, a log, etc.

2. **Explicit evidence types**  
   We know which kinds of evidence are relevant:
   - Static structure (what we can see in compiled profiles or binaries).
   - Dynamic behavior (what happens when we run code under a sandbox).
   - Cross-references (how names and IDs line up across sources).

3. **Stable and tractable mappings**  
  We can fix in a machine-readable form:
  - How concepts map to example code.
  - How concepts map to shared abstractions and mapping JSONs, and (when frozen) how they surface in CARTON as part of the host’s canonical IR web.

## How to read this file

- Use the **cluster overview** to see which evidence clusters are strong vs partial vs blocked.
- For a given cluster, read its section to understand:
  - Which concepts it covers.
  - What evidence “looks like”.
  - Which manifests already witness those concepts.
  - Where the gaps are.
- Use the **Evidence manifests** section as the router into `book/graph/mappings/` and `book/graph/concepts/validation/out/`.
- Use **Validation workflow** and **Guidance for new validation paths** when you want to add new evidence or extend the inventory.
- Treat the **Appendix on misconceptions** as conceptual hygiene: it describes ways to be wrong, not new evidence or instructions.

---

## Concept clusters at a glance

We group concepts by the kind of evidence that most naturally supports them. These *concept clusters* are “how can we actually see this?” categories for this host.

- **Static-Format cluster** (status: strong)  
  - Concepts: Binary Profile Header, Operation Pointer Table, Regex/Literal Table, Profile Format Variant, PolicyGraph/Policy Node.  
  - Evidence: compiled profile blobs, decoder output, op-table experiments, tag layouts, anchors, system profile digests/attestations/static checks.  
  - Manifests: `mappings/system_profiles/{digests,attestations,static_checks}.json`, `mappings/op_table/*`, `mappings/tag_layouts/tag_layouts.json`, `mappings/anchors/anchor_filter_map.json`, `validation/out/static/*`.

- **Semantic Graph and Evaluation cluster** (status: partial)  
  - Concepts: Operation, Filter, Metafilter, Decision, Action Modifier, Policy Node, PolicyGraph.  
  - Evidence: golden-triple runtime expectations/traces, legacy sandbox-exec logs (brittle), decoded graphs.  
  - Manifests: `mappings/runtime/expectations.json`, `mappings/runtime/traces/*`, `validation/out/semantic/*`.

- **Vocabulary and Mapping cluster** (status: strong static, partial runtime)  
  - Concepts: Operation Vocabulary Map, Filter Vocabulary Map.  
  - Evidence: dyld-derived vocab tables, op-table/vocab alignment, static mappings; runtime vocab usage where apply gates allow.  
  - Manifests: `mappings/vocab/{ops.json,filters.json,attestations.json}`, `mappings/op_table/op_table_vocab_alignment.json`, `validation/out/vocab/*`.

- **Runtime Lifecycle and Extension cluster** (status: partial/blocked)  
  - Concepts: Sandbox Extension, Policy Lifecycle Stage, Profile Layer, Policy Stack Evaluation Order, Compiled Profile Source, Container, Entitlement, Seatbelt label/credential state, adjacent controls.  
  - Evidence: golden-triple runtime expectations, lifecycle traces (entitlements/extension attempts), apply failures on platform blobs.  
  - Manifests: `mappings/runtime/{expectations.json,lifecycle.json}`, `mappings/runtime/{traces,lifecycle_traces}/*`, `system_profiles/attestations.json`, `validation/out/lifecycle/*`.

---

## Static-Format cluster

### Concepts in scope

- Binary Profile Header  
- Operation Pointer Table  
- Regex/Literal Table  
- Policy Node / PolicyGraph  
- Profile Format Variant

### Evidence shape

These concepts are about how profiles look when compiled and stored: the concrete bytes and structures that the kernel and libraries consume, and the canonical binary IR that ingestion produces.

Primary evidence:
- Captured compiled profiles (system profiles, small hand-compiled profiles, profiles emitted by tooling).
- Parsers that map blobs into typed structures (headers, op-tables, node arrays, literal/regex pools).
- Structural invariants such as:
  - Offsets and sizes line up.
  - Op-table entries and operation counts are consistent.
  - String/regex tables are referenced correctly.

A single “profile ingestion” spine (decoder + tag layouts) serves this cluster: input is a blob, output is a typed PolicyGraph-like IR plus invariants.

### Current evidence & manifests

- **System profile digests and attestation**
  - `book/graph/mappings/system_profiles/digests.json` – per-profile digests (op-table buckets, tag mixes, literal samples) for canonical system blobs (`airlock`, `bsd`, `sample`).
  - `book/graph/mappings/system_profiles/attestations.json` – cross-linked attestations (blob hashes, op-table entries, tag counts, literal strings/anchor hits, tag-layout/vocab versions, runtime links where available).
  - `book/graph/mappings/system_profiles/static_checks.json` – decoder-backed invariants (header op_count, section sizes, tag_counts, tag_layout hash) for the same canonical blobs.

- **Op-table and node layout**
  - `book/graph/mappings/op_table/{op_table_map.json,op_table_signatures.json,op_table_operation_summary.json,op_table_vocab_alignment.json}` – op-table bucket maps, structural signatures, and vocab alignment for synthetic profiles.
  - `book/graph/mappings/tag_layouts/tag_layouts.json` – per-tag node layouts for tags that carry literal/regex operands; used by the decoder.

- **Anchors and field2**
  - `book/graph/mappings/anchors/{anchor_field2_map.json,anchor_filter_map.json}` – anchor-derived mappings tying human-meaningful strings (paths, mach names, etc.) to field2 values and Filter IDs.

- **Static ingestion outputs**
  - `book/graph/concepts/validation/out/static/*` – JSON summaries of modern and legacy blobs produced by ingestion tools (`profile_ingestion.py`, `decode_blob.py`).

Together, these artifacts ground Binary Profile Header, Operation Pointer Table, Profile Format Variant, PolicyGraph/Policy Node, and Filter at the structural level for this host.

### Gaps and open questions

- Field2→Filter-ID mapping is still partial for some tags and anchors; additional tag-aware decoding and anchor scans are needed for full coverage.
- Some profile format variants and legacy decision-tree layouts are supported only heuristically; they are good enough for structural orientation but not for full SBPL reconstruction.

---

## Semantic Graph and Evaluation cluster

### Concepts in scope

- Operation  
- Filter  
- Metafilter  
- Decision  
- Action Modifier  
- Policy Node  
- PolicyGraph

### Evidence shape

These concepts describe how the sandbox decides what to allow or deny: operations, filters, decisions, and the structure of the policy graph.

Primary evidence:
- Small, focused profiles or profile fragments encoding particular semantic shapes:
  - Allow-all / deny-all.
  - “Deny except X.”
  - “Allow only if regex/path filter matches.”
- Probes that:
  - Run under those profiles (via wrapper or sandbox-exec as a fallback).
  - Attempt a small, explicit set of operations (file opens, network calls, IPC, etc.).
  - Record which actions succeed or fail in a structured form (JSON/JSONL).

The ideal pattern is “microprofile + probe + decoded graph path”: for each scenario, we know which operations were attempted, which filters were relevant, which decision node was reached, and how that path maps back to SBPL.

### Current evidence & manifests

- **Golden-triple runtime expectations (preferred semantic witnesses)**
  - `book/graph/mappings/runtime/expectations.json` – manifest keyed by `profile_id` with host/build/SIP metadata, blob path + SHA256, status (`ok`/`partial`/`blocked`), probe count, and trace path.
  - `book/graph/mappings/runtime/traces/*.jsonl` – normalized per-profile probe rows (operation name/ID, input path, expected vs actual, match/status, command, exit code).
  - These runs currently cover `allow_all`, `metafilter_any`, and a bucket4 profile (`ok`), plus a bucket5 profile (`partial`) where expected vs actual diverge.

- **Legacy sandbox-exec traces (brittle, but still informative)**
  - `book/graph/concepts/validation/out/semantic/{metafilter.jsonl,sbpl_params.jsonl,network.jsonl,mach_services.jsonl}` – older logs using sandbox-exec-based harnesses.
  - These are marked `brittle` in `validation/out/index.json` and should not be silently upgraded to “ok”.

### Gaps and open questions

- Semantic coverage is intentionally narrow: mainly file-read/file-write and simple metafilter shapes on small SBPL profiles.
- Bucket5 behavior and system/platform profiles are still partial or blocked due to apply gates and legacy harness limitations.
- There is still work to do in tying runtime traces to precise node paths in decoded graphs for more complex profiles.

---

## Vocabulary and Mapping cluster

### Concepts in scope

- Operation Vocabulary Map  
- Filter Vocabulary Map

### Evidence shape

These concepts are about naming and alignment: how symbolic names and argument shapes relate to on-disk IDs and observed behavior.

Primary evidence:
- Enumerations of operations and filters from:
  - Dyld cache slices (libsandbox / Sandbox framework) on this host.
  - Compiled profiles (extracted op/filter tables).
  - Runtime probes (which operation IDs/names actually get used).
- Cross-checks between:
  - Canonical vocab tables for this host.
  - Tables extracted from compiled profiles.
  - Operation/filter names referred to by examples and probes.

### Current evidence & manifests

- **Canonical vocab tables**
  - `book/graph/mappings/vocab/ops.json` – Operation vocab map (ID↔name + provenance).
  - `book/graph/mappings/vocab/filters.json` – Filter vocab map.
  - `book/graph/mappings/vocab/operation_names.json` / `filter_names.json` – raw harvested names from dyld cache.
  - `book/graph/mappings/vocab/attestations.json` – attestation tying vocab tables to dyld slices and reference blobs (SHA256, counts, source paths).

- **Op-table ↔ vocab alignment**
  - `book/graph/mappings/op_table/op_table_vocab_alignment.json` – per-profile alignment of op-table entries to Operation IDs, used to interpret buckets in terms of concrete operations.
  - `book/graph/mappings/op_table/{op_table_map.json,op_table_signatures.json,op_table_operation_summary.json}` – bucket maps and structural signatures for synthetic profiles.

- **Validation outputs**
  - `book/graph/concepts/validation/out/vocab/*` – mirrored vocab tables and any runtime-usage summaries (`runtime_usage.json` is currently `blocked` when no runtime IDs are observed).

### Gaps and open questions

- Runtime vocab usage remains `blocked` in scenarios where apply gates prevent observing live IDs.
- Further alignment work is needed to cover all observed buckets across system profiles and to thread filter IDs into bucket shifts for more complex filters.

---

## Runtime Lifecycle and Extension cluster

### Concepts in scope

- Sandbox Extension  
- Policy Lifecycle Stage  
- Profile Layer (system/global/app layering)  
- Policy Stack Evaluation Order  
- Compiled Profile Source  
- Container  
- Entitlement  
- Seatbelt label / credential state  
- Adjacent controls (TCC service, hardened runtime, SIP) where they intersect with sandbox outcomes

### Evidence shape

These concepts concern when and how profiles apply over a process lifetime, how layers compose into an effective policy stack, and how extensions and adjacent controls modify effective policy.

Primary evidence:
- Scenario-style probes that:
  - Launch processes through different paths (launchd, GUI, sandbox-exec, wrapper) and attempt operations at different lifecycle stages.
  - Observe how access changes over time in response to extensions, container setup, and profile changes.
  - Capture entitlements, container roots, profile sources, and any extensions/adjacent controls that impact decisions.

### Current evidence & manifests

- **Runtime expectations (golden triple)**  
  - `book/graph/mappings/runtime/expectations.json` + `traces/*` – provide end-to-end runs for a small set of profiles, including their blob paths and statuses. These are primarily semantic witnesses but also serve as concrete examples of policy attachment for non-platform profiles.

- **Lifecycle manifest**
  - `book/graph/mappings/runtime/lifecycle.json` – normalized lifecycle scenarios:
    - `entitlements-evolution` (unsigned baseline; `partial` – entitlements absent, useful as a baseline witness).
    - `extensions-dynamic` (`blocked` – crashes/NULL tokens, see `extensions_dynamic.md`).
  - `book/graph/mappings/runtime/lifecycle_traces/*.jsonl` – per-scenario rows with key fields (executable, entitlements_present, notes, source logs).

- **System profile attestations**
  - `book/graph/mappings/system_profiles/attestations.json` – provides blob hashes, tag-layout/vocab versions, anchors, and runtime links where expectations exist. These are the static “profile layer” side of lifecycle examples.

- **Lifecycle validation outputs**
  - `book/graph/concepts/validation/out/lifecycle/*` – source logs for entitlements and extension attempts (see `entitlements.json`, `extensions_dynamic.md`).

### Gaps and open questions

- Entitlement → profile → runtime behavior pipeline is not yet end-to-end; current lifecyle traces show only unsigned baselines and failing extension calls.
- Platform profiles still fail apply gates (`sandbox_init`/`sandbox_apply` returning `EPERM`); these failures are evidence about the environment, but they constrain what lifecycle evidence we can gather on this host.
- Containers and per-service composition scenarios exist as plans/examples but have not yet been refreshed into mapping-grade manifests.

---

## Evidence manifests (router)

The following manifests are the main entry points from concepts → examples → artifacts for this host:

- `book/graph/concepts/validation/out/index.json`  
  - Cluster-level summary of validation outputs (static/semantic/vocab/lifecycle) and their statuses.

- `book/graph/mappings/system_profiles/digests.json`  
  - Static digests for canonical system/profile blobs.

- `book/graph/mappings/system_profiles/attestations.json`  
  - Compiled-profile attestations: blob hashes, op-table entries, tag counts, literal strings/anchor hits, vocab/tag-layout versions, runtime links.

- `book/graph/mappings/system_profiles/static_checks.json`  
  - Decoder-backed structural checks (header op_count, section sizes, tag_layout hash) for canonical blobs.

- `book/graph/mappings/op_table/*`  
  - Op-table buckets, signatures, operation summaries, and vocab alignment.

- `book/graph/mappings/tag_layouts/tag_layouts.json`  
  - Per-tag PolicyGraph layouts.

- `book/graph/mappings/anchors/anchor_filter_map.json`  
  - Anchor → filter-ID/name map with status per anchor.

- `book/graph/mappings/vocab/{ops.json,filters.json,attestations.json}`  
  - Canonical vocab tables and their attestation to dyld slices and reference blobs.

- `book/graph/mappings/runtime/expectations.json` + `traces/*`  
  - Golden-triple runtime expectations and per-profile probe traces.

- `book/graph/mappings/runtime/lifecycle.json` + `lifecycle_traces/*`  
  - Lifecycle scenarios (entitlements/extension attempts) and their normalized traces.

Agents should treat these manifests as the primary handles when wiring concepts to artifacts or adding new witnesses.

---

## Validation workflow (condensed)

The validation plan ties `book/examples/` labs to the four clusters. Harness code and task metadata live under `book/graph/concepts/validation/` (see `validation/README.md` and `validation/tasks.py`).

- **Stage 0 — Setup and metadata**
  - Record host OS/build, hardware, SIP/TCC state, and profile format variant in `validation/out/metadata.json`.

- **Stage 1 — Static-Format validation**
  - Produce compiled blobs via `sb`, `extract_sbs`, `sbsnarf`, etc.
  - Ingest via shared ingestion (`profile_ingestion.py`, `book.api.decoder`) and write JSON under `validation/out/static/`.
  - Update static mappings (`system_profiles/*`, `op_table/*`, `tag_layouts/*`, `anchors/*`) when evidence is strong enough to be reused.

- **Stage 2 — Semantic Graph and Evaluation**
  - Prefer wrapper-based `runtime-checks`/golden-triple harness over sandbox-exec; write results to `validation/out/semantic/` and normalize into `mappings/runtime/expectations.json` + `traces/*`.
  - Distinguish Seatbelt decisions from TCC/SIP/platform failures where possible.

- **Stage 3 — Vocabulary and Mapping**
  - Extract vocab from compiled blobs into `mappings/vocab/ops.json` and `filters.json`.
  - Cross-check against dyld-derived tables and write `validation/out/vocab/*` and `mappings/vocab/attestations.json`.
  - Align operations with op-table buckets via `op_table/op_table_vocab_alignment.json`.

- **Stage 4 — Runtime Lifecycle and Extension**
  - Run lifecycle probes (`entitlements-evolution`, `platform-policy-checks`, `containers-and-redirects`, `extensions-dynamic`, `libsandcall`).
  - Capture logs under `validation/out/lifecycle/` and promote stable scenarios into `mappings/runtime/lifecycle.json` + `lifecycle_traces/*` once they are “golden” enough.

- **Stage 5 — Evidence index and handoff**
  - Summarize existing outputs in `validation/out/index.json`.
  - Use this index plus the mapping manifests above when wiring concept entries to witnesses in code or prose.

---

## Guidance for new validation paths

For both humans and agents, the safest way to extend validation is to reuse the existing spines and manifests rather than inventing new ad-hoc evidence.

### Good combinations of evidence

- **Static + vocab + anchors**
  - Start from compiled blobs, decode them, then join:
    - Static checks and attestations (`system_profiles/*`),
    - Vocab tables + attestation (`mappings/vocab/*`),
    - Anchor mappings (`mappings/anchors/*`).
  - Best for Binary Profile Header, Operation Pointer Table, Profile Format Variant, PolicyGraph/Policy Node, and Filter (at the structural level).

- **Static + runtime expectations**
  - For semantic concepts, use golden-triple runtime expectations as the runtime leg:
    - One profile (with attestation),
    - One or more runtime traces (`runtime/expectations.json` + `traces/*`),
    - A decoded graph path (via decoder/ingestion).
  - Good for Operation, Filter, Metafilter, Decision, and Action Modifier.

- **Lifecycle + static + runtime**
  - For lifecycle concepts, combine:
    - Lifecycle manifest + traces (`runtime/lifecycle.json` + `lifecycle_traces/*`),
    - System profile attestations/static checks (`system_profiles/*`),
    - Runtime expectations where available.
  - Treat apply gates and runtime crashes as evidence about the environment, not as missing policy.

### Where to start when adding a new validation path

- Check `validation/out/index.json` to see current coverage for your cluster.
- Choose nearby examples from `book/examples/` (see `EXAMPLES.md` for cluster bindings).
- Prefer:
  - Small, composable examples over large scenarios.
  - Evidence that is regenerable on this host over opaque or manual logs.
  - Outputs that plug into existing manifests under `book/graph/mappings/` and `book/graph/concepts/validation/out/`.

### What has been done vs what remains

- **Strong (mostly static/vocab)**
  - Profile structure and op-table behavior on this host are well covered by static ingestion, op-table experiments, tag layouts, system profile digests, vocab attestation, and static checks.
  - Canonical Operation/Filter vocab tables and their provenance are fixed and should be treated as authoritative for this baseline.

- **Partial (semantic)**
  - Golden-triple runtime expectations provide good, narrow semantic witnesses for basic file operations and some metafilter shapes.
  - Bucket5 behavior and platform/system profiles are partial or blocked.

- **Partial/blocked (lifecycle)**
  - Entitlements and extensions have early witnesses, but there is no complete entitlement→profile→runtime pipeline yet.
  - Apply gates for platform blobs remain in place on this host and constrain further lifecycle work.

When in doubt, bias toward:
- Adding witnesses to existing manifests and updating `status`/`notes`,
- Making uncertainty explicit rather than smoothing gaps,
- Keeping every new claim traceable to at least one of the manifests listed above.

---

## Appendix: Misconceptions and failure modes

The point of building a concept inventory and validation plan is straightforward: every important idea about the sandbox needs something concrete under it. For each “operation,” “filter,” “policy graph,” or “extension,” we want to be able to say what artifacts and behaviors show that we understand it correctly on current macOS.

That also means that coherent but wrong models are dangerous: they tend to generate plausible experiments and diagrams that reinforce the wrong picture. The examples below are “fair” misconceptions—plausible, technically informed ways to be wrong—and the kinds of errors they produce.

### SBPL Profile

**Misconception**

“An SBPL profile is *the* policy for a process: if I read the profile text, I see the full effective sandbox.”

This treats the SBPL file (or snippet) as a self-contained, complete description of the sandbox, ignoring that:

- The effective policy can be a composition of multiple profiles (system base profile, app/container profile, service-specific overlays).
- Some behavior comes from implicit or generated rules (e.g., containerization, platform defaults), not explicitly written SBPL.

**Resulting error**

You might confidently claim:

> “If operation X is allowed in this SBPL, the process can always perform X.”

Then you design a probe that:

- Runs under a containerized app profile that is layered on top of the SBPL you’re looking at, or
- Picks a system service whose effective policy has extra hidden constraints.

Your probe reports “denied,” and you incorrectly attribute that denial to a failure in your understanding of the SBPL syntax, rather than to stacked profiles and implicit rules you never accounted for.

---

### Operation

**Misconception**

“Each syscall maps to exactly one sandbox ‘operation’, and those names are just thin labels over syscalls.”

This flattens the abstraction:

- Operations can be broader than a single syscall (e.g., multiple syscalls hitting the same operation).
- A single syscall can trigger multiple operations, or an operation can be consulted in contexts that do not look like a single syscall boundary.
- Operations sometimes correspond to higher-level notions (e.g., `file-read*`, `mach-lookup`) rather than raw kernel entry points.

**Resulting error**

You assume:

> “If `open(2)` fails due to the sandbox, that means the `file-read*` operation is denied.”

Then you:

- Design probes that equate “open denied” ⇔ “operation A denied,” and “open allowed” ⇔ “operation A allowed”.
- Build capability tables based on that equivalence.

Later you discover cases where:

- `open` fails for reasons tied to different operations (metadata-only access, path resolution, or Mach-right preconditions), or
- A different syscall hitting the same operation yields a different denial pattern.

Your mapping from “observed syscall outcomes” to “operation-level policy” ends up misleading, and you over- or under-estimate the scope of particular operations.

---

### Filter

**Misconception**

“Filters are simple ‘if-conditions’ checked once per rule; if the key/value matches, the rule fires, otherwise it’s ignored.”

This treats filters as one-shot guards on flat rule lists, instead of:

- Nodes and edges in a graph where unmatched filters route evaluation to other nodes.
- Conditions that can be evaluated in multiple stages with default branches and combinations, not just “test and drop rule.”

**Resulting error**

You explain filters as:

> “Think of filters like `if (path == "/foo") then allow; else ignore this rule`.”

Then you:

- Try to “prove” that a certain path is unreachable because every rule with that path filter looks safe in isolation.
- Ignore how non-matching filters might send evaluation along a default edge that reaches a permissive decision for broader paths.

You miss an allow-path that emerges from graph structure (default edges, metafilters, fall-through) and state in your write-up:

> “Path /foo/bar is definitely denied in all cases,”

when in reality the graph structure allows it via a non-obvious route.

---

### Profile Layer / Policy Stack Evaluation Order

**Misconception**

“Multiple sandbox layers just combine as ‘most restrictive wins’ (a simple logical AND over allows/denies).”

This is intuitive, but:

- Real composition includes ordering, default paths, and sometimes explicit overrides.
- Some layers introduce new operations/filters or defaults that are not pure subsets of another.
- Extensions and dynamic changes can alter the stack in ways that do not look like a straightforward meet of policies.

**Resulting error**

You teach:

> “If any layer denies an operation, it’s denied overall; if all allow it, it’s allowed.”

Then you:

- Analyze a system profile + app profile + extension scenario under this AND model.
- Conclude that a sensitive operation is impossible because “layer B denies it.”

In practice, evaluation order or an extension changes the decision path so the deny in layer B is never reached (or is overridden). Your risk assessment claims “this cannot happen,” when in fact it does under real evaluation order.

---

### Sandbox Extension

**Misconception**

“An extension is basically a ‘turn off sandbox here’ token; once you have one, the sandbox doesn’t really apply to that resource anymore.”

This conflates:

- Scoped, capability-like grants (often tied to a path or specific operation types) with a global disable.
- The idea that extensions can be time- or context-limited, or only affect certain operations, with a blanket exemption.

**Resulting error**

You describe extensions as:

> “If an app gets an extension for `/private/foo`, it can do anything there, sandbox be damned.”

On that basis you:

- Design probes that simply check “with extension present, can we read/write/delete everything under that path?” and treat any failure as “extension is broken.”
- Overstate threat models (“leak one extension and the whole sandbox collapses”) while ignoring narrower semantics.

You mischaracterize the scope of extensions and design validation that expects full removal of constraints, misinterpreting partial, correctly scoped behavior as surprising or inconsistent.

---

### Dangers

All of these misconceptions compress a layered, data-structure-heavy, evaluation-order-sensitive system into something that looks like a static ACL with a few predicates. That compression makes the sandbox seem easy to reason about and tempting to summarize with a few diagrams, tables, or one-off probes.

That is why this inventory keeps insisting on:

- **Concrete witnesses** on this host (blobs, logs, traces), not just diagrams.
- **Versioned manifests** as the glue (mappings and validation outputs), not ad-hoc evidence.
- **Status fields** (`ok`, `partial`, `brittle`, `blocked`) as part of the meaning, not cosmetic labels.

If a new validation path or explanation cannot be traced back to those pieces, it is probably building on a mental model instead of the actual sandbox. This file exists to keep the concepts pinned to what we can see and rerun, so that even our misunderstandings are at least diagnosable. 
