# CONCEPT_INVENTORY.md

## 0. Preface

This document is a **concept inventory** for the Seatbelt/XNUSandbox work in this repo. It enumerates the key ideas from `Orientation.md` and `Appendix.md` and gives each concept:

- A stable name.
- A short definition snapshot.
- A place to later record implementation status and evidence.

Think of this as the bridge between the *abstract model* (Orientation/Appendix) and the *code/examples* in the modernized folders. It does **not** describe concrete implementations in detail; that is left to code-level documentation and future Codex passes.

### 0.1 Purpose

- Make the core Seatbelt concepts explicit and enumerable.
- Provide one canonical “home” per concept to track:
  - Definitions (now),
  - Implementation status and evidence (later),
  - Version-specific caveats and open questions (later).
- Support cross-cutting refactors: multiple examples can converge on the same conceptual targets instead of re-inventing them.

### 0.2 How to read this document

- Sections **3.x** each describe a single concept.
- For each concept:
  - The heading includes initial **status** and **epistemic** tags (see §1).
  - An **introductory remark** gives a quick sense of why this concept matters.
  - `3.x.1 Definition snapshot` is filled now.
  - `3.x.2+` are placeholders for future work by code-aware agents (Codex).

### 0.3 Relationship to other documents

- `Orientation.md` – narrative overview of the Seatbelt model (what the sandbox “is” and “does”).
- `Appendix.md` – reference material (DSL cheatsheet, binary formats, operations/filters, policy stacking).
- `ModernizationReport.md` – what was done to the legacy XNUSandbox examples on macOS 14.x.
- `CONCEPT_INVENTORY.md` (this file) – index of the **conceptual pieces** that all of the above rely on and that future code should explicitly implement or reference.

---

## 1. Status & Epistemic Legend

These tags are attached to each concept heading as rough initial labels. They are intentionally conservative and should be updated as code and evidence accumulate.

### 1.1 Status tags (`S:`)

- `[S:doc-only]`  
  Concept appears only in text (Orientation/Appendix/etc.); no shared code-level abstraction yet.

- `[S:doc-only→code-partial]`  
  Concept is currently only documented, but there is a clear intent to implement a shared abstraction; some ad hoc code may already exist in examples.

- `[S:code-partial]`  
  Concept is implemented in some form in one or more examples, but not yet unified into a shared abstraction (multiple ad hoc versions, partial coverage).

- `[S:code-partial→core]`  
  Concept is partially implemented and is a good candidate to become a central shared abstraction.

- `[S:code-core]`  
  Concept has a clear, shared implementation that is used across examples (this is a target state, not a claim for current code).

### 1.2 Epistemic tags (`E:`)

- `[E:2011-heavy]`  
  Understanding is anchored mainly in 2010–2011-era reversing and documents (Blazakis, SandBlaster, early OS X/iOS).

- `[E:14.x-sampled]`  
  Concept has been empirically checked on at least some macOS 14.x profiles or behavior (as described in modernization docs).

- `[E:speculative]`  
  Concept is plausible and consistent with public docs, but hasn’t been strongly validated on modern systems; details may be wrong or incomplete.

- Combined tags like `[E:2011-heavy+14.x-sampled]` or `[E:2011-heavy+speculative-on-14.x]` indicate mixed grounding.

### 1.3 Sources and evidence (for future use)

When later filling in `3.x.2+` sections, evidence should be ordered roughly by:

1. Direct behavior/tests on current macOS (14.x+).
2. Orientation/Appendix alignment.
3. Historical papers and code.
4. Inferred patterns and informed speculation.

---

## 2. Global Model (high-level)

This section describes how the concepts fit together, at a coarse level.

### 2.1 Seatbelt model snapshot

At a high level, Seatbelt is a **kernel-enforced reference monitor** driven by policies written in SBPL, compiled by `libsandbox` into binary profiles, and evaluated via MAC hooks for each sensitive operation. The core moving parts are:

- **SBPL profiles** (what the policy author writes).
- **Operations** (what is being attempted).
- **Filters and metafilters** (under what conditions rules apply).
- **Decisions and action modifiers** (what happens: allow/deny/log/prompt).
- **Policy graphs** over **nodes**, backed by **headers**, **operation pointer tables**, and **regex/literal tables** in the compiled blob.
- A **stack** of profile layers (platform, per-process) plus **extensions** and other MAC modules that combine into a final decision.

### 2.2 Concept vs encoding

Many concepts have two faces:

- A **semantic face**: “an operation is a class of behavior like `file-read*`.”
- A **format face**: “operation ID 37 indexes into this pointer table entry.”

The inventory deliberately separates these:

- Concepts like **Operation**, **Filter**, **Decision**, **PolicyGraph** are semantic.
- Concepts like **Binary Profile Header**, **Operation Pointer Table**, **Profile Format Variant** are about concrete encodings.

This separation should guide future code: semantic types on one side; format-specific parsers/writers on the other.

### 2.3 Concept → examples linkage (for future filling)

A later Codex pass can fill in a matrix of:

- Concepts vs examples (which folders exercise what).
- Concepts vs shared abstractions (which types/modules implement what).

For now, this document just defines the concepts.

---

## 3. Concept Inventory

> Note: For each concept below, only **Introductory remarks** and **3.x.1 Definition snapshot** are filled. Sections 3.x.2–3.x.6 are placeholders.

---

### 3.1 SBPL Profile `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
SBPL profiles are the textual “programs” that define sandbox policies; they are the most human-facing artifacts in the system and the starting point for many examples.

#### 3.1.1 Definition snapshot

An SBPL profile is the high-level sandbox policy written in Apple’s Scheme-like Sandbox DSL: it declares a version, a default decision (usually `(deny default)`), and a list of `(allow …)`/`(deny …)` rules that name operations and constrain them with filters. This is the “source code” for a Seatbelt policy that `libsandbox` parses and compiles into a binary form; it’s where concepts like `file-read*`, `mach-lookup`, `subpath`, and `require-any` appear explicitly and in a way humans can read and edit.

#### 3.1.2 Implementation status

#### 3.1.3 Evidence & tests

#### 3.1.4 Version-specific notes

#### 3.1.5 Example usages

#### 3.1.6 Open questions / TODOs

---

### 3.2 Operation `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
Operations are the verbs of Seatbelt: every syscall or action the sandbox can control is mapped to one of these named operations.

#### 3.2.1 Definition snapshot

An operation is a named class of kernel action that the sandbox can control, such as `file-read*`, `file-write*`, `network-outbound`, `mach-lookup`, or `sysctl-read`. In SBPL it appears as the main verb in a rule; in compiled profiles it becomes an integer operation ID keyed into a table of entrypoints. Conceptually, an operation answers “what kind of thing is this process trying to do?” before filters and policy graphs decide whether that attempt is allowed.

#### 3.2.2 Implementation status

#### 3.2.3 Evidence & tests

#### 3.2.4 Version-specific notes

#### 3.2.5 Example usages

#### 3.2.6 Open questions / TODOs

---

### 3.3 Filter `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
Filters encode the conditions under which a rule applies, by looking at paths, addresses, process metadata, and other parameters.

#### 3.3.1 Definition snapshot

A filter is a key–value predicate that narrows when a rule applies by inspecting arguments or process/system state: path predicates (`literal`, `subpath`, `regex`), vnode properties (`vnode-type`), IPC names (`global-name`), network endpoints (`remote ip`, `remote tcp`), or metadata like `signing-identifier`, `entitlement-is-present`, and `csr`. In SBPL these appear as nested s-expressions after the operation; in the compiled graph each filter becomes a node that tests a particular key/value and branches based on whether it matches.

#### 3.3.2 Implementation status

#### 3.3.3 Evidence & tests

#### 3.3.4 Version-specific notes

#### 3.3.5 Example usages

#### 3.3.6 Open questions / TODOs

---

### 3.4 Metafilter `[S:doc-only→code-partial][E:2011-heavy+speculative]`

Introductory remarks  
Metafilters describe the logical structure of conditions—how individual filters combine as AND/OR/NOT—rather than any single predicate.

#### 3.4.1 Definition snapshot

A metafilter is a logical combinator that glues filters together using boolean structure: `require-all` (AND), `require-any` (OR), and `require-not` (NOT). They let SBPL express complex conditions like “allow file reads under `/System` that are not symlinks and either match this regex or carry a particular extension token” in a structured way. In compiled profiles, these combinators disappear as named constructs and are implemented by specific patterns of filter nodes and edges in the policy graph.

#### 3.4.2 Implementation status

#### 3.4.3 Evidence & tests

#### 3.4.4 Version-specific notes

#### 3.4.5 Example usages

#### 3.4.6 Open questions / TODOs

---

### 3.5 Decision `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
Decisions are where policy evaluation ends: they determine whether an operation is allowed or denied (and with what side effects).

#### 3.5.1 Definition snapshot

A decision is the terminal outcome of evaluating a policy graph for a given operation and set of arguments: typically “allow” or “deny”, possibly decorated with flags like “log this” or “defer to user consent”. In SBPL it’s implicit in the `(allow …)` or `(deny …)` form; in the compiled graph it appears as a terminal node or encoded result code that ends traversal. When the kernel walks the graph for an operation, the decision node it lands on determines whether the underlying syscall succeeds or fails.

#### 3.5.2 Implementation status

#### 3.5.3 Evidence & tests

#### 3.5.4 Version-specific notes

#### 3.5.5 Example usages

#### 3.5.6 Open questions / TODOs

---

### 3.6 Action Modifier `[S:doc-only][E:2011-heavy+speculative]`

Introductory remarks  
Action modifiers change what happens around a decision—logging, prompting, etc.—without changing the basic allow/deny verdict.

#### 3.6.1 Definition snapshot

An action modifier is an annotation on a rule that changes what happens when it matches without changing the basic allow/deny verdict, such as `(with report)` for extra logging or user-consent modifiers that integrate with TCC. They appear in SBPL as a wrapper around the operation, e.g. `(allow (with report) sysctl …)`, and in compiled form as additional flags or fields attached to decision nodes. Conceptually, they encode side effects like “log this event” or “ask the user” layered on top of the permit/deny outcome.

#### 3.6.2 Implementation status

#### 3.6.3 Evidence & tests

#### 3.6.4 Version-specific notes

#### 3.6.5 Example usages

#### 3.6.6 Open questions / TODOs

---

### 3.7 Profile Layer `[S:doc-only][E:2011-heavy+speculative-on-14.x]`

Introductory remarks  
Profile layers separate “what this app’s sandbox says” from “what the platform policy says”, which matters when interpreting effective behavior.

#### 3.7.1 Definition snapshot

A profile layer describes which sandbox policy is being applied in the multi-layer system: the global **platform** policy that applies to almost all processes, per-process policies like App Sandbox or custom profiles attached via `sandbox_init*`, and any other Seatbelt profiles. The conceptual model is that multiple layers can apply to a single operation, with platform policy evaluated first and per-process policy next; thinking in terms of layers helps keep straight where a particular rule lives and why a decision was made.

#### 3.7.2 Implementation status

#### 3.7.3 Evidence & tests

#### 3.7.4 Version-specific notes

#### 3.7.5 Example usages

#### 3.7.6 Open questions / TODOs

---

### 3.8 Sandbox Extension `[S:doc-only][E:2011-heavy+speculative]`

Introductory remarks  
Sandbox extensions are the mechanism for granting narrow, dynamic exceptions to otherwise static SBPL rules.

#### 3.8.1 Definition snapshot

A sandbox extension is a token-based capability that, when granted to and consumed by a process, temporarily widens what its sandbox allows for specific resources like paths, Mach services, or containers. Instead of rewriting profiles, trusted system components issue opaque extension strings that the sandbox policy recognizes via `extension` filters and uses to grant narrowly scoped exceptions. Extensions bridge static SBPL rules and dynamic, per-request access decisions driven by components like tccd or Launch Services.

#### 3.8.2 Implementation status

#### 3.8.3 Evidence & tests

#### 3.8.4 Version-specific notes

#### 3.8.5 Example usages

#### 3.8.6 Open questions / TODOs

---

### 3.9 Policy Lifecycle Stage `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The policy lifecycle captures the different shapes a sandbox policy takes as it moves from text to kernel-enforced graph.

#### 3.9.1 Definition snapshot

Policy lifecycle stages are the distinct forms a sandbox policy takes from authoring to enforcement: (1) SBPL source text written in the sandbox DSL, (2) the `libsandbox` / TinyScheme intermediary representation (often exposed as a per-operation rules vector), (3) the compiled binary profile blob (header, operation tables, node graph, regex/literal tables), and (4) the in-kernel evaluation of that blob via MAC hooks at syscall time. Separating these stages helps you reason about which tools and formats are involved at each step.

#### 3.9.2 Implementation status

#### 3.9.3 Evidence & tests

#### 3.9.4 Version-specific notes

#### 3.9.5 Example usages

#### 3.9.6 Open questions / TODOs

---

### 3.10 Binary Profile Header `[S:code-partial→core][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The binary profile header is the entry point for any decoder: it tells you how to find everything else in the compiled blob.

#### 3.10.1 Definition snapshot

The binary profile header is the fixed-layout structure at the start of a compiled profile blob that records format/version information and the offsets and counts for all major sections: operation pointer table, node array, regex pointer table, literal/regex data, and, in bundled formats, per-profile descriptors. It’s the entry point for any decoder: reading the header tells you how many operations there are, where to find each section, and which variant of the format you’re dealing with.

#### 3.10.2 Implementation status

Shared parsers for both the modern graph-based layout (`graph-v1`, used by `examples/sb/`) and the legacy decision-tree layout (`legacy-tree-v1`, used by `examples/sbdis/`) live in `concepts/cross/profile-ingestion/ingestion.py`.

#### 3.10.3 Evidence & tests

#### 3.10.4 Version-specific notes

#### 3.10.5 Example usages

#### 3.10.6 Open questions / TODOs

---

### 3.11 Operation Pointer Table `[S:code-partial→core][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The operation pointer table is how the profile connects abstract “operations” to concrete starting points in the node graph.

#### 3.11.1 Definition snapshot

The operation pointer table is an array indexed by operation ID where each entry is an offset or index into the policy node array for that operation’s rule graph. Instead of giving each operation a separate block, the compiled profile often stores all nodes in a single array and uses this table as the set of entrypoints. When decoding, you start from the pointer for a given operation and follow nodes until you reach a decision; without this table, all you have is an undifferentiated node heap.

#### 3.11.2 Implementation status

Operation pointer table parsing for both modern graph-based and legacy decision-tree formats is provided by the shared ingestion layer in `concepts/cross/profile-ingestion/ingestion.py`, exercised by `examples/sb/` and `examples/sbdis/`.

#### 3.11.3 Evidence & tests

#### 3.11.4 Version-specific notes

#### 3.11.5 Example usages

#### 3.11.6 Open questions / TODOs

---

### 3.12 Policy Node `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
Policy nodes are the basic building blocks of the compiled graph: each node either tests something or decides something.

#### 3.12.1 Definition snapshot

A policy node is an individual element in the compiled policy graph: either a non-terminal filter node that tests a specific key/value and has “match” and “unmatch” successors, or a terminal decision node that encodes allow/deny (and possibly logging/consent flags) and ends traversal. The entire policy is built from these nodes, with operations selecting starting nodes via the op-pointer table and filters/metafilters emerging from how nodes and successors are wired together.

#### 3.12.2 Implementation status

#### 3.12.3 Evidence & tests

#### 3.12.4 Version-specific notes

#### 3.12.5 Example usages

#### 3.12.6 Open questions / TODOs

---

### 3.13 Policy Graph / PolicyGraph `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The policy graph (or `PolicyGraph` type) is the canonical in-memory representation we want everything to converge on.

#### 3.13.1 Definition snapshot

A policy graph (often modeled as a `PolicyGraph` type) is the full, per-profile representation of how operations, filters, metafilters, and decisions connect: for each operation ID, an entrypoint into a directed graph of policy nodes. Conceptually, it’s the canonical internal form for analysis and tooling: once you’ve turned a profile blob into a PolicyGraph, you can render it as SBPL-like rules, visualize subgraphs, test reachability for certain decisions, or compare different profiles structurally.

#### 3.13.2 Implementation status

#### 3.13.3 Evidence & tests

#### 3.13.4 Version-specific notes

#### 3.13.5 Example usages

#### 3.13.6 Open questions / TODOs

---

### 3.14 Regex / Literal Table `[S:code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The regex/literal table is where all the stringy bits live: paths, patterns, and other literals shared across nodes.

#### 3.14.1 Definition snapshot

The regex/literal table is the shared pool of string data and serialized regex NFAs referenced by filters in the policy graph. Rather than embedding full paths or patterns in nodes, compiled profiles store them once in a combined literals/regex section and have filter nodes hold small indices into this table. Decoding these tables lets you turn abstract “filter key = path, value index = 17” back into concrete expressions like `(literal "/bin/ls")` or `(regex #"^/Users/[^/]+/Documents")` in reconstructed SBPL.

#### 3.14.2 Implementation status

#### 3.14.3 Evidence & tests

#### 3.14.4 Version-specific notes

#### 3.14.5 Example usages

#### 3.14.6 Open questions / TODOs

---

### 3.15 Profile Format Variant `[S:doc-only→code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
Profile format variants capture that the same high-level concepts have been encoded in different binary layouts over OS and device generations.

#### 3.15.1 Definition snapshot

A profile format variant is a concrete on-disk/in-kernel encoding of compiled policies, such as the early decision-tree format (simple handler records with terminal/non-terminal opcodes) and the later graph-based formats (operation pointer tables plus shared node arrays and regex tables), including bundled multi-profile blobs used on newer systems. Each variant uses the same conceptual building blocks—operations, filters, nodes, graphs—but with different headers, node layouts, and section arrangements that decoders must handle explicitly.

#### 3.15.2 Implementation status

Shared code currently handles two concrete variants via the ingestion layer: `graph-v1` (modern, `examples/sb/`) and `legacy-tree-v1` (early decision-tree, `examples/sbdis/`).
#### 3.15.3 Evidence & tests

#### 3.15.4 Version-specific notes

#### 3.15.5 Example usages

#### 3.15.6 Open questions / TODOs

---

### 3.16 Operation Vocabulary Map `[S:doc-only→code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The operation vocabulary map is the dictionary that turns integer operation IDs back into human-readable names like `file-read*`.

#### 3.16.1 Definition snapshot

The Operation Vocabulary Map is the bidirectional mapping between numeric operation IDs used in compiled profiles and the human-readable operation names used in SBPL, like `file-read*` or `mach-lookup`. It’s essential for turning anonymous graphs into understandable output and for targeting analysis to specific behaviors; in practice it’s built from `libsandbox` strings, system SBPL profiles, and observed behavior, and must track which mappings are confirmed, inherited from older reversals, or still unknown on a given OS version.

#### 3.16.2 Implementation status

#### 3.16.3 Evidence & tests

#### 3.16.4 Version-specific notes

#### 3.16.5 Example usages

#### 3.16.6 Open questions / TODOs

---

### 3.17 Filter Vocabulary Map `[S:doc-only→code-partial][E:2011-heavy+14.x-sampled]`

Introductory remarks  
The filter vocabulary map plays the same role as the operation map, but for the keys and encoded values used in filter nodes.

#### 3.17.1 Definition snapshot

The Filter Vocabulary Map is the similar mapping for filter keys and their encoded values: from numeric filter key IDs and packed representations (enums, indices, bitfields) in nodes to names and semantics like `literal`, `subpath`, `vnode-type`, `global-name`, `signing-identifier`, `entitlement-is-present`, and so on. It underpins meaningful reconstruction of SBPL filters from raw nodes and allows tools to group and reason about filters by category (path-based, Mach, network, process metadata, CSR/TCC-related) rather than by opaque integers.

#### 3.17.2 Implementation status

#### 3.17.3 Evidence & tests

#### 3.17.4 Version-specific notes

#### 3.17.5 Example usages

#### 3.17.6 Open questions / TODOs

---

### 3.18 Policy Stack Evaluation Order `[S:doc-only][E:2011-heavy+speculative-on-14.x]`

Introductory remarks  
The evaluation order explains how multiple policies and MAC modules combine to produce a single allow/deny for any given operation.

#### 3.18.1 Definition snapshot

Policy stack evaluation order describes how Seatbelt composes multiple policies when a sandbox-relevant operation occurs: the platform policy is evaluated first, then any per-process profile (App Sandbox or custom), and the final decision is the logical AND of all participating MAC policies (including non-Seatbelt ones). Understanding this order matters because a deny in the platform profile short-circuits per-process rules, and because some constraints that look “mysterious” at the SBPL level may actually live in a different layer of the stack.

#### 3.18.2 Implementation status

#### 3.18.3 Evidence & tests

#### 3.18.4 Version-specific notes

#### 3.18.5 Example usages

#### 3.18.6 Open questions / TODOs

---

### 3.19 Compiled Profile Source `[S:doc-only→code-partial][E:14.x-sampled]`

Introductory remarks  
Compiled profile source is about provenance: what kind of profile a blob represents and how it was obtained.

#### 3.19.1 Definition snapshot

“Compiled profile source” describes *where* a given binary sandbox profile blob comes from and *what role* it plays in the system. At this level we distinguish at least three broad classes: (1) **toy/test profiles** that we compile ourselves from small SBPL snippets for experimentation and unit tests, (2) **system service / App Sandbox profiles** that Apple ships as `.sb` files or embedded policies for daemons and GUI apps, and (3) **platform / global profiles** that are baked into system components and act as the baseline policy for large classes of processes. Tracking the source class for each blob is crucial, because it determines the intended scope of the rules (single process vs class of apps vs entire platform), the expected interaction with other policy layers, and how confidently we can generalize any structural observations we make from that profile.

#### 3.19.2 Implementation status

#### 3.19.3 Evidence & tests

#### 3.19.4 Version-specific notes

#### 3.19.5 Example usages

#### 3.19.6 Open questions / TODOs

## 4. Cross-Cutting Axes

This section groups concepts from §3 into a few **vertical axes** that cut across formats and examples. Each axis is a potential shared implementation layer: if we build one good abstraction per axis, most examples can converge on it.

> Note: Like §3.x.2+, the subsections here are mostly placeholders for future code-aware passes. The main content now is the **structure** and **linkage to concepts**.

---

### 4.1 Profile Ingestion Layer

This axis covers everything from “raw bytes on disk” to “typed representation of a compiled profile’s sections.”

#### 4.1.1 Scope & intent

- Define a minimal, shared interface for:
  - Reading compiled profile blobs from various **sources**.
  - Parsing **headers** and locating sections.
  - Normalizing differences between **profile format variants**.

#### 4.1.2 Related concepts

- **Binary Profile Header** (§3.10)
- **Operation Pointer Table** (§3.11)
- **Regex / Literal Table** (§3.14)
- **Profile Format Variant** (§3.15)
- **Compiled Profile Source** (§3.19)
- Touches: **Policy Lifecycle Stage** (§3.9), **SBPL Profile** (§3.1) as origin

#### 4.1.3 Example entry points

- Folders that currently contain ad hoc ingestion logic:
  - `examples/apple-scheme/`
  - `examples/extract_sbs/`
  - `examples/sb/`
  - `examples/sbsnarf/`
  - `examples/sbdis/`
  - `examples/resnarf/`

#### 4.1.4 Target shared abstractions (for future filling)

- Design targets (not yet implemented):
  - Types:
    - `ProfileBlob` – raw bytes plus `CompiledProfileSource` metadata.
    - `ProfileHeader` – parsed header fields: format identifier, counts, section offsets.
    - `ProfileSections` – typed slices for op-pointer table, node array, regex/literal data.
    - Optional `ProfileFormatVariant` tag to annotate layout differences.
  - Core functions:
    - `parse_header(ProfileBlob) -> ProfileHeader`
    - `slice_sections(ProfileBlob, ProfileHeader) -> ProfileSections`
    - Optional `detect_format(ProfileBlob) -> ProfileFormatVariant`
  - All of the above are conceptual sketches to guide future implementations; no code exists yet.

#### 4.1.5 Open tasks (for future filling)

- Unifying per-folder parsers.
- Handling additional format variants.
- Corpus integration from §3.19.
- Refactor additional legacy consumers (e.g., `examples/resnarf/`) to consume the shared ingestion layer for header/section parsing.

---

### 4.2 Graph Construction Layer

This axis covers turning “sections” into a **PolicyGraph** built from **nodes**, **filters**, **metafilters**, and **decisions**.

#### 4.2.1 Scope & intent

- Define how to take:
  - Header + op-pointer table + node array (+ regex/literal table),
  - And build a stable in-memory **PolicyGraph** representation.
- Capture filter and decision semantics at the node level, independent of exact encoding.

#### 4.2.2 Related concepts

- **Policy Node** (§3.12)
- **Policy Graph / PolicyGraph** (§3.13)
- **Filter** (§3.3)
- **Metafilter** (§3.4)
- **Decision** (§3.5)
- Touches: **Regex / Literal Table** (§3.14), **Action Modifier** (§3.6)

#### 4.2.3 Example entry points

Graph Construction: `examples/sbdis/`, `examples/re2dot/`, `examples/resnarf/`

#### 4.2.4 Target shared abstractions (for future filling)

- Proposed `PolicyGraph` API:
  - Node structs/enums,
  - Per-operation entrypoints,
  - Traversal helpers.

#### 4.2.5 Open tasks (for future filling)

- Formalizing metafilter detection patterns.
- Handling unknown node opcodes.
- Representing action modifiers cleanly in the graph.

---

### 4.3 Vocabulary Mapping Layer

This axis covers mapping numeric IDs and encodings back to **names and semantics** for operations and filters.

#### 4.3.1 Scope & intent

- Provide a version-aware dictionary from:
  - Operation IDs → operation names (and categories).
  - Filter key IDs / encoded values → filter names and semantics.
- Track confidence and provenance for each mapping.

#### 4.3.2 Related concepts

- **Operation Vocabulary Map** (§3.16)
- **Filter Vocabulary Map** (§3.17)
- **Operation** (§3.2)
- **Filter** (§3.3)
- Touches: **Profile Format Variant** (§3.15), **Compiled Profile Source** (§3.19)

#### 4.3.3 Example entry points (for future filling)

Vocabulary Mapping: `examples/sbdis/`, `examples/network-filters/`, `examples/mach-services/`, `examples/entitlements-evolution/`

#### 4.3.4 Target shared abstractions (for future filling)

- Central mapping structures:
  - `OperationVocabulary` (with known/legacy/unknown states),
  - `FilterVocabulary` (with categories and encodings).
- Strategy for seeding from `libsandbox`, SBPL, and observed blobs.

#### 4.3.5 Open tasks (for future filling)

- Completing 14.x operation and filter maps.
- Representing unknown and partially known IDs gracefully.
- Handling OS/version-specific differences.

---

### 4.4 Rendering & Analysis Layer

This axis covers everything that turns a **PolicyGraph** plus vocab into human-facing representations and analyses.

#### 4.4.1 Scope & intent

- Define a family of renderers and analyzers that consume:
  - `PolicyGraph`,
  - Operation/filter vocab,
  - Optional source/corpus metadata.
- Produce:
  - SBPL-like text,
  - DOT graphs,
  - Tabular summaries,
  - Higher-level diagnostics.

#### 4.4.2 Related concepts

- **SBPL Profile** (§3.1) – target for reconstruction
- **Policy Graph / PolicyGraph** (§3.13)
- **Operation Vocabulary Map** (§3.16)
- **Filter Vocabulary Map** (§3.17)
- **Policy Lifecycle Stage** (§3.9)
- Touches: **Profile Layer** (§3.7), **Policy Stack Evaluation Order** (§3.18), **Sandbox Extension** (§3.8), **Action Modifier** (§3.6)

#### 4.4.3 Example entry points

Rendering & Analysis: `examples/re2dot/`, `examples/sbdis/`, `examples/metafilter-tests/`

#### 4.4.4 Target shared abstractions (for future filling)

- Shared renderers:
  - `to_sbpl`, `to_dot`, `summarize_operations`, `summarize_filters`.
- Hooks for profile-layer/source annotations (e.g., app vs platform).

#### 4.4.5 Open tasks (for future filling)

- Normalizing output formats across examples.
- Identifying useful “standard views” for teaching and debugging.
- Integrating policy-layer context (when/if identifiable) into renderings.
