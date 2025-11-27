This conversation is grounded in a frozen documentation substrate about Apple’s macOS “Seatbelt” sandbox and a synthetic textbook being built from it. Treat what follows as the shared context for answering questions, proposing text, or analyzing behavior within that sandbox world.

# Grounding
>This spine summarizes substrate version SUBSTRATE_2025-frozen

What follows is a compressed view of the substrate for the macOS Seatbelt sandbox project. It is meant to act as a compact context bundle for agents when working on textbook text, code, or analysis.

Summaries here map to originals as follows: `substrate/Orientation.md` → ("Orientation"), `substrate/Concepts.md` → ("Concepts"), `substrate/Appendix.md` → ("Appendix"), `substrate/Environment.md` → ("Environment"), and `substrate/State.md` → ("State"). Those originals remain the normative sources; this file is a dense, readable map of what they say and how they fit together.

## Orientation

Orientation’s role is to give a mental model of Seatbelt: what the sandbox “is,” how policies flow from SBPL to kernel decisions, and how to think about stacked profiles and operations.

It introduces the main moving parts—operations, filters, policy graphs, profile layers—and sketches the four-stage policy lifecycle from SBPL template to installed kernel policy. It explains how Seatbelt attaches policy to process credentials, how platform and per-process policies combine with sandbox extensions, and how to reason about a single operation by walking the relevant policy graphs and applying precedence rules. It also sets expectations for how tooling in this repo should be structured: clean separation between SBPL parsing, binary profile decoding, and higher-level analysis, with explicit version assumptions and reliance on the Appendix and Concepts docs for precise vocabulary.

What this document gives you:
- A narrative overview of Seatbelt’s architecture and policy lifecycle.
- The basic vocabulary for operations, filters, decisions, policy graphs, and profile layers.
- A picture of how platform, app, and custom profiles stack with sandbox extensions at enforcement time.
- A method for analyzing a particular denied/allowed operation using graphs and precedence rules instead of flat rule lists.
- Working discipline for writing code and documentation that stay aligned with the substrate (small concept set, clear separation of concerns, explicit versioning).

## Concepts

Concepts defines the core terminology the rest of the project uses when talking about Seatbelt: language-level objects, binary structures, and composition ideas that all other docs and tools are expected to share.

It gives precise definitions for SBPL profiles and parameterization, operations, filters, metafilters, decisions, policy nodes and graphs, profile layers, and the policy lifecycle stages. It also introduces binary-oriented notions such as binary profile headers, operation pointer tables, regex/literal tables, and profile format variants, along with mapping structures like operation and filter vocabulary maps. For composition and provenance, it defines Profile Layer, Policy Stack Evaluation Order, Compiled Profile Source, and related concepts that describe where a profile comes from and how multiple profiles combine at runtime. Each concept is paired with concrete “handles” (what to look at in code or artifacts), validation patterns, and links to related concepts.

What this document gives you:
- Stable, implementation-shaped definitions for the main Seatbelt concepts (SBPL, operations, filters, policy graphs, profile layers).
- A structured view of binary profiling pieces (headers, node arrays, pointer tables, literal/regex tables, format variants).
- Names and roles for mapping structures (operation and filter vocabulary maps) that connect symbolic names to numeric encodings.
- A model for profile provenance and composition via Compiled Profile Source, Profile Layer, and Policy Stack Evaluation Order.

## Appendix

Appendix is the technical reference: it spells out SBPL syntax and patterns, binary profile formats, policy graph structure, entitlements and parameterization, compiled profile sources, and policy stacking details.

It starts with a cheatsheet for SBPL, including core forms, operations, filters, metafilters, and action modifiers, and how profiles are templated with `(param ...)`. It then walks through binary profile formats: early decision-tree layouts, later graph-based layouts, and modern bundled `.sb` profiles, detailing headers, operation pointer tables, node encodings, regex/literal tables, and AppleMatch NFA handling. Later sections describe how profiles move from SBPL templates through entitlements and parameters into compiled graphs, how entitlements act as capability selectors and profile parameters, how compiled policies are installed and attached to process labels, and how platform vs app profiles and sandbox extensions combine to form an effective policy stack. It also covers the role of operation/filter vocabulary maps and the structural invariants that decoding and capability catalogs rely on.

What this document gives you:
- A concise but concrete reference for SBPL syntax, including parameterization and metafilter composition.
- Detailed descriptions of binary profile formats and policy graphs, including node layouts, pointer tables, and regex storage.
- A lifecycle pipeline from signed binaries and entitlements through profile compilation, kernel installation, and runtime evaluation.
- An explanation of how entitlements, containers, and SBPL parameters interact to yield concrete profiles.
- A structural view of platform vs app profiles and sandbox extensions, as seen in the kernel’s policy stack.

## Environment

Environment describes the context around Seatbelt: how containers and filesystem views are laid out, which parts of the system are stable vs high-churn, and how adjacent security layers (TCC, hardened runtime, SIP) interact with sandboxing.

It explains the macOS container model: per-app directories under `~/Library/Containers/<bundle>/` with `Data/Documents`, `Data/Library`, and `Data/tmp` subtrees, and how SBPL filters reference these paths directly or via parameters. It contrasts macOS and iOS container behavior and timing, emphasizing that container roots are stable enough to be structural, even if subdirectories and symlinks move around. It then distinguishes structural invariants (Seatbelt as a MACF module in `Sandbox.kext`, compiled policy graphs, per-process labels, container existence) from high-churn surfaces (exact entitlements, operation/filter inventories, container subdirectory details, TCC taxonomy). Finally, it sketches TCC’s consent model, hardened runtime’s code-signing constraints, and SIP’s protection of system paths and platform binaries, and shows how these layers sit beside or on top of Seatbelt decisions.

What this document gives you:
- A concrete mental model of macOS containers and how they shape a sandboxed app’s filesystem view.
- Clarity about which aspects of Seatbelt and its environment are treated as architectural invariants vs version-specific details.
- Short structural summaries of TCC, hardened runtime, and SIP, and how they add extra gates beyond the sandbox allow/deny graph.
- A layered view of how code signing, Seatbelt, TCC, and SIP combine when diagnosing why a given operation fails or succeeds.

## State

State summarizes how the macOS sandbox actually shows up in the wild around 2024–2025: who is sandboxed, how the pipeline from signing to containers looks today, and which parts of the ecosystem are stable vs volatile.

It notes that the snapshot targets macOS 13–14 on Apple Silicon and that Seatbelt’s core architecture (TrustedBSD MACF module, SBPL-compiled profiles, operation-driven graph evaluation) remains intact, while the surrounding systems (code signing, hardened runtime, TCC, containermanagerd) have evolved. It highlights the distribution split: Mac App Store apps are overwhelmingly sandboxed, while most non-store apps remain unsandboxed and instead rely on code signing, TCC, and user-granted “Full Disk Access.” It describes Apple’s own mix of sandboxed and unsandboxed system processes and helpers, including tightly scoped profiles and private entitlements, and contrasts macOS’ mixed ecosystem with iOS’ near-universal sandboxing. Later sections map the modern pipeline (Gatekeeper, secinit, entitlements, containermanagerd, Seatbelt, TCC, SIP), summarize structural invariants and high-churn surfaces, and outline an implicit threat model and historical failure modes that motivate empirical probing and capability catalogs.

What this document gives you:
- A current picture of where Seatbelt is actually applied (MAS apps, system services) vs where it is not (most traditional desktop software).
- A modern view of the sign→secinit→container→Seatbelt→TCC→SIP pipeline for sandboxed processes.
- Evidence-backed distinctions between structural facts (e.g., presence of containers, role of entitlements) and volatile details (exact profiles and entitlements).
- A high-level threat and practice model for how Seatbelt, entitlements, TCC, and hardened runtime are used, misused, and occasionally bypassed.

## Compact Concept Map

- **SBPL profile** – High-level sandbox policy written in Apple’s Scheme-like DSL, declaring a version, default decision, and ordered allow/deny rules over operations with filters; this is the human-editable “source” that `libsandbox` compiles. (Concepts, Appendix)

- **SBPL parameterization** – Treatment of profiles as templates using `(param ...)` and string combinators, instantiated at compile or launch time with entitlements and metadata such as container roots and bundle IDs. (Concepts, Appendix, Orientation)

- **Operation** – Named class of kernel action (e.g., `file-read*`, `mach-lookup`, `network-outbound`) that Seatbelt mediates, represented as symbols in SBPL and numeric IDs in compiled profiles. (Concepts, Appendix, Orientation)

- **Filter** – Key–value predicate on operation arguments or process/OS state (paths, vnode types, network endpoints, identities, entitlements, extensions) that narrows when a rule applies. (Concepts, Appendix, Orientation)

- **Metafilter (require-any/all/not)** – Logical combinators that build compound conditions over filters; explicit forms in SBPL, recovered from graph patterns in compiled profiles. (Concepts, Appendix, Orientation)

- **Decision and action modifiers** – Terminal allow/deny verdicts in the policy graph, optionally decorated with modifiers that affect logging, reporting, or user-visible behavior. (Concepts, Appendix, Orientation)

- **Policy node** – Individual node in the compiled policy graph representing either a filter test (with match/unmatch edges) or a decision (with outcome and flags). (Concepts, Appendix)

- **PolicyGraph** – The compiled graph representation of a profile, composed of nodes and edges plus supporting tables, where each operation has an entrypoint into the graph. (Concepts, Appendix, Orientation)

- **Binary profile header** – Top-level metadata for a compiled profile: magic, version, counts, and offsets to sections such as operation pointer tables, node arrays, and literal/regex tables. (Concepts, Appendix)

- **Operation pointer table** – Array that maps operation IDs to entry nodes in the policy graph, acting as the bridge between operation vocabulary and graph structure. (Concepts, Appendix, Orientation)

- **Regex / literal table** – Shared storage for string constants and compiled regex NFAs used by filters, indexed by small integers in filter records. (Concepts, Appendix)

- **Profile format variant** – Specific on-disk/in-kernel encoding layout for compiled profiles (headers, node formats, section arrangements) that varies across OS releases but preserves SBPL-level semantics. (Concepts, Appendix)

- **Operation vocabulary map** – Mapping between SBPL operation names and numeric operation IDs used in compiled profiles, maintained per-OS-version for decoding and capability catalogs. (Concepts, Appendix, State)

- **Filter vocabulary map** – Mapping between filter key codes and human-readable filter names plus argument schemas, used to reconstruct SBPL-like descriptions from raw filter records. (Concepts, Appendix)

- **Profile layer** – Classification of profiles by role in the stack: platform/global policies, app-specific/App Sandbox profiles, auxiliary or helper profiles; answers “which part of the system does this profile belong to?” (Concepts, Appendix, Orientation, Environment)

- **Policy Stack Evaluation Order** – Rules for how multiple profile layers and sandbox extensions are evaluated and combined when a syscall occurs, with higher-priority denies dominating lower-level allows. (Concepts, Appendix, Orientation)

- **Compiled Profile Source** – Provenance of a compiled policy blob, distinguishing between platform bundles, App Sandbox templates, custom sandbox(7) profiles, and test/harness profiles. (Concepts, Appendix, State)

- **Sandbox extension** – Opaque token attached to process labels that grants narrow, dynamic exceptions (e.g., user-selected files or volumes) beyond the base profile, checked by dedicated filters in the policy graph. (Concepts, Appendix, Environment, Orientation)

- **Container** – Per-app filesystem subtree (on macOS, under `~/Library/Containers/<bundle>/Data/...`) that provides a default private read/write area, frequently referenced in SBPL via literal paths or parameters. (Environment, Appendix, State)

- **Entitlement** – Key–value claim embedded in a code signature that both influences which profile is selected/parameterized and may appear directly in filters; primary way for apps to request capabilities. (Concepts, Appendix, Environment, State)

- **Platform binary** – Apple-signed binaries that have special platform status and may receive different entitlements, SIP treatment, and sandbox profiles than third-party apps. (Environment, State)

- **TCC service** – Higher-level capability (camera, microphone, photos, screen recording, etc.) governed by Transparency, Consent, and Control; enforced via per-app approval databases in addition to sandbox rules. (Environment, State)

- **Hardened runtime** – Code-signing mode that adds constraints on code execution and enables certain sensitive entitlements, operating alongside Seatbelt rather than replacing its policies. (Environment, State)

- **System Integrity Protection (SIP)** – Kernel-level protection of specific filesystem paths and operations, creating “no, even if sandbox allows” decisions for non-privileged or non-platform processes. (Environment, State)

- **Seatbelt label / credential state** – Per-process MACF label data that stores references to active profiles and sandbox extensions; the kernel consults this state when enforcing sandbox decisions. (Concepts, Appendix, Orientation, State)

- **Capability catalog** – Structured representation of what operations, filters, entitlements, and extensions a process or profile encompasses, grounded in the substrate and intended for comparison and risk analysis. (Concepts, Appendix, State)

## How to Use This Spine

The spine is a summary, not a replacement for the substrate. When something matters for correctness or seems ambiguous, follow the pointers back to `Orientation.md`, `Concepts.md`, `Appendix.md`, `Environment.md`, or `State.md` and treat the originals as authoritative.

# Invariants

The following points are project-wide invariants: fixed assumptions about Seatbelt’s architecture, terminology, and modeling that other texts and tools in this project rely on. When you reason, explain, or write code for this project, do not contradict them; if external knowledge differs, follow these invariants and at most note the discrepancy.

* Seatbelt is implemented as a TrustedBSD MAC policy inside `Sandbox.kext` that mediates sensitive operations via internal policy graphs.

* Seatbelt mediates kernel operations by consulting compiled policy graphs keyed by operation identifiers, not by interpreting SBPL at runtime.

* SBPL is the primary sandbox policy language; it is a Scheme-like DSL compiled by a TinyScheme-derived interpreter in `libsandbox`.

* SBPL policies are expressed in terms of operations, filters, and metafilters, and these map directly onto structures in the compiled policy graph.

* Compiled profiles are binary policy graphs consisting of a header, an operation pointer table, a node graph, and shared literal/regex tables, with format variants across OS versions.

* Each operation class (for example, `file-read*`, `mach-lookup`, `network-outbound`) has a numeric ID and an entrypoint into the compiled graph; decisions are taken by traversing that graph for the operation.

* Sandbox decisions conceptually consist of an allow/deny verdict plus optional action modifiers, derived from the path taken through the policy graph for a given operation and context.

* The effective sandbox for a process is a stack of policies (platform profiles, app/custom profiles, optional auxiliary policies) plus sandbox extensions, evaluated with a fixed precedence where stronger denies dominate allows.

* Sandbox extensions act as a third dimension that grants narrowly scoped additional rights without changing the underlying profiles, and they are attached to process labels as opaque tokens consumed by filters.

* Every sandboxed process has a Seatbelt label in the kernel that encodes its active profiles and sandbox extensions; enforcement decisions are made against this label, not per-thread ad hoc state.

* The App Sandbox model provides each sandboxed app with a dedicated container directory, which defines the default filesystem view for that app.

* Access to files outside the container is widened primarily via sandbox extensions (for example, when the user picks a file in an open/save panel), not by permanently broadening the base profile.

* TCC, hardened runtime, and SIP are separate but adjacent security layers: they are not part of Seatbelt profiles but their decisions intersect with Seatbelt’s, and can veto operations even when Seatbelt would allow them.

* The high-level Seatbelt architecture—SBPL policies compiled into graph-based binary profiles enforced by `Sandbox.kext` against process labels—has remained stable from macOS 10.x through at least macOS 13–14.

* The existence and centrality of containers, entitlements, TCC, hardened runtime, and SIP as major components of Apple’s security stack are treated as stable facts for this project.

* High-churn surfaces include the exact SBPL contents of system profiles, the entitlement catalogue, detailed TCC service taxonomy and defaults, container layout minutiae, and fine-grained hardened-runtime/SIP rules; these are explicitly not treated as invariants.

* Any claim about high-churn surfaces must be versioned (by OS / build) and preferably backed by probes and logs; such claims remain empirical observations, not structural assumptions.

* `SUBSTRATE_2025-frozen` is the normative description of Seatbelt and its environment for this project; where external sources disagree, the substrate wins unless it is intentionally revised.

* The canon consists of exactly seven sandbox-related sources, which are treated as the primary external evidence for Seatbelt architecture and behavior in this substrate version.

* New information beyond the canon is incorporated via explicitly versioned deltas (for example, updated State documents or new substrate versions) rather than by silently rewriting canonical claims.

* `Concepts.md` defines the authoritative vocabulary and distinctions for this project; all code, documentation, and analysis should use these terms consistently.

* Each core concept (for example, SBPL Profile, PolicyGraph, Operation, Filter, Metafilter, Policy Stack Evaluation Order, Sandbox Extension) must be interpretable both at the SBPL text level and at the compiled/binary or trace level.

* Conceptual claims in substrate documents should be anchored in empirical artifacts (profiles, binaries, traces, probes) or canonical sources; ungrounded speculation is out of scope for the substrate.

* XNUSandbox’s role is strictly to decode and explain sandbox-related artifacts (SBPL, compiled profiles, labels) and to present a stable conceptual IR; it is not an enforcement engine, syscall interceptor, or TCC/hardened-runtime implementation.

* XNUSandbox targets the modern graph-based profile formats used on current macOS, but its internal IR is concept-driven in a way that should tolerate reasonable changes in binary layout.

* Tools and tests in this project should reason about sandbox behavior using the small concept set (operations, filters, metafilters, decisions, policy graphs, labels, containers, extensions, entitlements) rather than introducing unrelated ad-hoc notions.

* Capability catalog entries must be expressible in terms of underlying Seatbelt constructs (operations, filters, profiles, extensions, containers, entitlements, adjacent controls), not purely in terms of user-visible feature labels.

* When explaining or debugging a real-world decision, the correct mental model is a combination of stacked policies, process label, sandbox extensions, and adjacent controls, not a single flat SBPL rule list.

* macOS and iOS share a common container-centric, entitlement-driven sandbox model; platform differences are treated as variations in defaults and coverage on top of that shared structure.

* For the synthetic textbook, worked examples (such as TextEdit’s sandbox on a specific macOS release) are binding demonstrations of how the concepts map to real code and behavior; disagreements are resolved in favor of those examples plus the substrate.

## Context end

That’s the end of the shared context for this conversation. Everything above defines the sandbox world we are working inside.