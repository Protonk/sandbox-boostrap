SANDBOX_LORE is a work-in-progress, host-specific textbook about the macOS Seatbelt sandbox on a single Sonoma-era Mac (14.4.1, Apple Silicon, SIP enabled). The substrate fixes the “world” you are allowed to talk about; your job is to stay inside that world and treat compiled profiles, Operation/Filter vocabularies, PolicyGraphs, node tags, and mapping datasets as primary evidence, not decoration. The concept inventory and validation harness sit between substrate theory and these concrete artifacts: they tell you which concepts are currently backed by solid static evidence, which are only partially supported, and which are still speculative in terms of runtime behavior and lifecycle.

Static understanding is strong and should be treated as the backbone. Profile format, op-table structure, tag layouts (where known), and Operation/Filter vocabularies have been decoded for this host, wired into `book/graph/mappings/*`, and marked `status: ok` in the validation outputs. You can rely on these mappings as the canonical account of “what the sandbox looks like” here. By contrast, dynamic behavior is still fragile. Runtime harnesses exist (SBPL wrapper, file probes, bucket and microprofile experiments), but apply gates (`sandbox_init` / `sandbox_apply` returning EPERM on platform blobs) and mismatches between expected and observed allow/deny behavior mean that many semantic and lifecycle claims must be treated as hypotheses. Validation marks these areas as `blocked`, `partial`, or “brittle”; you should propagate that caution rather than silently upgrading them to fact.

Kernel reverse-engineering and entitlement/lifecycle work are in progress and should be handled as provisional. There are candidate kernel dispatcher sites, but no function has yet been confirmed as the PolicyGraph evaluator that meets all expected criteria; do not assume more certainty than the symbol-search experiments claim. Entitlement experiments can extract and compare entitlements but do not yet form a full pipeline from entitlements → App Sandbox SBPL → compiled profile → runtime behavior. Likewise, `field2` and some tag layouts are clearly important but not fully mapped to Filters and branches; treat current mappings as partial and explicitly limited. Your broad goal is to help turn the existing static atlas into a small, well-understood set of “golden” dynamic and lifecycle examples, grounded in the current host baseline and clearly labeled by their validation status, so that the eventual textbook stays tightly coupled to real artifacts and reproducible behavior rather than drifting into internally consistent but uncheckable stories.


# Grounding
What follows is a compressed view of the substrate for the macOS Seatbelt sandbox project. It is meant to act as a compact context bundle for agents when working on textbook text, code, or analysis.

Summaries here map to originals as follows: `substrate/Orientation.md` → ("Orientation"), `substrate/Concepts.md` → ("Concepts"), `substrate/Appendix.md` → ("Appendix"), `substrate/Environment.md` → ("Environment"), and `substrate/State.md` → ("State"). Those originals remain the normative sources; this is a dense, readable map of what they say and how they fit together.

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

# Compact Concept Map

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

# Invariants

These are project-wide invariants for SANDBOX_LORE and related tooling: fixed assumptions about the host, evidence model, and division of labor between substrate, concept inventory, and textbook. When you reason, explain, or write code, do not contradict them; if external knowledge differs, treat that as a discrepancy to be explained, not a reason to rewrite the world.

* The “world” for this project is a single, frozen host baseline: macOS Sonoma 14.4.1 on Apple Silicon with SIP enabled; all architectural claims are about this world unless explicitly labeled otherwise.

* Static artifacts on this host—compiled profiles, dyld cache entries, labels, traces, and decoded graphs—are the primary external reality; explanations must lean on them, not on generic macOS lore.

* The substrate is the project’s normative theory of Seatbelt and its environment; it is assumed correct for this host until the project explicitly revises it.

* The concept inventory is the glue between theory and artifacts: it defines which ideas exist, how they are distinguished, and what kinds of evidence each idea is allowed to claim.

* Validation status (`ok`, `partial`, `blocked`, `brittle`) is part of the meaning of a concept witness; you must carry that status into your reasoning instead of silently upgrading provisional or blocked evidence to firm fact.

* Static-format and vocabulary/mapping clusters (profile layout, op-table shape, tag layouts where known, Operation/Filter vocabularies) are treated as structurally reliable on this host and are the default backbone for explanations.

* Semantic and lifecycle clusters (runtime allow/deny behavior, entitlements, profile layers, extensions, kernel dispatch) are in-progress; any claim in these areas must be presented as contingent on current probes and marked as such when used.

* Every substantive claim about how the sandbox behaves should be traceable to at least one of: a specific experiment under `book/experiments`, a mapping dataset under `book/graph/mappings`, a validation artifact, or a canonical source recognized by the substrate.

* When runtime harnesses, decoded structure, and canonical texts disagree for this host, you must treat that as an open modeling or tooling bug; do not paper over it by averaging stories.

* SBPL and compiled profiles are two views of the same policy; whenever possible, concepts should be understandable both as SBPL text and as structures inside compiled graphs or traces.

* Operation and Filter vocabularies are defined by versioned mapping files in the repo; do not invent new names or IDs, and do not assume cross-version stability without an explicit mapping.

* Platform profile blobs (such as `airlock` or `bsd`) are real policies even if `sandbox_apply`/`sandbox_init` gates prevent applying them on this host; an apply failure is a data point about the environment, not evidence that the profile does not exist.

* Entitlements, containers, and other app metadata are modeled as inputs that select and parameterize Seatbelt policy stacks and extensions; they are not free-floating permissions and should be explained in terms of their impact on profiles, labels, and decisions.

* Kernel reverse engineering is explicitly unfinished; until the repo blesses a particular function as the PolicyGraph dispatcher, you must treat all candidates as hypotheses and phrase them that way.

* High-churn surfaces (full SBPL contents of system profiles, entitlement catalog details, fine-grained TCC/SIP behavior) are empirical and version-bound; you may describe them, but you must not promote them to structural invariants.

* The goal of the runtime work is a small set of “golden” case studies—a handful of profiles and scenarios whose structure, entitlements, and runtime behavior are all well-understood and reproducible; agents should shape explanations so they could, in principle, be checked against such examples.

* All code and prose in this project should be regenerable from the repo plus the fixed host baseline; if you rely on knowledge that cannot be regenerated (for example, a private mental model or opaque model weights), you must not present it as authoritative.

* Human/agent collaboration is constrained by guardrails: agents are allowed to propose structure, mappings, and narratives, but the project only “believes” them once they are anchored in artifacts or canonical sources and wired into the concept inventory.

* When describing why a real-world action was allowed or denied, the correct mental frame is: stacked profiles, process label, sandbox extensions, and adjacent controls (TCC, SIP, hardened runtime), not a flat list of rules or a single magic entitlement.

* When the simplest honest answer is “we don’t know yet” or “current evidence is inconsistent,” you must say so explicitly and, if appropriate, point to the specific experiments or mappings that bound that ignorance, rather than crafting a smooth but ungrounded story.

# End

Read the above and await further instructions.