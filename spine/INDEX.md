# Index

What follows is an index to core substrate documents for the macOS Seatbelt sandbox project. These documents are the primary textual sources for the project’s architecture, concepts, environment, and empirical state.

Treat the files indexed here as normative: they define the model, vocabulary, and assumptions the rest of the repository is expected to follow. This index is a navigational map, not a replacement for reading the documents themselves when details matter.

## Documents

### Appendix.md

- **Path:** `substrate/Appendix.md`
- **Role:** Technical reference for Seatbelt’s SBPL language, binary profile formats, and policy graph mechanics.
- **Summary:** Describes SBPL syntax and idioms (operations, filters, metafilters, action modifiers, parameterization), then follows profiles through their compiled binary forms: headers, operation pointer tables, node arrays, literal/regex tables, and AppleMatch NFAs. It explains how entitlements and other metadata shape compiled profiles, how profiles are installed into `Sandbox.kext`, and how platform policies, app policies, and sandbox extensions stack at runtime. It also records structural invariants and highlights where formats and details are version-specific.
- **Primary topics:** SBPL syntax, binary profile formats, policy graphs, entitlements and parameterization, profile lifecycle, policy stacking

### Canon.md

- **Path:** `substrate/Canon.md`
- **Role:** Defines the fixed set of external canonical sources that underwrite the substrate’s claims about Seatbelt.
- **Summary:** Lists seven key references (papers, guides, posts) that together cover Seatbelt’s architecture, SBPL language and compiler, binary profiles, ecosystem usage, and offensive perspectives. It explains why this canon is deliberately small and frozen, how different sources cover different abstraction levels and eras, and how downstream artifacts (orientation, concepts, examples, catalog) are keyed to this set. Each source is annotated with its scope, strengths, blind spots, and guidance on when to rely on it.
- **Primary topics:** canonical sources, evidence model, architecture references, empirical studies, threat perspectives, version/time axes

### Concepts.md

- **Path:** `substrate/Concepts.md`
- **Role:** Authoritative glossary of implementation-shaped concepts used across the project when describing the macOS Seatbelt sandbox.
- **Summary:** Provides precise definitions for SBPL profiles and parameterization, operations, filters and metafilters, decisions, policy nodes and PolicyGraph, profile layers, and policy lifecycle stages. It also defines binary-level structures (headers, operation pointer tables, literal/regex tables, profile format variants) and mapping tables (operation and filter vocabulary maps), plus composition and provenance ideas like Profile Layer, Policy Stack Evaluation Order, and Compiled Profile Source. Each entry includes concrete “handles” in code or artifacts and suggested validation patterns for tying the concept back to real profiles and behavior.
- **Primary topics:** concept inventory, SBPL objects, policy graphs, profile layers, vocabulary maps, validation patterns

### Environment.md

- **Path:** `substrate/Environment.md`
- **Role:** Describes the system environment around Seatbelt: containers, structural invariants vs high-churn details, and adjacent security layers.
- **Summary:** Explains how macOS (and, by contrast, iOS) lay out per-app containers, how those directory structures shape a sandboxed app’s filesystem view, and how SBPL profiles reference container paths directly or via parameters. It distinguishes long-lived architectural invariants (Seatbelt as a MACF module, compiled policy graphs, container existence) from volatile surfaces (operation/filter inventories, entitlement lists, container subtrees, TCC taxonomy). It also sketches how TCC, hardened runtime, and SIP work structurally and how they interact with Seatbelt decisions when diagnosing why a given operation is allowed or denied.
- **Primary topics:** containers and filesystem view, structural invariants, high-churn surfaces, TCC, hardened runtime, SIP

### Orientation.md

- **Path:** `substrate/Orientation.md`
- **Role:** High-level orientation and mental model for Seatbelt’s architecture and policy lifecycle.
- **Summary:** Introduces the key moving parts—operations, filters, decisions, PolicyGraph, profile layers—and explains how Seatbelt policies flow from SBPL templates through compilation to kernel-side evaluation. It emphasizes that policies are attached to process credentials, that platform policies, app/custom policies, and sandbox extensions form a stack, and that effective decisions result from combining these layers under fixed precedence rules. It also gives working guidelines for keeping code and documentation aligned with the substrate: small explicit concept sets, clean separation of SBPL parsing vs binary decoding vs analysis, and explicit version assumptions.
- **Primary topics:** architecture and mental model, policy lifecycle, operations and filters, profile stacking, analysis discipline

### State.md

- **Path:** `substrate/State.md`
- **Role:** Snapshot of how the macOS sandbox is actually used and behaves in practice around 2024–2025.
- **Summary:** Focuses on modern macOS (13–14, primarily Apple Silicon) and describes who is sandboxed (Mac App Store apps, many Apple apps and services) versus who typically is not (most traditionally distributed desktop software). It outlines how code signing, Gatekeeper, hardened runtime, entitlements, secinit, and containermanagerd feed into Seatbelt, TCC, and SIP to form the effective security pipeline. It distinguishes structural realities from high-churn details in the current ecosystem, summarizes common patterns of entitlement use and misconfiguration, and sketches an implicit threat model and historical failure modes that justify probes, catalogs, and empirical checks.
- **Primary topics:** ecosystem state, sandbox adoption, entitlements in practice, modern pipeline, threat model, empirical variability

