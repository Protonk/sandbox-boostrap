>SUBSTRATE_2025-frozen
# Concepts

This document defines the core concepts that XNUSandbox and the surrounding texts rely on when talking about the macOS Seatbelt sandbox. Each entry is meant to be a stable, implementation-shaped idea (operation, filter, policy graph, profile layer, entitlement-driven parameterization, etc.), not a loose metaphor or API surface. The goal is to give tools and agents a shared set of names and roles they can use when parsing profiles, generating probes, or interpreting results. When other documents (Orientation, Appendix, State2025, Canon) use these terms, they should mean exactly what is written here; if they do not, this file is the reference that wins.


* **SBPL Profile**
  An SBPL profile is the high-level sandbox policy written in Apple’s Scheme-like sandbox DSL: it declares a version, a default decision (usually `(deny default)`), and a list of `(allow …)` / `(deny …)` rules that name operations and constrain them with filters. This is the “source code” for a Seatbelt policy that `libsandbox` parses and compiles into a binary form; it is where constructs like `file-read*`, `mach-lookup`, `subpath`, and `require-any` appear explicitly and in a way humans can read and edit.

  * **Role:** Language surface (profile definition in the SBPL DSL).
  * **Concrete handles:**

    * Text `.sb` files on disk that contain SBPL policies (system templates, app profiles, test fixtures).
    * SBPL fragments embedded in documentation, comments, or examples.
    * Input strings passed directly to `sandbox_compile_*` APIs.
  * **Validation pattern:**

    * Write a minimal SBPL profile, compile it with `libsandbox`, and confirm via probes that the resulting binary profile enforces the expected allow/deny behavior for a few operations.
    * Decode the compiled profile and verify that operations, filters, and decisions correspond to the SBPL rules.
  * **Related concepts:** SBPL Parameterization; Operation; Filter; Metafilter; Decision; Policy Lifecycle Stage; Profile Format Variant.

---

* **SBPL Parameterization**
  SBPL parameterization treats a profile as a template that expects external values. Profiles use forms like `(param "KEY")` and string operations (e.g., `string-append`) to build paths, identifiers, or other strings based on parameters supplied at compile-time or launch-time. Callers such as container managers, system services, or tools provide a parameter dictionary; if required parameters are missing, compilation fails or yields an unusable profile.

  * **Role:** Language surface / template mechanism (binding profiles to environment-provided values).
  * **Concrete handles:**

    * `(param "…")` forms and string-composition logic visible in SBPL templates.
    * Parameter dictionaries passed into `sandbox_compile_file` or related APIs.
    * Container or configuration metadata that defines keys and values for the parameters used in SBPL.
  * **Validation pattern:**

    * Author a small SBPL profile that uses `(param "FOO")` inside a path rule; attempt to compile it with and without a parameters dictionary to demonstrate failure vs success.
    * Supply different parameter values for the same SBPL and show that the compiled profile’s behavior (which paths are allowed/denied) changes accordingly.
  * **Related concepts:** SBPL Profile; Regex / Literal Table; Policy Lifecycle Stage; Binary Profile Header; Compiled Profile Source.

---

* **Operation**
  An operation is a named class of kernel action that the sandbox can control, such as `file-read*`, `file-write*`, `network-outbound`, `mach-lookup`, or `sysctl-read`. In SBPL it appears as the main verb in a rule; in compiled profiles it becomes an integer operation ID keyed into a table of entrypoints. Conceptually, an operation answers “what kind of thing is this process trying to do?” before filters and the policy graph decide whether that attempt is allowed.

  * **Role:** Policy-graph primitive (unit of “what is being attempted”).
  * **Concrete handles:**

    * Operation names in SBPL `(allow operation …)` / `(deny operation …)` forms.
    * Operation ID entries in the operation pointer table of a compiled profile.
    * Operation labels in probe results or diagnostics (“decision for `file-read*` on /path”).
  * **Validation pattern:**

    * Build a test profile that allows one operation (e.g., `file-read*`) while denying another (e.g., `file-write*`) and confirm the difference via probes that perform both actions on the same resource.
    * Decode the compiled profile and verify that operation IDs map to the expected graph entry nodes.
  * **Related concepts:** Filter; Policy Node; PolicyGraph; Operation Vocabulary Map; Decision.

---

* **Filter**
  A filter is a key–value predicate that narrows when a rule applies; it constrains an operation by path, file type, network address, process attribute, or similar metadata. In SBPL it appears inside a rule as clauses like `(subpath "/Users/…")` or `(remote tcp "127.0.0.1:…")`. In the compiled policy graph, each filter becomes a node that inspects the current operation’s arguments or context for a particular key/value and branches based on whether it matches.

  * **Role:** Policy-graph predicate (condition on an operation’s context).
  * **Concrete handles:**

    * Filter forms and arguments in SBPL (`subpath`, `literal`, `regex`, `remote`, etc.).
    * Filter key/value codes and arguments in compiled filter tables.
    * Annotated filter descriptions in decoding tools and logs.
  * **Validation pattern:**

    * Construct profiles that differ only in a single filter (e.g., `subpath "/tmp/foo"` vs `subpath "/tmp/bar"`) and show that probes observing the same operation type on different paths receive different decisions.
    * Decode the policy graph and trace the filter nodes that lie on the path to an allow/deny decision for a given operation.
  * **Related concepts:** Metafilter; Regex / Literal Table; Filter Vocabulary Map; Operation; Policy Node.

---

* **Metafilter**
  A metafilter is a logical combinator that glues filters together: constructs like `require-any`, `require-all`, and `require-not` build compound conditions over one or more underlying filter predicates. In SBPL they appear as higher-order forms that wrap other filters; in the compiled policy graph they become subgraphs that represent boolean structure (AND/OR/NOT) over filter nodes and edges.

  * **Role:** Policy-graph combinator (boolean logic over filters).
  * **Concrete handles:**

    * SBPL forms such as `(require-any (subpath …) (literal …))`, `(require-all …)`, `(require-not …)`.
    * Branching patterns in the policy graph where multiple filter nodes feed into a single decision node via AND/OR structure.
  * **Validation pattern:**

    * Create small profiles using each metafilter form and use probes to show how combinations of inputs (e.g., path + process attribute) yield different decisions under `require-any` vs `require-all` vs `require-not`.
    * Compare compiled graphs for otherwise identical profiles that differ only in the metafilter to see how graph shape changes while the basic filters remain the same.
  * **Related concepts:** Filter; Decision; Policy Node; PolicyGraph.

---

* **Decision**
  A decision is the terminal outcome of evaluating a policy graph for a specific operation and context: allow or deny, possibly with additional annotations. SBPL exposes decisions via the default policy (`(allow default)` / `(deny default)`) and explicit allow/deny rules; compiled profiles encode decisions as terminal nodes or actions reached after traversing filters and metafilters. The decision ultimately determines whether the underlying syscall succeeds or fails.

  * **Role:** Policy-graph outcome (what the sandbox finally does).
  * **Concrete handles:**

    * Default decision declarations and explicit `(allow …)` / `(deny …)` rules in SBPL.
    * Terminal decision records in the compiled graph representation.
    * Observed results of system calls in probes (success vs `EPERM`/`EACCES`) and any associated logs.
  * **Validation pattern:**

    * For a given operation, construct profiles where only the decision differs (e.g., deny vs allow with otherwise identical filters) and show that probes see the same graph path but different terminal outcomes.
    * Cross-check decoded decision nodes against observed system call results to verify that evaluation matches runtime behavior.
  * **Related concepts:** Action Modifier; PolicyGraph; Profile Layer; Policy Stack Evaluation Order.

---

* **Action Modifier**
  An action modifier is an annotation on a rule or decision that changes what “allow” or “deny” means in practice: for example, logging-only behavior, soft failure variants, or behaviors that interact with higher-level frameworks. From SBPL’s point of view, these are extra bits on top of the basic decision; in compiled form they appear as flags or action codes that alter what the kernel or cooperating subsystems actually do when the decision is reached.

  * **Role:** Policy-graph decoration (adjusts semantics of a decision).
  * **Concrete handles:**

    * SBPL constructs or annotations that distinguish plain deny from variants (e.g., quiet vs noisy, or behaviors tied to specific subsystems).
    * Action fields or flags bundled with decision records in compiled profiles.
    * Differences in logging or user-visible behavior when the same operation is denied under different profile actions.
  * **Validation pattern:**

    * Compare profiles that are identical except for action modifiers and run probes that trigger denies; observe differences in logs, error codes, or user prompts where applicable.
    * Decode decision structures to confirm that different action codes correspond to distinct runtime behaviors.
  * **Related concepts:** Decision; Policy Lifecycle Stage; PolicyGraph; Sandbox Extension.

---

* **Profile Layer**
  A profile layer describes which sandbox policy is being applied and at what level: platform/global sandbox, per-service profiles, the App Sandbox template for an individual app, and any additional or injected policies. It answers “what layer of the system does this profile belong to?” and helps explain why multiple policies might be consulted when a single process makes a system call.

  * **Role:** Lifecycle / composition concept (where a profile sits in the stack).
  * **Concrete handles:**

    * Distinct compiled profile blobs for platform, service, and app layers.
    * Metadata or naming conventions that indicate whether a profile is platform-level, app-level, or auxiliary.
    * Container and entitlement records that indicate which layers’ rules apply to a given process.
  * **Validation pattern:**

    * Identify separate platform and app profiles, then observe how the same operation behaves under each in isolation vs when both are active.
    * Use probes to show that changing a profile at one layer (e.g., app) does not override denies originating from a higher layer (e.g., platform).
  * **Related concepts:** Policy Stack Evaluation Order; Compiled Profile Source; Policy Lifecycle Stage; Sandbox Extension.

---

* **Sandbox Extension**
  A sandbox extension is a token-based capability that, when granted to a process, temporarily widens what the sandbox allows for specific resources like paths, Mach services, or containers. Instead of rewriting profiles, the system issues opaque extension tokens that Seatbelt consults alongside the static policy when deciding whether to permit an operation.

  * **Role:** Runtime mechanism (token capability that augments effective policy without changing SBPL).
  * **Concrete handles:**

    * Opaque extension tokens created and consumed via sandbox extension APIs.
    * Differences in behavior for the same operation and path before vs after applying a specific extension.
    * System logs or diagnostics that record extension issuance and use.
  * **Validation pattern:**

    * Run a probe that first attempts a restricted operation (e.g., opening a nominally denied path) and records the deny; then obtain a sandbox extension for that resource, retry the same operation, and confirm that it now succeeds without changing the underlying profile or entitlements.
    * Compare boundary objects before and after applying the extension to highlight that the only change is the presence of the token.
  * **Related concepts:** Profile Layer; Decision; Policy Stack Evaluation Order; Policy Lifecycle Stage.

---

* **Policy Lifecycle Stage**
  Policy lifecycle stage divides a sandbox policy’s existence into phases: SBPL source, compiled binary profile on disk, loaded kernel policy, and per-process application at runtime. It tracks how a policy moves from editable text to an in-kernel graph and how that evolution affects what can be inspected or changed at each step.

  * **Role:** Lifecycle concept (how policies move from source to enforcement).
  * **Concrete handles:**

    * SBPL files and embedded source in documentation or code.
    * Compiled profile blobs as stored in files or bundled into binaries.
    * Loaded kernel structures visible via debugging, tracing, or tools that query active policies.
  * **Validation pattern:**

    * Follow a test profile from SBPL text through compilation to a loaded policy, verifying at each stage that key properties (operations, filters, decisions) are preserved.
    * Modify the SBPL, recompile, and confirm that the corresponding changes appear in the compiled profile and in runtime behavior.
  * **Related concepts:** SBPL Profile; SBPL Parameterization; Binary Profile Header; Profile Format Variant; Compiled Profile Source.

---

* **Binary Profile Header**
  A binary profile header is the structured prefix of a compiled sandbox profile that records versioning, sizes, offsets, and other metadata needed to interpret the rest of the blob. It tells a decoder where to find operation tables, nodes, and literal/regex pools; it also encodes which profile format variant is in use.

  * **Role:** Binary metadata structure (entry point for decoding compiled profiles).
  * **Concrete handles:**

    * Fixed-format header fields at the start of compiled profile blobs (magic, version, section counts, offsets).
    * Differences in header layout between profile format variants and OS versions.
  * **Validation pattern:**

    * Write a parser that reads the header from several compiled profiles and confirm that the implied offsets and lengths correctly locate other sections (operation pointer table, nodes, literal table).
    * Compare headers across OS versions to infer which profile format variants are in play.
  * **Related concepts:** Profile Format Variant; Operation Pointer Table; Regex / Literal Table; PolicyGraph.

---

* **Operation Pointer Table**
  The operation pointer table is the compiled profile structure that maps each operation ID to the policy graph node where evaluation should begin for that operation. It is the bridge between “what syscall category is this?” and “which subgraph evaluates whether it is allowed.”

  * **Role:** Binary indirection table (connects operations to graph entry points).
  * **Concrete handles:**

    * Arrays or tables in the compiled profile whose entries are offsets or indices into the node array, keyed by operation ID.
    * Disassembled or decoded structures in tools that show “operation X → node index Y.”
  * **Validation pattern:**

    * Decode a compiled profile and confirm that changing SBPL rules for a specific operation causes the corresponding table entry to point to a different or modified subgraph.
    * For a given operation, trace from the table entry through the policy graph to the terminal decision, and confirm that this matches the intended SBPL semantics.
  * **Related concepts:** Operation; Policy Node; PolicyGraph; Binary Profile Header; Operation Vocabulary Map.

---

* **Policy Node**
  A policy node is a unit in the compiled policy graph: it might represent a filter test, a metafilter combination, or a terminal decision. Each node has a type and one or more outgoing edges that direct evaluation to other nodes based on whether a test passes.

  * **Role:** Policy-graph element (atomic step in evaluation).
  * **Concrete handles:**

    * Node arrays in compiled profiles, with type tags and edge indices.
    * Decoder output that lists nodes as “filter node,” “decision node,” and so on, along with their successors.
  * **Validation pattern:**

    * On a minimal SBPL profile, decode the compiled policy graph and map each node back to its SBPL origin (filter, metafilter, or decision).
    * Use probes to drive evaluation along specific paths and confirm that the dynamic behavior corresponds to traversing the expected nodes.
  * **Related concepts:** Filter; Metafilter; Decision; Operation Pointer Table; PolicyGraph.

---

* **PolicyGraph**
  PolicyGraph is the compiled policy graph: the full directed graph of policy nodes and edges produced by compiling SBPL. In prose, “the policy graph” refers to an instance of this structure. For each operation, evaluation starts at the node pointed to by the operation pointer table and walks the graph until it reaches a decision node. The graph as a whole encodes the sandbox policy in a form the kernel can evaluate quickly.

  * **Role:** Policy-graph structure (the full compiled policy for a profile).
  * **Concrete handles:**

    * Node and edge arrays in compiled profiles interpreted together as a graph.
    * Visualizations or dumps produced by decoding tools that show graph shape per operation.
  * **Validation pattern:**

    * Generate graph visualizations for small example profiles and verify that structural changes in SBPL (added filters, new rules) are reflected in the policy graph.
    * For a particular operation and input, trace the path through the policy graph taken during evaluation and confirm it ends at the expected decision.
  * **Related concepts:** Policy Node; Operation Pointer Table; Decision; Policy Lifecycle Stage; Profile Format Variant.

---

* **Regex / Literal Table**
  The regex / literal table stores string constants and pattern objects used by filters: path prefixes, exact file names, regular expressions, and other literals. In SBPL these appear as string arguments or regex forms inside filters; in compiled profiles they are pooled into dedicated tables and referenced by index.

  * **Role:** Binary data pool (shared storage for strings and patterns).
  * **Concrete handles:**

    * Tables of strings and compiled regexes in the binary profile.
    * Indices in filter records that point into these tables.
  * **Validation pattern:**

    * Create profiles whose only differences are the string or regex arguments to filters, compile them, and confirm that the literal/regex tables differ accordingly while the policy graph structure remains largely the same.
    * Decode filters and verify that their referenced literals/regexes match the SBPL source.
  * **Related concepts:** Filter; SBPL Parameterization; Filter Vocabulary Map; Profile Format Variant.

---

* **Profile Format Variant**
  A profile format variant is a concrete on-disk/in-kernel encoding layout for compiled profiles: it fixes header structure, node layouts, table formats, and section arrangements. Different OS releases or internal tools may introduce new variants while keeping the high-level SBPL semantics stable.

  * **Role:** Binary encoding concept (versioned layout of compiled profiles).
  * **Concrete handles:**

    * Version or format fields in the binary profile header.
    * Differences in section offsets, node encodings, and table structures between compiled profiles from different systems or eras.
  * **Validation pattern:**

    * Compare headers and decoded structures from multiple OS versions to map out which profile format variants exist and how they differ.
    * Ensure that decoders correctly interpret each variant by round-tripping small test profiles across OS versions.
  * **Related concepts:** Binary Profile Header; Operation Pointer Table; Regex / Literal Table; Operation Vocabulary Map; Filter Vocabulary Map.

---

* **Operation Vocabulary Map**
  The Operation Vocabulary Map is a bidirectional mapping between operation names used in SBPL (e.g., `file-read*`) and the integer operation IDs used in compiled profiles. It is maintained as repo metadata informed by Apple documentation and reverse engineering, and it may be incomplete or approximate for lesser-known operations.

  * **Role:** Metadata mapping (names ↔ IDs for operations).
  * **Concrete handles:**

    * Tables or files in the repo that list operation names, numeric IDs, and comments.
    * Cross-references in decoding tools that turn operation IDs back into readable names.
  * **Validation pattern:**

    * Decode a compiled profile and use the map to label operation entries; confirm that changing SBPL rules for a named operation affects the corresponding ID entry.
    * Where possible, cross-check against Apple documentation or empirical behavior to strengthen confidence in the mapping.
  * **Related concepts:** Operation; Operation Pointer Table; Profile Format Variant; Filter Vocabulary Map.

---

* **Filter Vocabulary Map**
  The Filter Vocabulary Map is a mapping for filter keys and their arguments: it ties numeric filter codes in compiled profiles to human-readable names like `subpath`, `literal`, or keys that address process metadata, network properties, or TCC/CSR-related state, and it describes how their arguments should be interpreted.

  * **Role:** Metadata mapping (names ↔ IDs for filter keys and argument types).
  * **Concrete handles:**

    * Repo tables that associate filter key codes with names, argument schemas, and notes.
    * Decoder logic that uses the map to turn raw filter records into annotated filter descriptions.
  * **Validation pattern:**

    * Decode filters from compiled profiles using the map and confirm that they reconstruct plausible SBPL forms (paths, regexes, process attributes, etc.).
    * Build targeted profiles that exercise specific filter keys and verify via probes that changing arguments produces expected behavior, reinforcing the mapping.
  * **Related concepts:** Filter; Regex / Literal Table; Operation Vocabulary Map; Profile Format Variant.

---

* **Policy Stack Evaluation Order**
  Policy stack evaluation order describes how Seatbelt composes multiple policy layers—platform/global profiles, per-service profiles, App Sandbox, entitlements-driven tweaks—and in what order they are consulted when a syscall occurs. The effective decision behaves like a logical AND of participating policies, with higher-priority denies able to short-circuit lower layers.

  * **Role:** Lifecycle / composition concept (how multiple policies combine at runtime).
  * **Concrete handles:**

    * Documentation and empirical traces that show which profile is consulted first and which one provides the final decision in conflicts.
    * Observed behavior where a platform-level deny persists even when an app profile appears permissive.
  * **Validation pattern:**

    * Construct scenarios where a higher-layer profile denies an operation while a lower-layer profile allows it, and confirm via probes that the deny wins.
    * Use probes to compare behavior with different combinations of profiles loaded to infer practical evaluation order for a given process.
  * **Related concepts:** Profile Layer; Decision; Sandbox Extension; Policy Lifecycle Stage; Compiled Profile Source.

---

* **Compiled Profile Source**
  Compiled profile source refers to where a given compiled policy blob came from and what it represents: a direct compilation of your own SBPL for testing, a system `.sb` file (such as an App Sandbox template or service profile), or a platform/global profile embedded in system components. Tracking the source is important for both analysis and teaching, since it tells you whether you’re looking at a toy profile, an app-level sandbox, or a piece of the platform policy, and therefore how to interpret its scope and its interaction with other layers.

  * **Role:** Metadata / provenance concept (origin and intended scope of a profile).
  * **Concrete handles:**

    * File paths or binary sections where compiled profiles are stored (test fixtures vs system bundles vs OS components).
    * Build or packaging metadata that identifies a profile as template, app-specific, service-specific, or platform-level.
  * **Validation pattern:**

    * Catalog compiled profiles by source (test, app, platform), decode each, and compare their structure and capabilities to understand typical differences in scope.
    * For a specific process, identify which compiled profiles are actually in use and how they relate to their on-disk or embedded sources.
  * **Related concepts:** Profile Layer; Policy Lifecycle Stage; Profile Format Variant; Operation Vocabulary Map; Filter Vocabulary Map.
