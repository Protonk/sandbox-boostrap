# Concepts

- **SBPL Profile**  
  An SBPL profile is the high-level sandbox policy written in Apple’s Scheme-like Sandbox DSL: it declares a version, a default decision (usually `(deny default)`), and a list of `(allow …)`/`(deny …)` rules that name operations and constrain them with filters. This is the “source code” for a Seatbelt policy that `libsandbox` parses and compiles into a binary form; it’s where concepts like `file-read*`, `mach-lookup`, `subpath`, and `require-any` appear explicitly and in a way humans can read and edit.

- **Operation**  
  An operation is a named class of kernel action that the sandbox can control, such as `file-read*`, `file-write*`, `network-outbound`, `mach-lookup`, or `sysctl-read`. In SBPL it appears as the main verb in a rule; in compiled profiles it becomes an integer operation ID keyed into a table of entrypoints. Conceptually, an operation answers “what kind of thing is this process trying to do?” before filters and policy graphs decide whether that attempt is allowed.

- **Filter**  
  A filter is a key–value predicate that narrows when a rule applies by inspecting arguments or process/system state: path predicates (`literal`, `subpath`, `regex`), vnode properties (`vnode-type`), IPC names (`global-name`), network endpoints (`remote ip`, `remote tcp`), or metadata like `signing-identifier`, `entitlement-is-present`, and `csr`. In SBPL these appear as nested s-expressions after the operation; in the compiled graph each filter becomes a node that tests a particular key/value and branches based on whether it matches.

- **Metafilter**  
  A metafilter is a logical combinator that glues filters together using boolean structure: `require-all` (AND), `require-any` (OR), and `require-not` (NOT). They let SBPL express complex conditions like “allow file reads under `/System` that are not symlinks and either match this regex or carry a particular extension token” in a structured way. In compiled profiles, these combinators disappear as named constructs and are implemented by specific patterns of filter nodes and edges in the policy graph.

- **Decision**  
  A decision is the terminal outcome of evaluating a policy graph for a given operation and set of arguments: typically “allow” or “deny”, possibly decorated with flags like “log this” or “defer to user consent”. In SBPL it’s implicit in the `(allow …)` or `(deny …)` form; in the compiled graph it appears as a terminal node or encoded result code that ends traversal. When the kernel walks the graph for an operation, the decision node it lands on determines whether the underlying syscall succeeds or fails.

- **Action Modifier**  
  An action modifier is an annotation on a rule that changes what happens when it matches without changing the basic allow/deny verdict, such as `(with report)` for extra logging or user-consent modifiers that integrate with TCC. They appear in SBPL as a wrapper around the operation, e.g. `(allow (with report) sysctl …)`, and in compiled form as additional flags or fields attached to decision nodes. Conceptually, they encode side effects like “log this event” or “ask the user” layered on top of the permit/deny outcome.

- **Profile Layer**  
  A profile layer describes which sandbox policy is being applied in the multi-layer system: the global **platform** policy that applies to almost all processes, per-process policies like App Sandbox or custom profiles attached via `sandbox_init*`, and any other Seatbelt profiles. The conceptual model is that multiple layers can apply to a single operation, with platform policy evaluated first and per-process policy next; thinking in terms of layers helps keep straight where a particular rule lives and why a decision was made.

- **Sandbox Extension**  
  A sandbox extension is a token-based capability that, when granted to and consumed by a process, temporarily widens what its sandbox allows for specific resources like paths, Mach services, or containers. Instead of rewriting profiles, trusted system components issue opaque extension strings that the sandbox policy recognizes via `extension` filters and uses to grant narrowly scoped exceptions. Extensions bridge static SBPL rules and dynamic, per-request access decisions driven by components like tccd or Launch Services.

- **Policy Lifecycle Stage**  
  Policy lifecycle stages are the distinct forms a sandbox policy takes from authoring to enforcement: (1) SBPL source text written in the sandbox DSL, (2) the `libsandbox` / TinyScheme intermediary representation (often exposed as a per-operation rules vector), (3) the compiled binary profile blob (header, operation tables, node graph, regex/literal tables), and (4) the in-kernel evaluation of that blob via MAC hooks at syscall time. Separating these stages helps you reason about which tools and formats are involved at each step.

- **Binary Profile Header**  
  The binary profile header is the fixed-layout structure at the start of a compiled profile blob that records format/version information and the offsets and counts for all major sections: operation pointer table, node array, regex pointer table, literal/regex data, and, in bundled formats, per-profile descriptors. It’s the entry point for any decoder: reading the header tells you how many operations there are, where to find each section, and which variant of the format you’re dealing with.

- **Operation Pointer Table**  
  The operation pointer table is an array indexed by operation ID where each entry is an offset or index into the policy node array for that operation’s rule graph. Instead of giving each operation a separate block, the compiled profile often stores all nodes in a single array and uses this table as the set of entrypoints. When decoding, you start from the pointer for a given operation and follow nodes until you reach a decision; without this table, all you have is an undifferentiated node heap.

- **Policy Node**  
  A policy node is an individual element in the compiled policy graph: either a non-terminal filter node that tests a specific key/value and has “match” and “unmatch” successors, or a terminal decision node that encodes allow/deny (and possibly logging/consent flags) and ends traversal. The entire policy is built from these nodes, with operations selecting starting nodes via the op-pointer table and filters/metafilters emerging from how nodes and successors are wired together.

- **Policy Graph / PolicyGraph**  
  A policy graph (often modeled as a `PolicyGraph` type) is the full, per-profile representation of how operations, filters, metafilters, and decisions connect: for each operation ID, an entrypoint into a directed graph of policy nodes. Conceptually, it’s the canonical internal form for analysis and tooling: once you’ve turned a profile blob into a PolicyGraph, you can render it as SBPL-like rules, visualize subgraphs, test reachability for certain decisions, or compare different profiles structurally.

- **Regex / Literal Table**  
  The regex/literal table is the shared pool of string data and serialized regex NFAs referenced by filters in the policy graph. Rather than embedding full paths or patterns in nodes, compiled profiles store them once in a combined literals/regex section and have filter nodes hold small indices into this table. Decoding these tables lets you turn abstract “filter key = path, value index = 17” back into concrete expressions like `(literal "/bin/ls")` or `(regex #"^/Users/[^/]+/Documents")` in reconstructed SBPL.

- **Profile Format Variant**  
  A profile format variant is a concrete on-disk/in-kernel encoding of compiled policies, such as the early decision-tree format (simple handler records with terminal/non-terminal opcodes) and the later graph-based formats (operation pointer tables plus shared node arrays and regex tables), including bundled multi-profile blobs used on newer systems. Each variant uses the same conceptual building blocks—operations, filters, nodes, graphs—but with different headers, node layouts, and section arrangements that decoders must handle explicitly.

- **Operation Vocabulary Map**  
  The Operation Vocabulary Map is the bidirectional mapping between numeric operation IDs used in compiled profiles and the human-readable operation names used in SBPL, like `file-read*` or `mach-lookup`. It’s essential for turning anonymous graphs into understandable output and for targeting analysis to specific behaviors; in practice it’s built from `libsandbox` strings, system SBPL profiles, and observed behavior, and must track which mappings are confirmed, inherited from older reversals, or still unknown on a given OS version.

- **Filter Vocabulary Map**  
  The Filter Vocabulary Map is the similar mapping for filter keys and their encoded values: from numeric filter key IDs and packed representations (enums, indices, bitfields) in nodes to names and semantics like `literal`, `subpath`, `vnode-type`, `global-name`, `signing-identifier`, `entitlement-is-present`, and so on. It underpins meaningful reconstruction of SBPL filters from raw nodes and allows tools to group and reason about filters by category (path-based, Mach, network, process metadata, CSR/TCC-related) rather than by opaque integers.

- **Policy Stack Evaluation Order**  
  Policy stack evaluation order describes how Seatbelt composes multiple policies when a sandbox-relevant operation occurs: the platform policy is evaluated first, then any per-process profile (App Sandbox or custom), and the final decision is the logical AND of all participating MAC policies (including non-Seatbelt ones). Understanding this order matters because a deny in the platform profile short-circuits per-process rules, and because some constraints that look “mysterious” at the SBPL level may actually live in a different layer of the stack.

- **Compiled Profile Source**  
  Compiled profile source refers to where a given compiled policy blob came from and what it represents: a direct compilation of your own SBPL for testing, a system `.sb` file (e.g., App Sandbox templates or service profiles), or a platform/global profile embedded in system components. Tracking the source is important for both analysis and teaching, since it tells you whether you’re looking at a toy profile, an app-level sandbox, or a piece of the platform policy, and therefore how to interpret its scope and interaction with other layers.