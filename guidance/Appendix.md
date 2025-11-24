# Sandbox DSL Cheatsheet

This section is a compact reference for Apple’s Sandbox Profile Language (SBPL) as it appears in macOS/iOS Seatbelt. It focuses on the patterns you will see in XNUSandbox output and related tooling, not the full Scheme language.

---

## 1. SBPL at a Glance

A minimal SBPL profile looks like:

```scheme
(version 1)
(deny default)

(allow file-read* (path "/tmp/foo") (subpath "/tmp/bar"))
(allow (with report) sysctl (sysctl-name "kern.hostname"))
(allow file-write-create*
  (require-all
    (require-not (vnode-type SYMLINK))
    (subpath "/tmp/no-symlinks")))
```

Key observations:

* `(version 1)` declares the profile version.
* `(deny default)` sets the default decision for all operations not otherwise matched. Most real profiles are “default deny” and then whitelist specific permissions.
* Rules are expressed via `(allow …)` or `(deny …)`; each rule names:

  * An operation (e.g., `file-read*`, `sysctl`, `file-write-create*`).
  * Optional action modifiers (e.g., `(with report)`).
  * Zero or more filters (predicates) that must match for the rule to apply.

---

## 2. Top-Level Structure

Typical top-level forms:

* Version:

  ```scheme
  (version 1)
  ```

* Default decision:

  ```scheme
  (deny default)
  ;; or less commonly:
  (allow default)
  ```

  The default operation’s decision applies when no other rule’s filters match for a given operation. In practice, almost all built-in profiles are default-deny.

* Operation rules:

  ```scheme
  (allow OPERATION [FILTER ...])
  (deny  OPERATION [FILTER ...])
  (allow (with ACTION-MODIFIER ...) OPERATION [FILTER ...])
  ```

Each `(allow|deny)` applies to a named operation and is guarded by zero or more filters or metafilters (see below).

---

## 3. Operations

An operation in SBPL is a symbolic name that corresponds to one or more kernel actions (syscalls / hooks). Examples:

* Filesystem:

  * `file-read*`, `file-read-data`, `file-read-metadata`
  * `file-write*`, `file-write-create*`, `file-write-data`
* Networking:

  * `network-outbound`, `network-inbound`, sometimes `network*`
* IPC / services:

  * `mach-lookup`, `mach-register`, `ipc-posix-shm`
* System info:

  * `sysctl`, `sysctl-read`
* Process-related:

  * `process-fork`, `process-exec`, `signal`

At the SBPL level, operations are just symbols. The mapping from symbol → numeric operation ID lives in `libsandbox.dylib` and in the compiled profile format that XNUSandbox parses.

For a fuller discussion of operation families, see the “Operations and Filters Reference” section.

---

## 4. Filters (Key–Value Predicates)

A filter narrows the applicability of a rule. Conceptually:

```scheme
(allow OPERATION
  (FILTER-KEY FILTER-VALUE ...)
  (FILTER-KEY2 FILTER-VALUE2 ...))
```

At the binary level, a filter is a key–value pair, where both key and value are encoded as small integers that index shared tables.

Representative filters you will see (names approximate but aligned with Apple profiles and reversing notes):

### 4.1 Path-based filters (filesystem)

* Exact path:

  ```scheme
  (path "/exact/path")
  (literal "/bin/secret.txt")
  ```

* Prefix / tree:

  ```scheme
  (subpath "/Applications/MyApp.app")
  (subpath "/private/var/mobile/Containers/Data/Application")
  ```

* Regex on path:

  ```scheme
  (regex #"/bin/.*")
  (regex #"^/Users/[^/]+/Documents")
  ```

* Vnode type:

  ```scheme
  (vnode-type REGULAR-FILE)
  (vnode-type DIR)
  (vnode-type SYMLINK)
  ```

These show up heavily in file-related operations (`file-read*`, `file-write*`, etc.).

### 4.2 Network filters

Examples:

* Remote address / IP:

  ```scheme
  (remote ip "127.0.0.1")
  ```

* Remote TCP:

  ```scheme
  (remote tcp "localhost:22")
  ```

These correspond to lower-level `socket-local` / `socket-remote` filter keys in the binary format. SBPL spells them in a more human-readable form.

### 4.3 Other common filters

* `sysctl-name`:

  ```scheme
  (sysctl-name "kern.hostname")
  ```

* Sandbox extensions:

  ```scheme
  (extension "com.apple.app-sandbox.read")
  (extension "com.apple.sandbox.container")
  ```

* Process / signing predicates (in platform / App Sandbox profiles):

  ```scheme
  (signing-identifier "com.example.myapp")
  (entitlement-is-present "com.apple.security.network.client")
  (csr APPLE_EVENT)
  (system-attribute "platform-binary")
  ```

In compiled profiles, each of these is a filter key with an encoded value (string index, enum, bitfield, etc.).

---

## 5. Metafilters (Boolean Combinators)

Metafilters combine other filters logically. They are critical for mapping graph structures back into SBPL and show up frequently in real profiles.

### 5.1 `require-any` (logical OR)

```scheme
(allow file-read*
  (require-any
    (regex #"/bin/.*")
    (vnode-type REGULAR-FILE)))
```

Semantics: allow if any of the nested filters match.

### 5.2 `require-all` (logical AND)

```scheme
(allow file-read*
  (require-all
    (regex #"/bin/.*")
    (vnode-type REGULAR-FILE)))
```

Semantics: allow only if all nested filters match.

### 5.3 `require-not` (logical NOT)

```scheme
(allow file-read*
  (require-not
    (vnode-type REGULAR-FILE)))
```

Semantics: allow only if the nested filter does not match.

### 5.4 Nesting and graph patterns

You can nest metafilters to express complex conditions:

```scheme
(allow file-read*
  (require-all
    (require-not (vnode-type SYMLINK))
    (require-any
      (regex #"^/dev/ttys[0-9]+")
      (extension "com.apple.sandbox.pty"))))
```

In the compiled graph:

* Non-terminal nodes represent individual filter tests with “match” and “unmatch” edges.
* `require-any/all/not` emerge from specific patterns of nodes and edges; the binary format does not carry the names of these combinators explicitly.

XNUSandbox’s job includes recognizing those patterns and reconstructing the right metafilter structure.

---

## 6. Action Modifiers

Action modifiers decorate an `allow`/`deny` with additional behavior, such as logging or user consent.

### 6.1 `(with report)`

Example:

```scheme
(allow (with report) sysctl
  (sysctl-name "kern.hostname"))
```

Semantics:

* The operation is allowed if the filters match.
* A report/log entry is produced whenever this rule is triggered. In practice this affects whether sandboxd logs the event even though the syscall succeeds.

### 6.2 User-consent modifiers

More recent macOS profiles can include action modifiers that defer to user-consent workflows (TCC) for sensitive resources, for example camera or microphone access. Conceptually:

```scheme
(allow (with user-approval "Camera access")
  device-camera
  ...)
```

This is illustrative rather than canonical syntax, but the underlying idea is:

* Instead of outright deny or allow, the sandbox and TCC cooperate to prompt the user.
* The compiled profile encodes a decision plus flags that cause sandboxd/tccd to consult user consent.

From XNUSandbox’s perspective, these modifiers appear as additional flags or attributes on decision nodes.

---

## 7. Raw Strings and Scheme Features

SBPL rides on top of a TinyScheme-derived interpreter in `libsandbox.dylib`, with Apple-specific extensions.

Notable points:

* Raw string literals: `#"…"` are used for regexes and certain path strings:

  ```scheme
  (regex #"/bin/.*")
  ```

* TinyScheme was extended to support these “sharp expressions” so profiles can contain regexes without escaping everything.

* General Scheme constructs (conditionals, lambdas, macros, parameterization) exist, and Apple’s internal profiles do use macros and helper functions for reuse and entitlement-driven exceptions.

For XNUSandbox’s purposes, most of this sophistication is baked away during compilation. The compiled binary format mainly reflects:

* Which operation is involved.
* Which filters (key–value predicates) apply.
* How filters are combined (any/all/not).
* The final decisions and action modifiers.

When you see unfamiliar SBPL in XNUSandbox output, normalize it to that core structure.

---

# Binary Profile Formats and Policy Graphs

This section explains how SBPL policies become the binary “policy graphs” that Seatbelt actually enforces. It is the bridge between the high-level Sandbox DSL and the low-level XNUSandbox code that parses serialized blobs.

---

## 1. High-Level Picture: Binary Profiles as Serialized Graphs

Apple’s shipped sandbox profiles are compiled SBPL programs stored as binary blobs, not text. These blobs encode the policy as a graph of nodes:

* Each node represents either:

  * A filter test (e.g., “path matches this regex”) with outgoing edges for match / non-match, or
  * A terminal decision (allow/deny, possibly with flags).
* Each operation has an entrypoint into this graph.
* Shared tables hold strings, regexes, and other literal data.

From a reversing perspective:

* SBPL operations (like `file-read*`, `mach-lookup`) become entrypoints into per-operation subgraphs.
* SBPL filters become typed nodes with references into shared literal/regex tables.
* SBPL metafilters (`require-all/any/not`) are compiled into specific node patterns that can be reconstructed later.

Sandbox profiles can be stored as:

* Individual blobs per profile (“separated” storage).
* A single multi-profile blob (“bundled”), where profiles share tables and header structures.

XNUSandbox’s role is to parse these blobs, reconstruct the graph, and emit something close to the original SBPL.

---

## 2. Storage Models Across OS Versions

On iOS (and conceptually similarly on macOS), profiles are stored as binary blobs in OS images. The main evolution (following SandBlaster’s terminology) is:

* iOS 2–4:

  * Profiles embedded in the sandbox kernel extension (`com.apple.security.sandbox`).
  * Typically one blob per profile.
* iOS 5–8:

  * Profiles moved into `/usr/libexec/sandboxd` as discrete blobs.
* iOS 9+:

  * Profiles moved back into `com.apple.security.sandbox`.
  * Profiles bundled into a single blob with:

    * A header describing the bundle.
    * Shared operation-node, regex, and literal tables.
    * Per-profile indices into these shared structures.

For reversing, this matters mainly for extraction. Once you have the raw blob for a given profile (or the bundle), the internal layout is a graph plus a handful of tables.

---

## 3. Early Decision-Tree Format (Blazakis-Era)

Blazakis documented an early compiled profile format used by SandBox.kext. The core data structure:

* Header with:

  * `re_table_offset`: offset to regex-table (in 8-byte words).
  * `re_table_count`: number of compiled regexes.
  * `op_table`: an array of 16-bit offsets pointing to operation handlers.

* A sequence of handler records (nodes) forming per-operation decision trees:

  * Each handler entry begins with an opcode byte, e.g.:

    * `0x01` – terminal (decision node).
    * `0x00` – non-terminal (filter node).
  * For terminal nodes:

    * A result byte, e.g. `0x00 = allow`, `0x01 = deny`.
  * For non-terminal nodes:

    * `filter_type`: 1-byte filter key (path, xattr, file-mode, mach-global, mach-local, socket-local, socket-remote, signal, etc.).
    * `filter_arg`: 16-bit index into a table (literal/regex index, attribute value, etc.).
    * `transition_matched`: 16-bit offset of the next node if filter matches.
    * `transition_unmatched`: 16-bit offset of the next node otherwise.

* A regex cache sub-format referenced via `re_table_offset` / `re_table_count`, whose entries point to per-regex blobs that AppleMatch.kext unpacks and executes.

Operationally:

* For a given operation ID, SandBox.kext uses `op_table[op_id]` as the entrypoint into the node list.
* It then walks nodes, evaluating filters and following match / unmatch edges until landing on a terminal node that yields `allow` or `deny`.

In userland parsers like XNUSandbox, you typically see:

* A C struct mirroring the handler layout (opcode, result/filter type byte, 16-bit args, offsets).
* A table or enum mapping filter codes back to textual keys.
* Logic that, for each operation ID, follows transitions recursively to reconstruct a tree/graph and emit a readable representation.

---

## 4. iOS 7–9 Graph-Based Formats (SandBlaster Model)

SandBlaster generalizes and updates this view for later iOS versions, describing the compiled profile as a set of sections that together encode a policy graph.

For iOS 7–8 (separated profiles), the layout is roughly:

* **Header**

  * Magic / version identifier.
  * Counts and offsets for sections.
* **Operation Node Pointers**

  * Array indexed by operation ID.
  * Each entry is an offset into Operation Node Actions.
* **Operation Node Actions**

  * The serialized node graph for all operations in the profile.
  * Each node is a rule element (filter + maybe decision) with edges.
* **Regular Expression Pointers**

  * Array of offsets into the Literal/Regex section.
* **Literals and Regular Expressions**

  * Shared table of literal strings and serialized regexes.

For iOS 9 (bundled profiles), the same ideas apply, but:

* The header identifies the blob as a bundle and includes:

  * Number of profiles.
  * A list of profiles, each with:

    * Offset to its name string.
    * Offsets for its per-profile OpNode pointer table.
* Operation Node Actions, Regex Pointers, and Literals/Regexes are shared across all profiles in the bundle.

From an XNUSandbox point of view:

1. Parse the header and locate section offsets.
2. For a given profile:

   * Identify its operation-pointer table.
3. For each operation:

   * Use the pointer to locate the head of its rule subgraph in Operation Node Actions.
   * Walk nodes, resolving any references into the Regex / Literal tables.

---

## 5. Policy Graphs: Operations, Nodes, and Defaults

SandBlaster uses the term “operation node” for the serialized rule elements. Each operation’s policy is a subgraph of these nodes:

* Each node encodes:

  * Zero or more filters (e.g., path literal, path regex, vnode-type, process predicate).
  * A decision (allow/deny) or a continuation edge to other node(s).
  * Optional flags (logging, user-approval, etc.) depending on OS version.

Metafilters (`require-all`, `require-any`, `require-not`) are encoded as patterns of node/edge structure rather than explicit tags:

* `require-any` – multiple filters whose match edges converge on the same decision.
* `require-all` – sequential filters where failing any filter routes to a different decision.
* `require-not` – a node where match leads to deny and unmatch leads to allow, wrapped as a logical NOT of the underlying predicate.

The profile format guarantees that every known operation has an entry in the operation-pointer table, even if the original SBPL did not list it explicitly. In that case, the operation’s graph collapses to a default decision, typically deny.

Reconstruction workflow (SandBlaster-style):

1. Build operation ID ↔ name mappings from `libsandbox.dylib` and `.sb` profiles.
2. For each operation:

   * Start from its Operation Node Pointer.
   * Traverse Operation Node Actions, building an in-memory graph.
3. Post-process the graph:

   * Detect patterns corresponding to `require-any`, `require-all`, `require-not`.
   * Collapse literal/regex references into SBPL filters.
   * Emit SBPL-like rules that mirror the graph.

XNUSandbox code will look very similar, although details may vary.

---

## 6. Regular Expressions and Literal Tables

Filters that involve paths or other strings rely on shared literal and regex tables:

* Filters refer to literals/regexes by index into the Regular Expression Pointers array, which in turn points into the combined Literals/Regex section.
* Literals are stored as plain strings.
* Regexes are stored as serialized NFAs that AppleMatch.kext interprets in the kernel.

A userland reversing tool generally:

1. Reads the regex pointer table.
2. For each regex:

   * Parses the serialized NFA.
   * Optionally reconstructs a human-readable regex.
3. Maps the regex indices back into SBPL `(regex #"...")` filters.

XNUSandbox may or may not fully reconstruct regex syntax; it might instead give approximate or structured representations, depending on its goals.

---

## 7. Practical Hooks for Interpreting XNUSandbox

When reading XNUSandbox:

* Look for header parsing code:

  * Reads a fixed-header struct.
  * Computes offsets to operation-pointer tables, node arrays, and literal/regex tables.
* Look for node-traversal routines:

  * Accept an operation ID (or pointer index) and return a rule graph or iterated list of conditions + decision.
  * Switch on a node opcode / filter type byte.
* Look for post-processing passes:

  * Recognize graph patterns that correspond to `require-any`, `require-all`, `require-not`.
  * Emit SBPL or an intermediary Scheme-like format.

If something looks like “offset table + handler nodes + literal/regex region,” you are almost certainly looking at the binary policy graph substrate that Seatbelt uses at enforcement time.

---

# Operations and Filters Reference

This section gives you a compact mental model for the Seatbelt “vocabulary”: what an operation is, what a filter is, and how they compose into rules that XNUSandbox is decoding. For SBPL syntax details, see “Sandbox DSL Cheatsheet”. For serialization details, see “Binary Profile Formats and Policy Graphs”.

---

## 1. Operations: The Verbs of the Sandbox

At the SBPL level, an operation is a named class of kernel action such as `file-read*`, `network-outbound`, `mach-lookup`, or `sysctl-read`.

At compile time:

* Each operation is assigned a numeric ID.
* The compiled profile’s main structure is effectively:

  * `operation ID → entrypoint into policy graph`.

The `libsandbox` interpreter builds an internal vector (`*rules*` in Blazakis’ description) where each index corresponds to an operation’s rule graph. In the binary formats SandBlaster describes, the Operation Node Pointer table plays the same role: mapping each operation ID to its starting node.

Key points:

* Operation IDs are OS-version-specific; both the size and composition of the operation set grow over time.
* SandBlaster’s sampled systems show:

  * ~59 operations on 10.6.8.
  * ~80–120 operations on later iOS versions, depending on OS version.
* XNUSandbox needs (and maintains) a mapping table between operation IDs and human-readable names, usually derived from `libsandbox.dylib` and `.sb` profiles.

Treat operation ID as the primary key for everything else in the profile.

---

## 2. Operation Families You’ll See in Profiles

You usually don’t need an exhaustive list in the orientation; instead track the major families so patterns in decompiled output make sense.

### 2.1 Filesystem (`file*` family)

Examples:

* `file-read*`, `file-read-data`, `file-read-metadata`
* `file-write*`, `file-write-create*`, `file-write-data`
* Sometimes generic `file*` for a broader catch-all.

Common patterns:

* Default-deny:

  ```scheme
  (deny default)
  ```
* Allow only reads under certain directories:

  ```scheme
  (allow file-read* (subpath "/System"))
  (allow file-read* (subpath "/usr/lib"))
  ```
* Explicit denies:

  ```scheme
  (deny file-read* (literal "/bin/secret.txt"))
  ```

These patterns show up clearly in reversed profiles (e.g., Blazakis’ toy examples and SandBlaster’s reconstructed policies).

### 2.2 Process / control (`process*`, `signal`, `sysctl*`, etc.)

Representative operations:

* `process-fork`, `process-exec`
* `signal`
* `sysctl`, `sysctl-read`, `sysctl-write`
* `system-fsctl` and similar lower-level control operations

Profiles often:

* Allow broad process operations (`allow process*`) but constrain dangerous variants (`signal`, `sysctl-write`) to root or platform binaries.
* Use filters like `sysctl-name` and CSR predicates to gate access.

### 2.3 Mach IPC (`mach-*`)

Operations:

* `mach-lookup`
* `mach-register`
* `mach-priv-port` (on some OS versions)
* Other Mach IPC variants

These operations are typically constrained by filters on bootstrap names:

```scheme
(allow mach-lookup (global-name "com.apple.analyticsd"))
(deny  mach-lookup (global-name "com.apple.securityd"))
```

In the binary format, these are `mach-global` / `mach-local` filter keys plus string indices into the literal table.

### 2.4 Network (`network-*`)

Operations:

* `network-outbound`
* `network-inbound`
* Sometimes `network*` as a family catch-all.

Typical policy shapes:

* App Sandbox-style profiles that broadly allow outbound client network, optionally with entitlements gating:

  ```scheme
  (allow network-outbound (entitlement-is-present "com.apple.security.network.client"))
  ```
* Highly constrained profiles (daemons, platform components) that only permit specific local or remote destinations.

The underlying filters are `socket-local` / `socket-remote` predicates, but SBPL presents a higher-level spelling.

### 2.5 Meta / management operations

The Seatbelt module also exposes meta-operations (e.g., via `mac_syscall`) for managing profiles:

* `set_profile` – apply a compiled profile to a process.
* `platform_policy` – run checks against the platform profile.
* `check_sandbox` – manually query the current sandbox.

These are not SBPL operations in the resource sense; they are management commands. You may see them in XNUSandbox if it includes code that disassembles the sandbox syscall interface.

---

## 3. Filters: The Conditions on Each Operation

A filter is a predicate on an operation’s parameters or on process/OS state. In the binary profile, each non-terminal node encodes:

* A filter key (path, xattr, vnode-type, mach-global, socket-remote, etc.).
* A filter value (path index, regex index, vnode type enum, IP/port encoding, etc.).
* Match and unmatch successors in the graph.

Blazakis and SandBlaster describe early filter key sets that remain a good conceptual basis:

* Path / file:

  * `path`, `literal`, `subpath`, `regex`, `vnode-type`, `file-mode`, `xattr`
* Mach:

  * `mach-global`, `mach-local`
* Network:

  * `socket-local`, `socket-remote`
* Process / system:

  * `signing-identifier`, `entitlement-is-present`, `csr`, `system-attribute`, etc., in later profiles

You can think of filters in a few major groups.

### 3.1 Path- and file-based filters

These constrain filesystem operations and are the most commonly seen in examples:

* **Literal path**:

  ```scheme
  (literal "/bin/secret.txt")
  ```
* **Subpath**:

  ```scheme
  (subpath "/Applications/MyApp.app")
  ```
* **Regex**:

  ```scheme
  (regex #"^/Users/[^/]+/Documents")
  ```
* **Vnode type**:

  ```scheme
  (vnode-type REGULAR-FILE)
  (vnode-type DIR)
  (vnode-type SYMLINK)
  ```

Binary-wise, these correspond to filter codes plus indices into literal/regex tables and small enums for vnode type.

### 3.2 Mach and IPC filters

These constrain Mach bootstrap services and other IPC endpoints:

* By global bootstrap name:

  ```scheme
  (global-name "com.apple.analyticsd")
  ```
* By local name or other service identifiers.

These appear in SBPL attached to `mach-lookup` / `mach-register`, and in binary as filter keys with indices into literal tables.

### 3.3 Network filters

These constrain network operations. While the high-level SBPL names vary, conceptually they include:

* Remote IP / port:

  ```scheme
  (remote ip "127.0.0.1")
  (remote tcp "localhost:22")
  ```
* Possibly local address / port filters too.

These correspond to `socket-local` / `socket-remote` filter keys and encoded address values in the binary graph.

### 3.4 Process and OS state filters

These examine the calling process and system configuration:

* Signing identity:

  ```scheme
  (signing-identifier "com.example.myapp")
  ```
* Entitlements:

  ```scheme
  (entitlement-is-present "com.apple.security.device.camera")
  ```
* SIP / platform flags:

  ```scheme
  (csr APPLE_EVENT)
  (system-attribute "platform-binary")
  ```

They are critical in platform/App Sandbox profiles, which often gate access to powerful operations on entitlements and signing state.

---

## 4. Metafilters and Rule Composition

Filters can be combined directly (multiple filters in a single rule) or via explicit metafilters:

* `require-any` – logical OR.
* `require-all` – logical AND.
* `require-not` – logical NOT.

At the compiled level, this is represented purely by graph structure:

* Non-terminal nodes split control flow based on filter match / unmatch.
* Specific patterns of nodes and edges correspond to these logical combinators.
* XNUSandbox and SandBlaster detect these patterns when reconstructing SBPL.

When reading XNUSandbox output:

* If you see a rule printed with `require-any/require-all/require-not`, you are looking at the high-level interpretation of one of these node patterns.
* If you explore the underlying graph, expect multiple filters whose match edges converge or diverge in ways that implement OR/AND/NOT.

---

## 5. How XNUSandbox Obtains and Uses Operation/Filter Metadata

Tools like SandBlaster and XNUSandbox typically:

1. Extract operation and filter names from `libsandbox.dylib`:

   * `libsandbox` contains strings for operation names, filter keys, and sometimes descriptions.
2. Cross-check against `.sb` profiles in `/usr/share/sandbox` or `/System/Library/Sandbox/Profiles`.
3. Build bidirectional maps:

   * Operation name ↔ operation ID.
   * Filter key name ↔ filter key ID.
   * Filter enumerations (vnode types, system attributes, etc.).

XNUSandbox then uses those mappings to:

* Turn binary operation IDs into SBPL names (`file-read*`, `mach-lookup`, etc.).
* Turn filter keys/values into SBPL filter expressions.
* Validate decoded graphs by comparing them against known `libsandbox` intermediary representations (e.g., Scheme `*rules*` tables).

In summary:

* Operations tell you “what the process is trying to do.”
* Filters tell you “under what conditions.”
* Metafilters and graph structure tell you “how multiple conditions combine.”
* XNUSandbox sits at the seam, turning binary encodings of IDs and filter codes back into that higher-level vocabulary.

---

# Policy Stacking and Platform Sandbox

This section explains how Seatbelt policies stack: platform policy, per-process policy, and dynamic extensions. It provides context so you don’t over-interpret a single profile as the entire effective sandbox.

---

## 1. Two Levels of Seatbelt Policy

Seatbelt enforces sandbox rules at two distinct levels inside `Sandbox.kext`:

* **Platform sandbox policy**

  * Global policy applied system-wide.
  * Encodes system-wide constraints and behavior, including pieces of System Integrity Protection (SIP) and other global controls.
* **Process sandbox policy**

  * Per-process profile applied when:

    * The process is App Sandbox-enabled, or
    * The process calls `sandbox_init*` with a particular SBPL profile.
  * The compiled policy is attached to the process’s credentials as a MAC label.

From the kernel’s point of view, both are “just policies” evaluated through the same machinery; they differ in scope and how they are attached.

---

## 2. Evaluation Order: Platform First, Then Process

When a sandbox-relevant operation occurs (file open, socket connect, Mach lookup, etc.), XNU calls a sandbox MACF hook. `Sandbox.kext` then:

1. Maps the hook to a sandbox operation ID.
2. Evaluates the platform policy for that operation:

   * If the platform policy denies, the operation fails immediately.
   * The per-process sandbox is not consulted.
3. If the platform policy allows, and the process has its own sandbox profile:

   * Evaluates the per-process policy.
   * If the process policy denies, the operation fails.
4. If both allow (and any other MAC policies agree), the operation proceeds.

Net effect:

* Effective policy = platform policy ∧ process policy ∧ any other MAC policies.
* Platform-level denies are absolute, regardless of the per-process profile.

For a single decoded profile, you are always looking at one layer of this stack, not the final behavior in isolation.

---

## 3. Relationship to SIP, Entitlements, and Global Predicates

The platform sandbox policy is tightly coupled to SIP and global configuration:

* Predicates such as `csr` and `system-attribute` expose SIP state and system-wide flags into SBPL.
* Platform/App Sandbox profiles use process metadata predicates heavily:

  * `signing-identifier` to restrict rules to binaries with specific bundle IDs.
  * `entitlement-is-present` to gate access on entitlements (network, camera, files, etc.).
  * `system-attribute` to distinguish platform binaries from third-party apps.

In practice:

* Entitlements act as inputs to sandbox policy, not as independent allow/deny mechanisms.
* The platform policy often encodes “apps with entitlement X may do Y,” while individual App Sandbox templates encode more generic logic.

When you see filters referencing entitlements, signing IDs, or CSR flags in XNUSandbox output, you are likely looking at platform/App Sandbox logic, not app-specific one-off rules.

---

## 4. Userland Interface: Platform vs Process-Level Syscalls

Userland interacts with `Sandbox.kext` primarily via `__mac_syscall("Sandbox", ...)`, wrapped in `__sandbox_ms` and higher-level `libsandbox` APIs. Reversing work identifies several management commands (names vary by source):

* `set_profile`-like commands to:

  * Apply a compiled or named profile to the current process (or a target process).
* `platform_policy`-like commands to:

  * Trigger platform-specific checks against a process or operation.
* `check_sandbox`-like commands to:

  * Explicitly ask “would this operation be allowed by the current sandbox stack?”

These commands:

* Operate on the same underlying bytecode format (policy graphs) described earlier.
* Distinguish whether the call is manipulating process profiles, querying platform policy, or just checking an operation.

For XNUSandbox itself, this matters mainly as context: it focuses on decoding profiles, not on issuing these syscalls.

---

## 5. Sandbox Extensions as a Third Dimension

Beyond static platform + process policies, sandbox extensions add a dynamic third dimension:

* A sandbox extension is an opaque token that, when consumed by a process, extends its sandbox to access specific resources (paths, Mach names, etc.).
* Extensions are typically issued by trusted daemons (e.g., securityd, tccd, container management services) in response to system events:

  * Opening files via NSOpenPanel.
  * Granting Photos or Contacts access via TCC dialogs.
  * Launch services handing off file URLs across processes.
* Extensions are stored in MACF label slots and consulted in sandbox policy via filters like:

  ```scheme
  (extension "com.apple.app-sandbox.read")
  (extension "com.apple.sandbox.read-write")
  ```

  usually combined with path or other filters.

Conceptually:

* For a given operation, platform and process profiles both can query “does this process hold extension X?” and allow access only if so.
* Extensions therefore implement targeted exceptions without widening the base profile globally.

---

## 6. Implications for XNUSandbox and Profile Analysis

For a profile-decoding tool:

* A single decoded profile is one layer in a multi-layer system:

  * It might be a platform profile.
  * It might be an App Sandbox template (e.g., `application.sb`).
  * It might be a daemon’s custom profile.
* The effective runtime sandbox is:

  * Platform profile decisions
    ∧ process profile decisions (if any)
    ∧ active sandbox extensions
    ∧ other MAC policies (including SIP-related MAC modules)
    ∧ user-consent workflows (TCC) encoded via action modifiers and extension issuance.

When using XNUSandbox output to reason about real-world behavior:

* Do not assume a per-process profile alone explains why an operation is allowed or denied.
* Pay attention to:

  * Global predicates (`csr`, `system-attribute`).
  * Entitlement-based filters.
  * Extension filters.
* Remember the evaluation order: platform first, then process. A deny in the platform profile will win even if the process profile appears permissive.

This stacking model is essential context when tying decoded profiles back to actual behavior on modern macOS/iOS and when designing probes that try to characterize sandbox capabilities empirically.
