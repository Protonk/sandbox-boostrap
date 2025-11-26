# Sandbox DSL Cheatsheet

This section is a compact reference for Apple’s Sandbox Profile Language (SBPL) as used in macOS “Seatbelt” policies. It focuses on the subset that shows up in system profiles, compiled sandbox output, and related tooling, not the full Scheme language.

---

## 1. SBPL at a Glance

A minimal SBPL profile looks like:

```scheme
(version 1)
(deny default)

(allow file-read* (path "/tmp/foo") (subpath "/tmp/bar"))
(allow (with report) sysctl (sysctl-name "kern.hostname"))
...
```

Key elements:

* `(version 1)` – profile format version, not OS version.
* `(deny default)` – default decision if no rule matches (usually `deny` in built-in profiles).
* `(allow ...)` / `(deny ...)` – top-level rules.
* Operation names like `file-read*`, `network-outbound`, `mach-lookup`.
* Filters like `(path "/tmp/foo")`, `(subpath "/tmp/bar")`, `(sysctl-name "kern.hostname")`.
* Action modifiers like `(with report)`.

---

### Parameterization and templating

System profiles often template paths or names using parameters that must be supplied at compile time:

```scheme
(allow file-read*
  (subpath (string-append "/System/Library/" (param "bundle"))))
```

`(param "bundle")` is a placeholder; the compiler substitutes concrete values from a parameter dictionary. This lets Apple ship generic profiles that can be specialized per-application or per-context (e.g., different containers or bundle IDs) while still producing concrete literals in the compiled blob.

In many shipped profiles these parameters are mandatory: compiling without the expected keys or with incompatible values will fail or yield an unusable profile.

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
  ```

* Rules:

  ```scheme
  (allow OPERATION
    (FILTER-KEY FILTER-VALUE ...)
    ...)
  (deny OPERATION
    ...)
  ```

* Optional profile metadata (not always present in shipped profiles).

At the SBPL level, rules are order-sensitive: the first matching rule for a given operation generally determines the effective decision, although the compiled representation uses a graph that doesn’t look like a simple ordered list.

---

## 3. Operations

Operations are the verbs of the sandbox: they name classes of kernel actions (file reads, process creation, network I/O, etc.). At the SBPL level they appear as symbols:

```scheme
(allow file-read* ...)
(allow network-outbound ...)
(deny process-exec ...)
```

Common examples (abbreviated):

* File and directory:

  * `file-read*`, `file-write*`, `file-ioctl`, `file-issue-extension`
  * `file-write-create`, `file-write-unlink`
  * `file-read-metadata`, `file-write-xattr`

* Process and signals:

  * `process-exec`, `process-fork`, `process-suspend`
  * `signal`

* IPC:

  * `mach-lookup`, `mach-register`
  * `ipc-posix-shm`, `ipc-posix-sem`
  * `ipc-unix`, `ipc-sysv-shm`, `ipc-sysv-sem`, `ipc-sysv-msg`

* Network:

  * `network-inbound`, `network-outbound`
  * `network-bind`, `network-listen`

* System:

  * `sysctl-read`, `sysctl-write`
  * `system-logging`
  * `iokit-open`, `iokit-set-properties`

For each operation, filters specify when the rule applies. For example, `file-read*` with a `(subpath "/Applications/TextEdit.app")` filter permits file reads under that subtree.

---

## 4. Filters (Key–Value Predicates)

A filter narrows the applicability of a rule. Conceptually:

```scheme
(allow OPERATION
  (FILTER-KEY FILTER-VALUE ...)
  (FILTER-KEY2 FILTER-VALUE2 ...))
```

At the binary level, a filter is a key–value pair, where both key and value are encoded as small integers that index shared tables (for literals, regexes, and other metadata). The same SBPL syntax can map to different internal encodings depending on the operation and filter semantics.

Common filter families include:

* **Path / vnode filters**:

  * `(path "/absolute/path")`
  * `(literal "/absolute/path")` – older style; effectively the same in many profiles.
  * `(subpath "/prefix")`
  * `(regex #"^/tmp/.*")`
  * `(vnode-type REGULAR-FILE)`
  * `(vnode-type DIR)`
  * `(vnode-type SYMLINK)`

* **Process / identity filters**:

  * `(uid 0)` or `(uid 501)`
  * `(gid 0)`
  * `(target self)` / `(target other)`
  * `(target pid 1234)` – less common in static profiles; more common in runtime-created policies.

* **Network filters**:

  * `(remote ip "127.0.0.1")`, `(remote ip "0.0.0.0/0")`
  * `(local ip "10.0.0.0/8")`
  * `(remote port 80)`, `(local port 1024-65535)`
  * `(protocol "tcp")`, `(protocol "udp")`

* **Mach / IPC filters**:

  * `(global-name "com.apple.cfprefsd.daemon")`
  * `(local-name "com.apple.sandboxd")`
  * `(service-name "com.apple.backupd")`

Apple’s internal profiles contain many more specialized filters (I/O Kit classes, entitlements, container-relative paths, etc.), but they all follow the key–value predicate idea.

---

## 5. Metafilters: require-any/all/not

Metafilters combine other filters to express Boolean structure. They are most commonly seen as `require-any`, `require-all`, and `require-not`.

### 5.1 require-any

“Allow if any of these conditions hold”:

```scheme
(allow file-read*
  (require-any
    (subpath "/Applications/TextEdit.app")
    (subpath "/System/Applications/TextEdit.app")))
```

Semantics: the rule applies if **either** subpath condition matches.

### 5.2 require-all

“Allow only if all of these conditions hold”:

```scheme
(allow file-write*
  (require-all
    (subpath "/Users/alice/Library/Containers/com.apple.TextEdit")
    (vnode-type REGULAR-FILE)))
```

Semantics: both the subpath and vnode-type constraints must be satisfied.

### 5.3 require-not

“Allow only if this condition does *not* hold”:

```scheme
(allow file-read*
  (require-not
    (subpath "/System/Volumes/Data/private")))
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
* `require-any/all/not` emerge from specific patterns of nodes and edges, not from dedicated opcodes. The graph structure encodes Boolean combinations; the compiled format does not carry the names of these combinators explicitly.

XNUSandbox’s job includes recognizing those patterns and reconstructing the right metafilter structure.

---

## 6. Action Modifiers

Action modifiers decorate an `allow`/`deny` with additional behavior, such as logging or user consent.

Examples include:

* `(with report)` – request that violations be logged (e.g., to the system log).
* `(with telemetry)` – hypothetical; used here as a stand-in for custom reporting hooks.
* `(with user-approval)` – hypothetical; could represent a TCC-style user prompt.

At the SBPL level, these are nested forms:

```scheme
(allow (with report) file-read* (subpath "/tmp"))
```

In the compiled profile, these usually become bits or attributes attached to the decision node. Not all modifiers have public names in system profiles, but the pattern “modifier wraps operation in SBPL” → “flags on decision node in policy graph” holds.

---

# Binary Profile Formats and Policy Graphs

This section explains how SBPL policies become the binary “policy graph” structures that Seatbelt evaluates in the kernel, and how those structures are laid out in memory. It connects the textual DSL above with the low-level XNUSandbox code that parses serialized blobs.

---

## 1. High-Level Picture: Binary Profiles as Serialized Graphs

Apple’s shipped sandbox profiles are compiled SBPL programs stored as binary blobs. Conceptually, each compiled profile is:

* A header describing counts and offsets.
* A table mapping operation IDs to entrypoints into a graph.
* A set of nodes forming per-operation decision graphs.
* Shared tables for strings, regular expressions, and other literals.

At runtime, the kernel walks these graphs when mediating system calls and other events.

---

## 2. Early Decision-Tree Format (Blazakis-Era)

Blazakis’s 2011 paper (“The Apple Sandbox”) reverse-engineers an early on-disk and in-memory format where each operation’s policy is represented as a decision tree:

* A fixed header with a `re_table_offset` pointing to a regex cache.
* An array of operation records.
* A contiguous sequence of “handler” records encoding filter tests and terminal decisions.
* A separate regex cache, pointed to by `re_table_offset`.

Each handler record has fields roughly corresponding to:

* Kind of node (filter vs decision).
* Filter key (e.g., path, vnode-type, global-name).
* Filter argument (index into literal/regex table, enums for vnode type, etc.).
* Offsets for “match” and “unmatch” edges.

The kernel uses these to evaluate operations like `file-read*`: starting from an operation-specific entrypoint, it follows edges through filter nodes until reaching a terminal “allow” or “deny.”

From a reverse-engineering perspective, this format is convenient:

* The header gives you counts and offsets.
* The handler array gives you a flat list of nodes.
* The regex cache can be parsed separately and reassembled into human-readable patterns.

However, this decision-tree format is only one point in the evolution of Apple’s compiled sandbox representation.

---

## 3. Later Graph-Based Formats

Later OS versions (macOS and iOS) move from a strict tree representation to a more generic graph:

* Nodes are still filter tests or terminal decisions, but they are shared across different operations where possible (e.g., common subgraphs).
* The operation pointer table maps each operation ID to a node offset.
* A literal/regex table aggregates all string and regex data.
* Regexes are stored in an AppleMatch-specific NFA encoding, not as plain text.

Blazakis’s decision-tree format is best thought of as a special case of these more general graph-based layouts. The core ideas remain:

* One or more tables of shared literals and regexes.
* A node array encoding filter tests and decisions.
* Operation-specific entrypoints into that array.
* Regex caches with AppleMatch NFAs.

---

## 4. Modern Bundled Profile Format (macOS 13–14)

On macOS 13–14, system sandbox profiles live on disk as `.sb` files, typically under `/System/Library/Sandbox/Profiles/`. These files bundle:

* A header.
* An operation pointer table.
* A node graph.
* Literal and regex tables.
* Optional metadata.

While the exact header layout and section offsets differ across OS versions, a common pattern is:

* **Header**:

  * Magic / version identifier.
  * Counts and offsets for sections.

* **Operation Node Pointers (also known as Operation Pointer Table)**:

  * Array indexed by operation ID.
  * Each entry is an offset into Operation Node Actions.

* **Operation Node Actions**:

  * The serialized node graph for all operations in the profile.
  * Each node is a rule element (filter + maybe decision) with edges.

* **Regular Expression Pointers**:

  * Array of offsets into the Literal/Regex section.
  * Each entry corresponds to a compiled AppleMatch NFA for a regex used in the profile.

* **Literal / Regex Payloads**:

  * Shared tables for strings and regex NFAs.

Older descriptions of `re_table_offset` still apply conceptually (there is a section containing regex blobs), but the exact header fields and offsets have evolved. On macOS 14, compiled profiles may have `re_table_offset = 0` and use a different arrangement of regex tables; decoders should not assume this offset is always nonzero.

---

## 5. Nodes and Edges

In all these formats, the core idea is the same: a graph of nodes with edges that encode Boolean structure.

A node typically has:

* An opcode or kind field (filter vs decision).

* For filter nodes:

  * A filter key code (path, vnode-type, global-name, etc.).
  * A filter argument (index into literal/regex table, enums for vnode type).
  * Two outgoing edges: `match` and `unmatch`.

* For decision nodes:

  * A decision code (`allow`, `deny`, or a small set of variants).
  * Optional flags for action modifiers (reporting, logging, etc.).
  * No outgoing edges.

Edges are represented as:

* Byte or 16-bit offsets into the node array.
* Sometimes relative, sometimes absolute, depending on OS version.

The graph patterns corresponding to `require-any/all/not` emerge from how nodes connect:

* `require-any` ≈ parallel branches whose results OR together.
* `require-all` ≈ sequential tests where any failure jumps to a deny.
* `require-not` ≈ a branch inversion around some condition.

XNUSandbox’s parsers reconstruct a higher-level tree or graph representation from these low-level nodes and edges.

---

## 6. AppleMatch and Regex Tables

Regex filters in SBPL, such as:

```scheme
(allow file-read*
  (regex #"^/Applications/.*\\.app/Contents/Info.plist$"))
```

compile to AppleMatch-specific NFAs stored in regex tables. The binary profile typically has:

* A table of regex pointers (offsets into a regex payload section).
* One or more blobs containing AppleMatch NFA encodings.

Early reversing work used AppleMatch itself to interpret these NFAs. On modern macOS versions, userland tools instead parse the NFA encoding directly or via independent decoders; XNUSandbox treats the regex table as opaque NFA data that can be disassembled into a more convenient internal representation.

---

## 7. Storage Locations and Evolution

Historically:

* Early iOS/macOS builds embedded sandbox profiles in kernel extensions or the kernelcache itself.
* Later versions moved profiles into userland (`sandboxd`) or dedicated bundles.
* Modern macOS 13–14 store `.sb` files under `/System/Library/Sandbox/Profiles/` and load them at boot or as needed.

From a tooling perspective, this evolution means:

* Kernelcache scraping (as described in older blog posts and tools) is largely unnecessary on macOS 14: profiles are available as `.sb` files on disk.
* Tools like `extract_sbs` work at the SBPL/binary profile level, not by patching or scraping kernel images.

XNUSandbox assumes profiles are obtained from these modern `.sb` bundles (or from test fixtures compiled with `sandbox-exec`-style tooling on older systems) rather than from kernelcache offsets.

---

# Operations and Filters Reference

This section gives you a compact mental model for the Seatbelt “vocabulary”: what an operation is, what a filter is, and how they compose in policy graphs. It assumes familiarity with the SBPL syntax in the cheatsheet above; for compile-time and layout details, see “Binary Profile Formats and Policy Graphs”.

---

## 1. Operations: The Verbs of the Sandbox

At the SBPL level, an operation is a named class of kernel action: `file-read*`, `network-outbound`, `mach-lookup`, or `sysctl-read`.

At compile time:

* Each operation is assigned a numeric ID.
* The compiled profile’s main structure is effectively:

  * `operation ID → entrypoint into policy graph`.

The `libsandbox` interpreter builds an internal vector (`*rules*` in Scheme) where each element corresponds to an operation’s rule graph. In the binary formats, the operation pointer table plays the same role: mapping each operation ID to its starting node.

Key points:

* Operation IDs are OS-version-specific; both the size and composition of the operation set grow over time.
* SandBlaster’s sampled systems show:

  * ~59 operations on 10.6.8.
  * ~80–120 operations on later iOS versions, depending on OS version.
* XNUSandbox needs (and maintains) a mapping table between operation IDs and symbolic names, usually derived from `libsandbox.dylib` and `.sb` profiles.
  Because `libsandbox.dylib` is a private component without stable public headers or packaging, these symbol- and string-based mappings are inherently fragile and may change across OS versions; XNUSandbox treats them as best-effort hints rather than a stable API.

Treat operation ID as the primary key for everything else in the profile.

---

## 2. Operation Families

Some operations are closely related and share filters:

* File read/write families:

  * `file-read*`, `file-read-metadata`
  * `file-write*`, `file-write-create`, `file-write-unlink`
  * `file-issue-extension`

* Network:

  * `network-inbound`, `network-outbound`, `network-bind`, `network-listen`

* Mach IPC:

  * `mach-lookup`, `mach-register`, related service filters.

Understanding these families helps when constructing capability catalogs: you rarely need to list every variant if they share the same filter structure and differ only in small semantics.

---

## 3. Filters: The Conditions on Rules

Filters are key–value predicates that further constrain when a rule applies. In the compiled graph:

* Each filter is encoded as a filter key code plus an argument (often an index into a shared literal or regex table).
* Edges leave each filter node for the “match” and “unmatch” cases.

Broad categories:

### 3.1 Path and vnode filters

These are the most common and govern file-system access:

* Exact path:

  ```scheme
  (path "/bin/ls")
  ```

* Subpath:

  ```scheme
  (subpath "/Applications/TextEdit.app")
  ```

* Regex path:

  ```scheme
  (regex #"^/Users/[^/]+/Library/Containers/")
  ```

* Vnode type:

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

These appear in SBPL attached to `mach-lookup` / `mach-register`, and in binary as filters referencing literal strings.

### 3.3 Network filters

These govern network operations:

* Remote address and port:

  ```scheme
  (remote ip "127.0.0.1")
  (remote port 80)
  ```

* Local address and port:

  ```scheme
  (local ip "10.0.0.0/8")
  (local port 49152-65535)
  ```

* Protocol:

  ```scheme
  (protocol "tcp")
  ```

The binary format encodes these as structured arguments, often via small enums and packed integers.

### 3.4 Process / identity filters

These constrain by user, group, or process identity:

```scheme
(uid 0)
(gid 0)
(target self)
(target other)
```

They show up frequently in platform policies that differentiate between root and non-root actions, or between self-targeted and other-targeted signals.

---

## 4. Metafilters and Rule Composition

As described earlier, metafilters like `require-any`, `require-all`, and `require-not` combine filters:

* `require-any`: OR of multiple branches.
* `require-all`: AND of multiple conditions.
* `require-not`: negation of a condition.

In the compiled graph:

* These do not appear as dedicated opcodes.
* Instead, they emerge from patterns in how filter and decision nodes connect.
* XNUSandbox recognizes these patterns and reconstructs metafilters for human-readable output or capability catalogs.

---

## 5. Decisions and Action Modifiers

The terminal nodes in the policy graph carry decisions:

* `allow`
* `deny`

Action modifiers are attached to these decisions as flags:

* Logging/reporting.
* Telemetry hooks.
* User-approval prompts (TCC-style mediation).

In SBPL, modifiers wrap the operation; in the compiled graph, they live as bits on the decision node.

---

## 6. Operation and Filter Vocabulary Maps

XNUSandbox maintains its own “vocabulary maps”:

* Operation map:

  * Operation ID ↔ operation name (`file-read*`, `mach-lookup`, etc.).
  * Derived from `libsandbox.dylib`, Apple’s `.sb` profiles, and test fixtures.

* Filter map:

  * Filter key ID ↔ filter name (`path`, `subpath`, `vnode-type`, etc.).
  * Filter argument encodings ↔ human-readable values (string literals, regexes, enums).

These maps are essential for:

* Parsing compiled profiles into human-readable structures.
* Building capability catalogs that refer to operations and filters by name.
* Comparing profiles across OS versions (detecting added/removed operations and filters).

Because operation IDs and filter codes can change across OS versions, these maps are versioned and derived from the concrete artifacts at hand, not assumed to be stable.

---

# Policy Stacking and Platform Sandbox

This section explains how Seatbelt policies stack: platform policies, app-specific policies, and sandbox extensions combine to produce the effective sandbox for a process. It emphasizes that you must consider all layers together when reasoning about capabilities, and that you should not over-interpret a single profile as the entire effective sandbox.

---

## 1. Two Levels of Seatbelt Policy

Seatbelt enforces sandbox rules at two distinct levels inside `Sandbox.kext`:

* **Platform sandbox policy**:

  * System-wide rules applied to many processes, often tied to platform roles (system daemons, built-in apps, etc.).
  * Loaded early at boot.
  * Defines global restrictions and allow-lists.

* **Process-specific sandbox policy**:

  * Per-process policy created when an app opts into App Sandbox or is otherwise launched with a profile.
  * Often based on templates like `com.apple.sandbox.default`, specialized by entitlements.

Together, these layers form a stack: the effective decision for an operation is the result of evaluating both policies (and any extensions) with a defined precedence.

---

## 2. Platform vs App Sandbox

Platform policies:

* Cover system daemons, services, and core OS processes.
* Are typically defined in profiles that are not directly visible or customizable to third-party developers.
* Use operations and filters similar to app policies but are oriented around OS roles.

App sandbox policies:

* Are derived from templates and tuned by entitlements.
* Govern access to the file system, network, hardware, and IPC for individual apps.
* Are documented at a high level in Apple’s App Sandbox and Hardened Runtime guides.

From a capability catalog perspective:

* Platform policies set the background “fence line” of the system.
* App policies define additional fences or gates specific to each app.
* You must inspect both to correctly characterize what a process can and cannot do.

---

## 3. Evaluation Order and Precedence

Conceptually, when a sandboxed process attempts an action:

1. Seatbelt consults the platform policy.
2. Seatbelt consults the process-specific policy.
3. It combines decisions according to fixed precedence rules.

A simplified precedence model:

* If any layer yields a definitive `deny` (without an explicit override mechanism), the effective decision is `deny`.
* `allow` in a lower-priority layer cannot override a `deny` in a higher-priority layer.
* Sandbox extensions can add more specific allowances, but they do not rewrite existing rules.

This matches both the public documentation and reverse-engineering observations: platform denies (for example, forbidding writes to certain system paths) cannot be trivially overridden by app-level profiles.

---

## 4. Sandbox Extensions as a Third Dimension

Sandbox extensions are opaque tokens that grant additional, narrowly scoped capabilities without changing the underlying profile:

* Issued by trusted system components (e.g., `launchd`, system daemons, TCC agents).
* Encoded as blobs attached to the process’s label in the kernel.
* Referenced by filters like `(extension "com.apple.app-sandbox.read-write")`.

Examples of uses:

* Granting temporary read/write access to a file the user selected in an open/save dialog.
* Allowing access to a removable volume or network share.
* Enabling a process to receive data from another sandboxed process via a controlled channel.

In practice:

* Extensions are neither pure “platform” nor pure “app” policy; they are a dynamic overlay.
* XNUSandbox and similar tools model them as a separate capability channel.
* When building capability catalogs, you must account for extensions as potential “escape hatches” that legitimately widen an app’s access in specific contexts.

The policy stack, in summary, is:

* Platform profile(s).
* Process-specific profile.
* Sandbox extensions.

Any realistic assessment of a process’s sandbox must consider all three together, rather than any one layer in isolation.

---

# Lifecycle pipeline: from signed binary to sandboxed process

This section ties together the “where does a profile come from?” questions into a single pipeline: from a signed Mach-O on disk to a process with a Seatbelt label and an active policy graph in the kernel. It draws on the high-level view in ROWE_SANDBOXING, the low-level reverse engineering in BLAZAKIS2011 and SANDBLASTER2016, and the broader system context in APPLESANDBOXGUIDE, STATEOFSANDBOX2019, and WORMSLOOK2024.

---

## 1. On-disk ingredients

Before any sandboxing happens at runtime, the system already has several relevant artifacts on disk:

* **Signed executable and entitlements**

  * Each modern macOS app is a code-signed Mach-O binary (or bundle) whose signature includes an entitlements plist.
  * Entitlements determine, among other things, whether the app opts into the App Sandbox and what additional capabilities (network, device access, etc.) it requests.

* **Profile sources**

  * Built-in SBPL templates and precompiled profiles for the App Sandbox and system roles.
  * System `.sb` files under `/System/Library/Sandbox/Profiles/` in newer macOS versions, which hold compiled or bundled Seatbelt policies.
  * SBPL strings or files provided by applications that use the sandbox(7) APIs directly.

* **Platform policy bundle**

  * A set of platform profiles that capture OS-level policy for daemons, helpers, and core services, loaded at boot or as needed.

These map directly onto the **Compiled Profile Source** and **Profile Layer** concepts: you can think of them as the raw material for the per-process policy stack.

---

## 2. Launch and early initialization

When a process is started (via `launchd`, `xpcproxy`, or similar launch machinery), a series of early steps determine whether it will be sandboxed and how:

1. **Code signature and entitlements are evaluated**

   * A security initialization component (often referred to in the literature as `secinit`) checks the code signature, reads entitlements, and applies hardened runtime rules.
   * At this stage the system can already decide whether the App Sandbox entitlement is present and whether special platform flags apply.

2. **libSystem initializers decide whether to apply a sandbox**

   * For App Sandbox processes (those with the App Sandbox entitlement), Rowe observes that they are sandboxed “automatically by initializers in `libSystem` that run very early during an application’s launch.” ROWE_SANDBOXING
   * For processes without the App Sandbox entitlement, sandboxing is opt-in via explicit calls to the sandbox(7) APIs, primarily `sandbox_init_*`.

3. **Explicit vs implicit sandbox entry points**

   * **Implicit (App Sandbox):** `libSystem`’s early initializers consult process attributes (notably entitlements) and apply the App Sandbox policy automatically for Mac App Store and similar apps. The application itself does not call sandbox(7) directly.
   * **Explicit (custom policy):** Non-App-Sandboxed applications can call APIs like `sandbox_init` / `sandbox_init_with_parameters` to apply a named profile, SBPL file, or SBPL string at a time of their choosing.

Historically, the `sandbox-exec` utility wrapped this explicit path by calling `sandbox_init` before `fork`/`exec`. BLAZAKIS2011

---

## 3. Selecting and parameterizing a profile

Once the runtime has decided *that* a process should be sandboxed and *how* (App Sandbox template vs explicit policy), it must choose a concrete profile and fill in any parameters.

1. **Template and source selection**

   * **App Sandbox path:**

     * macOS uses a predefined App Sandbox profile template, effectively a large SBPL policy that represents what “being App Sandboxed” means at a coarse level.
     * Additional entitlements (network, hardware access, container exceptions) act as selectors that turn particular pieces of that template on or off.

   * **Custom sandbox path:**

     * The calling process can specify a named built-in profile, a path to an SBPL file, or a literal SBPL string.

2. **Parameter dictionaries**

   * Many system SBPL profiles use `(param "…")` forms and string combinators (`string-append`, etc.) that require a parameter dictionary at compile time (bundle identifiers, container roots, and other app-specific values). BLAZAKIS2011, WORMSLOOK2024
   * For App Sandbox profiles, entitlements and other launch metadata effectively *are* the parameter source; the system derives parameter values (e.g., container path fragments) and passes them to the SBPL compiler.

3. **Mapping to the concept space**

   * This stage corresponds to moving from a generic **SBPL Profile** plus **SBPL Parameterization** to a specific instance tied to a single process’s identity and entitlements.
   * The outcome is a concrete SBPL program with all parameters resolved, ready for compilation into the binary policy graph described elsewhere in the Appendix.

---

## 4. Compiling SBPL into a policy graph

The next step is to turn the selected, parameterized SBPL profile into a compiled representation that the kernel can evaluate efficiently.

1. **SBPL interpretation and compilation in `libsandbox`**

   * BLAZAKIS2011 and ROWE_SANDBOXING describe an interpreter within `libsandbox` (based on TinyScheme) that reads SBPL and emits a compiled form.
   * `sandbox_init` and related APIs in `libSystem` dynamically load `libsandbox.dylib`, invoke one of several `sandbox_compile_*` functions, and receive back a compiled policy blob.

2. **Compiled profile structure**

   * The compiled blob is a serialized **PolicyGraph**:

     * A header with offsets and counts.
     * An operation pointer table mapping operation IDs to graph entrypoints.
     * A node array of filter and decision nodes.
     * Shared tables for literals and regex NFAs (AppleMatch).

   * This is exactly the binary structure described in “Binary Profile Formats and Policy Graphs” and matches the **PolicyGraph**, **Policy Node**, and **Operation Pointer Table** concepts.

3. **Action modifiers and logging configuration**

   * During compilation, SBPL action modifiers (e.g., `(with report)`) are translated into flags on decision nodes in the graph, controlling logging behavior and violation reporting via `sandboxd`.

At the end of this stage, user space holds a compiled sandbox blob that is ready to be installed into `Sandbox.kext`.

---

## 5. Installing the profile in the kernel

With a compiled policy in hand, the system must make it active for the target process by loading it into the Sandbox kernel extension and attaching it to the process’s credentials.

1. **User–kernel boundary**

   * In earlier OS versions, BLAZAKIS2011 documents `sandbox_apply` as the userland entry point that hands the compiled blob to the kernel.
   * Later work observes both a dedicated syscall stub (`sandbox_ms`) and MIG-based messaging into `Sandbox.kext`, depending on OS version. SANDBLASTER2016, STATEOFSANDBOX2019

2. **Profile registration and reference counting**

   * The kernel stores the compiled profile in internal data structures and typically reference-counts it so that multiple processes can share the same compiled instance when appropriate. SANDBLASTER2016, STATEOFSANDBOX2019
   * Platform profiles (part of the global policy) are loaded early and shared widely; App Sandbox and custom profiles may be loaded on demand.

3. **Attaching to the process label**

   * XNU’s MAC Framework (MACF) maintains per-credential security labels. `Sandbox.kext` stores pointers to the process’s platform and app-level profiles, as well as any sandbox extensions, in this label. ROWE_SANDBOXING, SANDBLASTER2016
   * Conceptually, this is where the **Policy Stack Evaluation Order** and **Profile Layer** concepts become concrete: the process now has an effective policy stack consisting of:

     * One or more platform profiles.
     * Zero or one app-specific profile (App Sandbox or custom).
     * Zero or more sandbox extensions.

From this point on, the process is “sandboxed” in the sense that all relevant MACF hooks will consult this label and its associated policy graphs.

---

## 6. Enforcement at runtime

Once the label is attached, enforcement is entirely driven by kernel-side hooks and the policy graphs:

1. **MACF hooks into system call handling**

   * `Sandbox.kext` registers handlers for many MACF policy hooks, covering file operations, process management, IPC, and other sensitive actions. ROWE_SANDBOXING, SANDBLASTER2016
   * When a covered operation is attempted, XNU calls the Sandbox policy hook early in the system-call handling path, providing context (arguments, credentials, etc.).

2. **Policy graph evaluation**

   * The Sandbox hook:

     * Identifies the relevant operation ID (e.g., `file-read*`, `mach-lookup`).
     * Looks up the entrypoint in the operation pointer table for both platform and app profiles.
     * Walks the filter and decision nodes, following `match`/`unmatch` edges according to the operation’s arguments.

   * The kernel combines decisions across layers according to fixed precedence rules (platform denies dominating app allows, with extensions providing scoped exceptions), as described in “Policy Stacking and Platform Sandbox.”

3. **Outcomes and reporting**

   * If the effective decision is **allow**, the system call proceeds normally.
   * If it is **deny**, the kernel returns `EPERM` (operation not permitted) or similar to user space. ROWE_SANDBOXING
   * Depending on compiled action modifiers, `Sandbox.kext` may:

     * Log the violation via system logging.
     * Ask `sandboxd` to generate a violation report with backtrace and context. ROWE_SANDBOXING

At this point the lifecycle is complete: the signed binary and its entitlements have been turned into a concrete SBPL profile, compiled into a policy graph, loaded into the kernel, attached to the process label, and used to gate every relevant operation for the lifetime of the process.
