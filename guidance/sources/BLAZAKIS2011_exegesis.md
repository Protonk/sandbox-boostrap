## 1. BLAZAKIS2011

Blazakis’s “The Apple Sandbox” is a reverse-engineering study of the Snow Leopard–era macOS sandbox (“Seatbelt”). It traces the entire pipeline from public APIs (`sandbox_init`, `sandbox-exec`), through user-space implementation (`libSystem`, `libsandbox.dylib`, TinyScheme and SBPL), into the kernel implementation (`Sandbox.kext` as a TrustedBSD MAC policy, plus `AppleMatch.kext` for regex support). The paper reconstructs the SBPL language semantics, shows how profiles are compiled into a compact binary decision tree format, explains how that format is loaded into the kernel via a MAC syscall and bound to processes, and then walks through how that policy is evaluated at MAC hooks for filesystem, networking, and other operations. For anyone building a capability catalog, it provides a concrete map of operation codes, filter types, and how Apple’s stock profiles (like `no-internet`, `named.sb`, `ntpd.sb`) actually enforce their constraints.

---

## 2. Architecture pipeline

From userland, the main programmatic entry point is `sandbox_init(profile, flags, &errorbuf)`, exported by `libSystem.dylib`. Blazakis disassembles this function and shows that, depending on `flags`, it either calls into `libsandbox.dylib` to compile and apply a profile, or bypasses `libsandbox` and goes directly to the kernel. In the common case (`flags` nonzero), `sandbox_init` loads `libsandbox`, calls one of the `sandbox_compile_*` functions (e.g., `sandbox_compile_string`, `sandbox_compile_file`, `sandbox_compile_named`), then calls `sandbox_apply` with the resulting compiled profile, and finally `sandbox_free_profile`. There is a special case with `flags == 0` (used by `sandbox-exec -p`) where the `profile` string is treated as a full SBPL policy rather than a named profile.

`sandbox-exec` itself is a thin CLI wrapper over `sandbox_init`. With the `-p` flag it passes a literal SBPL profile string and uses `flags == 0`. With the `-n` flag it passes the *name* of a built-in profile and uses a “named profile” flag; the man page documents built-in profiles as `kSBXProfileNoInternet`, `kSBXProfileNoNetwork`, `kSBXProfileNoWrite`, `kSBXProfileNoWriteExceptTemporary`, and `kSBXProfilePureComputation`, which map to human-readable names like `no-internet`, `no-network`, etc. Those names are implemented by SBPL files under `/usr/share/sandbox` (for example, `bsd.sb`, `ntpd.sb`, `named.sb`, `sshd.sb`), which are compiled by `libsandbox`.

Underneath `sandbox_apply` sits an internal stub `__sandbox_ms` in `libSystem`, which is a very small wrapper around the generic MAC syscall `__mac_syscall`. It invokes `__mac_syscall` with a fixed syscall number (381 on the examined system) and three arguments: a policy name string (here `"Sandbox"`), an integer `call` that identifies the sandbox operation to perform, and a pointer to an operation-specific argument structure. `__mac_syscall` looks up the MAC policy module by name and dispatches to its syscall handler in the kernel. Blazakis identifies the kernel-side implementation as `com.apple.security.sandbox` (`Sandbox.kext`), which is registered as a TrustedBSD MAC policy with the name `"Sandbox"`.

Inside `Sandbox.kext`, there is a dispatcher (often called `hook_policy_syscall` in the paper’s reverse-engineered naming) that branches on the `call` number. Key calls include:

* A call that installs a *raw* compiled profile buffer (undocumented “RAW” interface).
* A call that installs a kernel-resident built-in profile (`SANDBOX_NAMED_BUILTIN`).
* A call that queries whether a particular operation would be allowed or denied under the current profile (a “would this be denied?” query interface).

The library-level `SANDBOX_NAMED` mode (named profiles like `no-internet`) is handled entirely in `libsandbox`, which compiles SBPL to a raw profile blob and then uses the RAW interface to install it; `SANDBOX_NAMED_BUILTIN` is a kernel-only mechanism for applying precompiled profiles baked into the kext. On RAW or NAMED_BUILTIN calls, the kernel copies the profile blob from user space, verifies its size, allocates a buffer, and passes that buffer into `re_cache_init`, which prepares regex caches (via `AppleMatch.kext`). It then creates a per-process sandbox state object (via `sandbox_create`) and attaches it to the process’s TrustedBSD label slot using `proc_apply_sandbox`. From that point on, the process is constrained by the profile.

Enforcement occurs at TrustedBSD MAC hooks. `Sandbox.kext` registers a policy operations table (`policy_ops`) via `mac_policy_register`, supplying callbacks for a range of operations (filesystem, Mach IPC, sockets, mount controls, etc.). Each hook constructs a small “filter context” for the current operation (paths and vnodes for filesystem operations, socket addresses and ports for networking, process/signal identifiers for signals, and so on) and then calls a central evaluator `sb_evaluate(opcode, context)`. For example, a filesystem control hook (`hook_mount_check_fsctl`) can defer to `cred_check`, which in turn calls `sb_evaluate` with the operation code for `system-fsctl`. `sb_evaluate` walks the profile’s compiled decision tree and returns a boolean allow/deny. The MAC hook then translates a deny into an appropriate errno (often `EPERM`) and returns it to the caller.

Regular expression matching in path-based filters is offloaded to `AppleMatch.kext`. The compiled profile encodes a table of regex blobs. `re_cache_init` iterates over them, and for each it calls `matchInit` and `matchUnpack` (AppleMatch entry points) to build internal NFA structures. Later, when `sb_evaluate` needs to check a path, it uses `matchExec` against the appropriate compiled regex; when profiles are torn down, `matchFree` is used to release regex resources. This design keeps the sandbox kernel code mostly focused on glue and decision-tree traversal, delegating complex pattern matching to a dedicated regex engine.

---

## 3. Language and policy model (SBPL as seen here)

Blazakis recovers the sandbox profile language (SBPL) from the user-space side by inspecting `libsandbox.dylib`, extracting its Scheme files (`init.scm`, `sbpl_stub.scm`, `sbpl_1_prelude.scm`, `sbpl_1.scm`), and running them under TinyScheme. The stub comment and code spell out the semantic model: evaluating a profile populates a global vector `*rules*`. Each element of `*rules*` corresponds to a specific operation code and is a list of rules. Each rule is either:

* A **test**: conceptually `(filter action . modifiers)`, where `filter` is a predicate (e.g., path match), `action` is usually `allow` or `deny`, and `modifiers` carry extra metadata (e.g., debug flags).
* A **jump**: `(#f . operation)`, which means “stop evaluating rules for this operation and continue with the rules list for the given operation.”

Evaluation is straightforward: for a given operation, take the rules list from `*rules*` and scan it from the beginning. For each rule, if it is a `test`, check whether the filter matches; if it matches, return that rule’s action. If it is a jump, replace the current operation with the target operation and start evaluating that other operation’s rule list. The last rule for an operation must either have a `#t` (“always true”) filter or be a jump, to guarantee termination.

The paper identifies a set of operations (numbered opcodes) with symbolic names like `file-read-data`, `file-write-data`, `sysctl-write`, and so forth. The first 59 operation codes correspond to such operations. For example, `file-read-data` may be opcode 5, and the sixth entry in `*rules*` can be a pure jump `(#f . 0)`, which means “use the rules for operation 0 as the default.” This shows that SBPL’s “default” behavior is just a particular operation whose rule list can be reused via jumps. Profiles can thus express “default allow” or “default deny” once and then delegate many operation codes to that default. The author describes SBPL as a Scheme-embedded DSL whose job is to build a binary decision diagram for each operation; that diagram is what gets serialized and sent to the kernel, not the Scheme code itself.

The SBPL surface syntax is illustrated with real profile files like `named.sb`. A typical profile begins with `(version 1)` and a debug directive such as `(debug deny)`. It then imports a shared base profile with `(import "bsd.sb")`. The profile sets a global stance with something like `(deny default)`, and then whitelists broad operation families, for example: `(allow process*)` to permit process-related operations, `(allow network*)` to permit networking, while explicitly denying sensitive families such as `signal` (e.g., `(deny signal)`). It can also selectively enable operations like `(allow sysctl-read)`.

After establishing these high-level permissions, the profile refines file access using path filters. For example, it may allow `file-write*`, `file-read-data`, and `file-read-metadata` only for paths that match specific `regex` expressions: its PID file, various log files, configuration files, and data directories. In SBPL, such rules look like “allow this file operation when `path` matches one of these regular expressions.” This language view surfaces three main concepts:

* **Operations**: discrete capability types, often grouped with wildcards (e.g., `file-read*`, `file-write*`, `process*`, `network*`).
* **Filters**: predicates over attributes of the operation (e.g., `path` via regex; and by implication other attributes like xattrs, file modes, Mach ports, socket endpoints, signals).
* **Actions and defaults**: rule-ordered `allow`/`deny` decisions, with jump-based sharing and a designated “default” operation.

To inspect the intermediate `*rules*` representation, Blazakis modifies TinyScheme to support Apple’s custom string syntax (`#"..."` as a “sharp expression”) and defines dummy variables (`*params*`) and helper functions (`%version-1`). He then loads a real SBPL profile (e.g., `ntpd.sb`), evaluates it, and prints `*rules*`. The printed structure is a vector of rule lists: some entries are simple jumps (`((#f . 0))`), others begin with a path filter test followed by an `allow` action and a jump. This validates that SBPL compilation first builds a clear, symbolic rules table before lowering it into the binary decision-tree format used by the kernel.

---

## 4. Compilation, internal format, and enforcement mechanics

On the user-space side, the key consolidation point is a function typically named `compile` inside `libsandbox.dylib`. All public compilation functions (`sandbox_compile_string`, `sandbox_compile_file`, `sandbox_compile_named`) ultimately call this function. For example, `sandbox_compile_string` simply forwards the SBPL string to `compile`, whereas `sandbox_compile_named` resolves the named profile to a file, then calls `sandbox_compile_file`, which again ends in `compile`. After compilation, the caller receives a pointer/length pair representing the compiled profile blob.

`sandbox_apply` then takes this blob, optionally sets up tracing (sandbox violation notifications via a Mach service), and calls the `__sandbox_ms` stub with the RAW call code and the blob pointer. On the kernel side, the RAW handler in `Sandbox.kext` copies the argument structure from user space, validates the profile length, allocates kernel memory, copies the blob, and then constructs a sandbox state object that includes a pointer to this blob and a regex cache. It passes the blob into `re_cache_init`, which parses the header and initialises regex caches via `AppleMatch.kext`. Finally, the sandbox state is attached to the current process via `proc_apply_sandbox`.

Blazakis reconstructs the compiled format by analyzing how `re_cache_init` and `sb_evaluate` walk through it. At a high level, the layout looks like this:

* **Header**:

  * A 16-bit little-endian `re_table_offset` indicating where the regex index table begins, expressed in 8-byte words from the start of the profile.
  * An 8-bit `re_table_count` indicating how many regexes are present.
  * Padding and then an array of 16-bit operation offsets, `op_table[]`, again expressed in 8-byte word units, with one entry per operation code.

* **Regex table**:

  * At `re_table_offset` there is an array of 16-bit offsets, each pointing to a regex blob.
  * Each regex blob begins with a 32-bit size field followed by the raw regex bytes.
  * `re_cache_init` iterates over the `re_table_count` regexes, calls `matchInit` and `matchUnpack` on each blob to create an NFA, and stores the resulting structures in a cache alongside the profile.

* **Operation handlers (`ophandlers`)**:

  * A set of variable-sized nodes forming decision trees.
  * Each node begins with a 1-byte `opcode`:

    * `0x01` for a terminal node.
    * `0x00` for a non-terminal node (internal decision node).
  * For a **terminal** node, the node contains a small result field, e.g., a byte that encodes the action (`allow` or `deny`); this corresponds to the “action” in a SBPL test.
  * For a **non-terminal** node, the node layout is:

    * `filter`: a 1-byte discriminator indicating which attribute to test:

      * `0x01` = path
      * `0x02` = xattr
      * `0x03` = file mode
      * `0x04` = Mach global
      * `0x05` = Mach local
      * `0x06` = socket local
      * `0x07` = socket remote
      * `0x08` = signal
    * `filter_arg`: a 2-byte index that selects a particular filter instance (e.g., an index into the regex table for path filters).
    * `transition_matched`: a 2-byte offset to the next node if the filter matches.
    * `transition_unmatched`: a 2-byte offset to the next node if the filter does not match.

At runtime, `sb_evaluate(opcode, context)` performs the following steps:

1. Look up `opcode` in `op_table` to get the offset of the first op-handler node for that operation.
2. Jump to that node in the `ophandlers` region.
3. While the current node is non-terminal:

   * Look at the `filter` field and, based on it, extract the relevant attribute from the `context` (e.g., a path string, an xattr value, a Mach port, a socket address, a signal number).
   * If the filter is a path-type filter, look up the corresponding regex (using `filter_arg` as index), and call `matchExec` from `AppleMatch` to test the path.
   * Based on whether the filter matched, follow either `transition_matched` or `transition_unmatched` to the next node.
4. When a terminal node is reached, return its result (`allow` or `deny`).

This is a direct, compact encoding of the ordered rule lists in `*rules*`: the node graph corresponds to a binary decision diagram whose leaves are allow/deny actions. Jumps between operations in `*rules*` correspond to op-table entries that simply point to the same handler tree or to nodes that quickly transition into the tree for another operation. The MAC hooks interpret the result and turn it into a kernel return code (success or an error like `EPERM`).

The third MAC syscall sub-call exposed by `Sandbox.kext` allows a process to query its current policy (“would this operation, with this context, be denied?”) without actually performing the operation. It passes an opcode and a context-like structure into the same `sb_evaluate` machinery. This is not the main enforcement path, but it reuses the same compiled profile representation and is useful for debugging or preflight checks.

---

## 5. Patterns in built-in profiles

The paper examines Apple’s stock profiles both in their SBPL form under `/usr/share/sandbox` and via the compiled/intermediate structures described above. The built-in profiles exposed via `sandbox_init` constants and the `sandbox-exec` man page (`kSBXProfileNoInternet`, `kSBXProfileNoNetwork`, `kSBXProfileNoWrite`, `kSBXProfileNoWriteExceptTemporary`, `kSBXProfilePureComputation`) have human-oriented descriptions like “TCP/IP networking is prohibited,” “all sockets-based networking is prohibited,” “filesystem writes are prohibited,” “writes are restricted to temporary locations,” and “all operating system services are prohibited.” Although the paper focuses more on service-specific profiles, these built-ins seem to follow the same structural patterns: a strong default stance plus targeted whitelists for the few operations still allowed.

Service profiles such as `named.sb` and `ntpd.sb` provide richer examples. A typical pattern is:

1. Declare version and debugging: `(version 1)`, `(debug deny)`.
2. Import a shared base: `(import "bsd.sb")`.
3. Set a default: `(deny default)` or `(allow default)` depending on the service.
4. Enable or disable broad operation families, e.g., `(allow process*)`, `(allow network*)`, `(deny signal*)`, `(allow sysctl-read)`.
5. Add path-based rules for file operations using `regex`, e.g., allowing `file-read*` and `file-write*` on the PID file, log files, configuration files, runtime state under `/var`, standard libraries under `/usr/lib` and `/System/Library`, locale/timezone data, etc.

When Blazakis inspects the intermediate `*rules*` for `ntpd.sb`, he finds that many operation entries are simple jumps back to a default entry (e.g., `((#f . 0))`), meaning “this operation behaves just like the default.” Operations that require special treatment have rules like `(((filter path 0 regex …) allow) (#f . 4))`: first check a path filter, and if it matches, allow; otherwise, jump to another operation whose rules may deny or further refine. These path regexes enumerate sets of required files: device nodes such as `/dev/null` and randomness devices, configuration files under `/etc`, runtime drift files under `/var/db`, and various libraries and resource directories.

Two recurring idioms from the paper are particularly useful for capability cataloging:

* **Operation grouping with shared defaults:** Many SBPL `allow` directives are wildcarded, like `allow network*` or `allow process*`, which correspond to families of concrete opcodes. In the internal representation, many of these opcodes point to the same decision tree or immediately jump to a shared default operation. For cataloging, this means the “capability space” has a smaller set of canonical behaviors (e.g., “default deny for file-read,” “default allow for process control”) that are shared across many specific operations.

* **Path-centric whitelisting for filesystem capabilities:** Service profiles carve out their needed filesystem capabilities primarily via `path` filters backed by regexes. Rather than granting broad “read anywhere” or “write anywhere” permissions, they typically grant `file-read*`/`file-write*` for specific path sets, implemented as regex lists compiled into `AppleMatch` NFAs. From a capability perspective, these are best understood not as a single “file-read” capability but as many distinct path-scoped capabilities, each tied to one or more regex filters.

Overall, the paper reveals that Apple’s sandbox policies are constructed from a relatively small vocabulary of operations and filters, organised around default-then-whitelist patterns and heavily reliant on path-based regex filtering for filesystem isolation. That structure maps naturally onto a capability catalog: operations (opcodes) define the axes of capability; filters (especially path filters) define the scope; and the decision-tree topology (defaults, jumps, and terminal actions) defines how those capabilities interact and compose across profiles.
