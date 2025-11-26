>SUBSTRATE_2025-frozen
## 1. Short orientation (1–2 paragraphs)

The paper provides a concrete, implementation-level walk from user processes calling `sandbox_init` down through `libSystem`, `libsandbox.dylib`, the Scheme/TinyScheme layer, the compiled binary profile format, the TrustedBSD policy plumbing, `Sandbox.kext`, and finally the `AppleMatch.kext` regex engine. It is explicitly aimed at reverse engineers and names many functions, data structures, and byte-level layouts.

As an implementation skeleton and repo-alignment guide, you can treat the paper as the canonical map of: (a) where policy text is turned into *rules* and then into a binary decision tree, (b) how that binary profile is passed to the kernel and stored as per-process state, and (c) how the kernel’s `Sandbox.kext` evaluates operations by walking that decision tree and invoking AppleMatch’s NFA regex engine. The list of symbols and layouts below is meant to drive concrete greps and code-reading passes in this project and the corresponding XNU sources.

---

## 2. Symbol and structure inventory

I’ll group symbols by layer. Within each, I list name (as in paper), role, and any naming notes.

### 2.1 Userland interfaces and libraries

* `sandbox_init`

  * Role: Public API function (in `libSystem.dylib`) that applications call to enter a sandbox. It routes to either `libsandbox.dylib` “compile + apply” flows or a direct syscall stub depending on flags.
  * Notes: Paper emphasizes this as the starting point for tracing into both userspace and kernel implementation.

* `sandbox-exec`

  * Role: Command-line wrapper that calls `sandbox_init` before `fork`/`exec`, exposing all ways to supply a profile (named built-in, file, inline string).
  * Notes: The manpage is reproduced; useful as a reference for flags and behaviour, less so for internal details.

* `sandbox_init` manpage flags and constants

  * `SANDBOX_NAMED`

    * Role: Flag meaning `profile` argument is a symbolic named profile like `kSBXProfileNoInternet`.
  * `SANDBOX_NAMED_BUILTIN` (value 2)

    * Role: Flag where `sandbox_init` skips `libsandbox` and calls `sandbox_ms` directly to use compiled built-in profiles.
  * Undocumented flag `0`

    * Role: When `flags == 0`, `sandbox_init` interprets `profile` as the full SBPL profile string (used by `sandbox-exec -p`).

* Built-in profile constants (C strings)

  * `kSBXProfileNoInternet`, `kSBXProfileNoNetwork`, `kSBXProfileNoWrite`, `kSBXProfileNoWriteExceptTemporary`, `kSBXProfilePureComputation`
  * Role: Named profiles used with `SANDBOX_NAMED`; their actual string values (e.g., `"no-internet"`) are looked up and then passed to `sandbox-exec -n`.

* `sandbox_free_error`

  * Role: API to free the error buffer returned by `sandbox_init`; included in the manpage.
  * Notes: Important for API completeness but not central to internals.

* `__mac_syscall`

  * Role: Kernel entry for the MAC syscall; paper uses a GDB breakpoint here to capture that sandboxing goes through a MAC syscall.
  * Notes: At runtime, the actual symbol hit is `__sandbox_ms` (next item).

* `__sandbox_ms` / `sandbox_ms`

  * Role: Stub in `libSystem` implementing the MAC syscall path used by sandboxing. It takes a string policy name (e.g., `"Sandbox"`) plus parameters and proxies to the kernel MAC framework.
  * Notes: Paper shows a GDB session that breaks in `__sandbox_ms` and inspects the policy-name string argument to discover `"Sandbox"`.

### 2.2 libsandbox.dylib and SBPL compilation

* `libsandbox.dylib`

  * Role: Private library that contains the Scheme interpreter, SBPL front-end, profile compiler, and some tracing support.

* `sandbox_compile_string`

  * Role: Exported `libsandbox` function called from `sandbox_init` to compile a profile supplied as an in-memory string.
  * Notes: Paper says this is a simple proxy that forwards to the unexported `compile` function. The text prints it with spaces (“sandbox compile string”) but context makes clear it is the C symbol.

* `sandbox_compile_file`

  * Role: Exported function that compiles a profile from a file path; used when `sandbox_init` is given a path.
  * Notes: Again described as ending in a call to `compile`.

* `sandbox_compile_named`

  * Role: Exported function that locates and compiles a named profile (e.g., a `.sb` file under `/usr/share/sandbox`).
  * Notes: Paper specifies that `sandbox_compile_named` ends in a call to `sandbox_compile_file`, which in turn calls `compile`.

* `compile` (unexported)

  * Role: Core profile compiler in `libsandbox.dylib`. It drives TinyScheme, loads SBPL scripts, and transforms Scheme-level rules into the binary profile format passed to the kernel.
  * Notes: Described as having a highly branched control-flow graph (“where all the magic happens”).

* `sandbox_apply`

  * Role: Function in `libsandbox.dylib` that wraps tracing-related Mach setup and ultimately invokes the syscall stub (`sandbox_ms`) to install the compiled profile in the kernel.
  * Notes: Paper points out that if you ignore tracing machinery, `sandbox_apply` is effectively a proxy around the syscall stub.

* `sandbox_free_profile`

  * Role: Function that frees memory allocated by the `sandbox_compile_*` functions (profile buffer, etc.).
  * Notes: Implementation is mostly calls to `free`.

* TinyScheme / Scheme loading symbols

  * `TinyScheme`

    * Role: Upstream Scheme interpreter `libsandbox` is based on.
  * `scheme_load_string` (name appears truncated in the paper text)

    * Role: Scheme interpreter helper used by `compile` to load SBPL prelude and profile text into the interpreter.
    * Notes: Paper calls out this as an “interesting call” when stepping through `compile`.

* Scheme and SBPL scripts / entry forms

  * `sbpl_stub.scm`, `sbpl_1_prelude.scm`, `sbpl_1.scm`

    * Role: Scheme-level implementation of SBPL; loaded by TinyScheme inside `libsandbox`.
    * Notes: Paper explicitly shows running them under stock TinyScheme for experimentation.
  * `*rules*` (Scheme vector)

    * Role: Key Scheme-level structure: a vector of rules, one per operation. Index 0 is the “default” operation; entries 1..N correspond to operations like `file-read-data`. Each entry is a list of rule clauses compiled from SBPL.
    * Notes: On OS X 10.6.4, first 59 entries correspond to operations; example shows `file-read-data` at operation code 5.
  * Rule encodings inside `*rules*`

    * `(#f . 0)`

      * Role: JUMP rule: “fall back to operation 0 (default)”.
    * `(#t deny)` / `(#t allow)`

      * Role: terminal rule entries representing unconditional deny/allow.
    * `((filter path 1 path regex /bin/*) allow) ...`

      * Role: Example of a rule with filters and actions; illustrates the higher-level decision structure prior to binary compilation.
  * `%version-1`

    * Role: Scheme-level function defined in `libsandbox.dylib` that orchestrates SBPL evaluation for `(version 1)` profiles. It sets up the interpreter, loads prelude, and drives rule construction into `*rules*`.
  * `take`, `drop`

    * Role: Additional Scheme functions provided in `libsandbox`’s init script beyond stock TinyScheme; necessary for SBPL support.

* TinyScheme modifications

  * Raw string sharp expression `#"..."`

    * Role: Syntax extension added by Apple to support raw strings in SBPL (used especially with regex filters).
    * Notes: Paper describes discovering this as an undefined “sharp expression” in unpatched TinyScheme and reconstructing the patch.

### 2.3 Kernel: TrustedBSD and Sandbox.kext

* `Sandbox.kext`

  * Role: Kernel extension implementing the TrustedBSD MAC policy named `"Sandbox"`. It enforces compiled sandbox profiles on system calls.

* `mac_policy_register`

  * Role: TrustedBSD API function called from `Sandbox.kext` when the extension is loaded to register the sandbox policy, its hooks, and label slots.

* `_kmod_start` / `kmod_start`

  * Role: Kernel module entry point for `Sandbox.kext`; responsible for calling `mac_policy_register`.

* `policy_ops` table (“policy ops table”)

  * Role: Struct of function pointers implementing all MAC hooks for the sandbox policy (vnode operations, networking, etc.). Each entry is a “hook_*” function.
  * Notes: Paper describes inspecting hook bodies and seeing them call `sb_evaluate`.

* `hook mount check fsctl`

  * Role: One example of a specific hook implementation (for filesystem control). It calls `cred_check`, passing an operation code (via register) that identifies the sandbox operation to evaluate.
  * Notes: Paper spells the name with spaces (“hook mount check fsctl”); the underlying C symbol presumably uses underscores.

* `cred_check`

  * Role: Helper function used by MAC hooks. It takes an operation code (via a register in the calling convention) and a filter context, and proxies a call to `sb_evaluate`.
  * Notes: Paper notes that in the `hook mount check fsctl` path, `cred_check` is called with operation code `0x30` (representing `system-fsctl`).

* `operation_names` table

  * Role: Table mapping numeric operation codes (e.g., `0x30`) to human-readable strings (`"system-fsctl"`, `file-read-data`, etc.). Used for introspection and logging.
  * Notes: Paper references this when explaining how the `0x30` operation is identified.

* `hook policy syscall`

  * Role: TrustedBSD hook that handles the sandbox initialization syscall for a process. It parses the incoming profile blob, sets up regex caches, constructs the sandbox state structure, and attaches it to the process.
  * Notes: Paper refers to it in prose as “hook policy syscall”; the corresponding C symbol likely uses underscores.

* `re_cache_init` (“re cache init”)

  * Role: Function in `Sandbox.kext` that iterates over all compiled regular expressions in the profile, calling `matchInit` and `matchUnpack` for each to build a regex cache.
  * Notes: There is an explicit byte layout for the regex cache table (see section 4).

* `sandbox_create`

  * Role: Function that allocates the main per-policy state structure, sets up a lock, and stores pointers to the profile bytecode and regex cache.

* `proc_apply_sandbox`

  * Role: Function that ultimately stores the constructed sandbox state structure into a TrustedBSD “policy label slot” on the process. This marks the effective end of sandbox initialization for that process.

* `sb_evaluate`

  * Role: Core evaluator for compiled sandbox profiles in the kernel. It takes an operation code and filter context, walks the decision tree encoded in the profile, consults regex caches, and returns allow/deny decisions.
  * Notes: Paper stresses that reversing `sb_evaluate` reveals the full compiled profile format.

* TrustedBSD label slot (“policy label slot”)

  * Role: Per-credential or per-process storage allocated by TrustedBSD for each policy; `Sandbox.kext` uses it to store the sandbox state structure created by `sandbox_create`.

### 2.4 Kernel: AppleMatch.kext and regex engine

* `AppleMatch.kext`

  * Role: Kernel extension that provides regex/NFA matching services to `Sandbox.kext`.

* Imported functions from AppleMatch.kext

  * `matchInit`

    * Role: Initializes a state structure (`matchExpr_t`) for a compiled regex, using caller-provided alloc/free callbacks.
  * `matchUnpack`

    * Role: Takes a serialized regex blob and unpacks it into the state structure created by `matchInit`.
  * `matchExec`

    * Role: Runs the NFA over input strings, determining whether the regex matches.
  * `matchFree`

    * Role: Frees regex state previously created by `matchInit` / `matchUnpack`.

* Regex-related typedefs and structs

  * `typedef void *(*m_alloc_func)(unsigned int size, const char *note);`
  * `typedef void (*m_free_func)(void *addr, const char *note);`
  * `struct matchExpr; typedef struct matchExpr matchExpr_t;`
  * `struct matchInput { unsigned char *start; unsigned char *end; }; typedef struct matchInput matchInput_t;`
  * `int matchExec(matchExpr_t *m, matchInput_t *inputs, unsigned int *input_count, unsigned int *result);`
  * Role: Together define the API by which `Sandbox.kext` initializes regex state and executes matches.

### 2.5 Binary profile and regex layouts

* Regex table layout in sandbox profiles (as used by `re_cache_init`)

  * Header fields:

    * `u16_le re_offset_table_offset` (in 8-byte words)
    * `u8 re_offset_table_count`
  * At `re_offset_table_offset`:

    * `u16_le re_offset[re_offset_table_count]`
  * At each `re_offset[n]`:

    * `u32_le re_size`
    * `u8 re_bytes[re_size]`
  * Role: Enumerates the compiled regex blobs embedded in the sandbox profile.

* Sandbox profile header and op handler layout (as deduced from `sb_evaluate`)

  * Header:

    * `u2 re_table_offset` (8-byte words from start of profile)
    * `u1 re_table_count` (low byte)
    * `u1 padding`
    * `u2[] op_table` (8-byte word offsets; one per operation)
  * Operation handler entries (“ophandlers”):

    * `u1 opcode`

      * `01`: terminal node
      * `00`: non-terminal node
  * Terminal node body:

    * `u1 padding`
    * `u1 result`

      * `00`: allow
      * `01`: deny
  * Non-terminal node body:

    * `u1 filter`

      * `01`: path
      * `02`: xattr
      * `03`: file-mode
      * `04`: mach-global
      * `05`: mach-local
      * `06`: socket-local
      * `07`: socket-remote
      * `08`: signal
    * `u2 filter_arg`
    * `u2 transition_matched`
    * `u2 transition_unmatched`
  * Role: Encodes a decision tree per operation, which `sb_evaluate` traverses using filter context and regex caches.

* Regex NFA layout inside each compiled regex blob (AppleMatch format)

  * Header:

    * `u4 version` (must be 1 or unpack fails)
    * `u4 node_count`
    * `u4 start_node`
    * `u4 end_node`
    * `u4 cclass_count`
    * `u4 submatch_count`
    * `node nodes[]`
    * `cclass cclasses[]`
  * `node`:

    * `u4 type`
    * `u4 arg`
    * `u4 transition`
  * `cclass`:

    * `u4 count`
    * `u4 spans[]`
  * Role: Represents the NFA structure executed by `matchExec`.

---

## 3. Phase-oriented implementation skeleton

This section follows the phases the paper describes, with concrete call skeletons and key symbols.

### 3.1 Profile authoring and SBPL/Scheme representation

High-level description:
Human authors write sandbox profiles in SBPL (a Scheme-derived EDSL) either as `.sb` files or inline strings. These are evaluated by a modified TinyScheme interpreter in `libsandbox.dylib`, which produces a Scheme vector `*rules*` mapping operations to rule lists.

Key symbols:

* `sandbox_init` (user entry)
* `sandbox-exec` (wrapper)
* TinyScheme interpreter in `libsandbox.dylib`
* `sbpl_stub.scm`, `sbpl_1_prelude.scm`, `sbpl_1.scm`
* `*rules*` (Scheme vector), `%version-1`, `take`, `drop`
* Sharp-string syntax `#"..."`

Pseudo-call skeleton (phase 1):

* Application calls `sandbox_init(profile, flags, &errorbuf)`.
* For flags that require dynamic compilation (e.g., path or string profiles), `sandbox_init` locates and loads `libsandbox.dylib` and calls one of `sandbox_compile_string`, `sandbox_compile_file`, or `sandbox_compile_named`.
* Inside `sandbox_compile_*`, control is forwarded to `compile`.
* `compile` initializes TinyScheme, loads initial scripts (`sbpl_stub.scm`, `sbpl_1_prelude.scm`, `sbpl_1.scm`) via functions like `scheme_load_string`, and invokes `%version-1` with the SBPL profile.
* `%version-1` evaluates SBPL forms, populating the `*rules*` vector with rule lists; each vector slot corresponds to an operation and contains filter/action clauses or fall-through jumps.
* Once `*rules*` is constructed, `compile` translates each rule into the binary profile format described in section 4 (header, op_table, op handlers, regex table).

### 3.2 Compilation / translation to binary format

High-level description:
`compile` converts Scheme-level rules (`*rules*`) into a compact binary profile layout comprising: a header, a regex offset table with embedded compiled regex NFAs, and per-operation decision trees.

Key symbols:

* `compile` (unexported)
* `*rules*` (Scheme vector)
* Regex table layout (re_offset_table, re_offset entries)
* Binary profile header (`re_table_offset`, `re_table_count`, `op_table[]`)
* Node encodings (terminal vs non-terminal; filter codes, transitions)

Pseudo-call skeleton (phase 2):

* For each operation index `i` in `*rules*`, `compile` walks the rule list to construct a tree of tests and jumps.
* For each regex filter encountered, it compiles the regex into a serialized NFA blob and adds an entry to the regex table (`re_offset_table`).
* After all operations are processed, `compile` builds a header: sets `re_table_offset`, `re_table_count`, and fills `op_table[]` with offsets to the first node of each operation’s decision tree.
* It then writes out a contiguous buffer containing header, op_table, op handler nodes, and regex blobs.
* The resulting buffer and length are returned to the caller (e.g., `sandbox_compile_string`).

### 3.3 Profile loading and registration with the kernel

High-level description:
`libsandbox` passes the compiled binary profile to the kernel using the MAC syscall, targeting the TrustedBSD policy named `"Sandbox"`. `Sandbox.kext` registers itself at load time with TrustedBSD and receives this profile in a policy-specific syscall hook.

Key symbols:

* `sandbox_apply`
* `sandbox_ms` / `__sandbox_ms`
* `__mac_syscall`
* `mac_policy_register`
* `Sandbox.kext`
* `kmod_start`
* `hook policy syscall`

Pseudo-call skeleton (phase 3):

* After successful compilation, `sandbox_init` calls `sandbox_apply` with the compiled profile.
* `sandbox_apply` optionally sets up tracing (Mach messages for sandbox logging), then calls `sandbox_ms` with the policy name `"Sandbox"` and the profile arguments.
* `sandbox_ms` executes the MAC syscall through `__mac_syscall`, passing the policy name and profile blob into the kernel.
* TrustedBSD locates the registered policy implementation by name (`"Sandbox"`) and dispatches the request to `Sandbox.kext`, into the `hook_policy_syscall` handler.
* `hook_policy_syscall` receives the profile blob and initiates sandbox-specific initialization: parsing, regex cache creation, and state structure allocation.

### 3.4 Label/credential setup and association with processes

High-level description:
Within `Sandbox.kext`, the parsed profile and associated regex state are stored in a per-policy state structure, which gets attached to the process’s TrustedBSD label slot via `proc_apply_sandbox`.

Key symbols:

* `re_cache_init`
* Regex table layout (`re_offset_table_offset`, `re_offset_table_count`, `re_offset[n]`)
* `sandbox_create`
* `proc_apply_sandbox`
* TrustedBSD “policy label slot”

Pseudo-call skeleton (phase 4):

* `hook_policy_syscall` calls `re_cache_init` with the profile blob.
* `re_cache_init` interprets the header fields `re_offset_table_offset` and `re_offset_table_count` to locate the list of regex offsets.
* For each `re_offset[n]`, it reads `re_size` and `re_bytes[]`, calls `matchInit` to allocate regex state, then `matchUnpack` to load the serialized NFA into a `matchExpr_t`.
* `re_cache_init` assembles a regex cache structure that maps profile-internal identifiers to `matchExpr_t` pointers.
* Back in `hook_policy_syscall`, `sandbox_create` is called. It allocates a state structure, initializes a lock, and stores pointers to both the original profile bytecode and the regex cache.
* The function `proc_apply_sandbox` stores this state structure in the TrustedBSD label slot associated with the process. Once `proc_apply_sandbox` returns, sandbox initialization for the process is effectively complete.

### 3.5 Hook invocation and context construction

High-level description:
After initialization, every MAC hook implemented by `Sandbox.kext` consults the sandbox state when certain operations occur (e.g., file access, network operations). Hook bodies are thin; they construct a filter context and call into `sb_evaluate` via `cred_check`.

Key symbols:

* `policy_ops` table
* `hook mount check fsctl` (representative hook)
* `cred_check`
* `sb_evaluate`
* `operation_names` table

Pseudo-call skeleton (phase 5):

* A kernel event (e.g., `mount` with `fsctl`) triggers a TrustedBSD hook. For the sandbox policy, this dispatches to a function like `hook mount check fsctl`.
* The hook locates the process’s sandbox state from its label slot and builds a filter context (containing path, vnode info, mach port names, socket endpoints, etc., depending on operation type).
* The hook calls `cred_check` with the operation code in a designated register (e.g., `edx = 0x30` for `system-fsctl`) and a pointer to the filter context.
* `cred_check` is essentially a wrapper around `sb_evaluate`, passing through the operation code and filter context.
* For debugging/introspection, `sb_evaluate` and/or surrounding code can use the `operation_names` table to map the numeric op code to a string name.

### 3.6 Rule evaluation and decision production

High-level description:
`sb_evaluate` is the interpreter for the compiled decision-tree representation. It uses the operation code to choose a starting node via `op_table`, then walks nodes according to filters and filter results, including regex matches via AppleMatch.

Key symbols:

* Profile header (`re_table_offset`, `re_table_count`, `op_table[]`)
* Node encoding (opcode, result, filter, filter_arg, transitions)
* Filter-type space (path, xattr, file-mode, mach-global, mach-local, socket-local, socket-remote, signal)
* `sb_evaluate`
* AppleMatch functions (`matchExec`)

Pseudo-call skeleton (phase 6):

* `sb_evaluate` takes inputs: sandbox state structure (with pointers to profile and regex cache), operation code, and filter context.
* It uses the operation code as an index into `op_table[]` to get the offset of the root node for that operation’s decision tree.
* It reads the node’s `opcode` byte.

  * If `opcode == 1` (terminal), it reads `result` and returns allow/deny.
  * If `opcode == 0` (non-terminal), it reads the `filter` code and `filter_arg` and evaluates the filter against the context:

    * For path-based filters, it will likely use the regex cache and call `matchExec` on a `matchExpr_t` corresponding to `filter_arg`.
    * For other filters (xattr, file-mode, mach-local/global, sockets, signal), it inspects corresponding fields in the filter context.
* Based on whether the filter matches or not, `sb_evaluate` uses `transition_matched` or `transition_unmatched` to jump to the next node (offset index).
* This process repeats until a terminal node is reached, producing a final allow/deny decision.

### 3.7 Supporting machinery: tracing and logging

High-level description:
The paper notes that `sandbox_apply` and `Sandbox.kext` have support for tracing sandbox decisions via Mach messages to a userspace helper (`sandboxd`), and for simplifying traces back into SBPL via `sandbox-simplify`.

Key symbols:

* `sandboxd` (Mach server)
* Mach message tracing directives in profiles
* `sandbox-simplify` (userland helper tool)

Pseudo-call skeleton (phase 7):

* If a profile includes trace directives, `sandbox_apply` sets up Mach communication so that before each access control check, `Sandbox.kext` sends a Mach message describing the operation and arguments.
* These messages go to `sandboxd`, which logs them (e.g., to disk).
* A utility like `sandbox-simplify` post-processes logs into candidate SBPL rules, aiding profile construction and debugging.

---

## 4. Data structures and evaluator patterns

### 4.1 Compiled profile representation

There are three main layers of representation:

1. SBPL / Scheme (`*rules*` vector):

   * Each operation index maps to a list of rules. Rule clauses can be:

     * Jumps to another operation (e.g., `(#f . 0)`),
     * Simple allow/deny entries (e.g., `(#t allow)`),
     * Filtered actions (e.g., path-based allow/deny), possibly chaining multiple clauses.
   * Semantically, this is already a decision tree expressed in Scheme.

2. Binary sandbox profile (as seen by `Sandbox.kext`):

   * Header holds `re_table_offset`, `re_table_count`, and an array `op_table[]` of 16-bit offsets (in 8-byte words) to per-operation node sequences.
   * For each operation, the nodes form a small program:

     * Terminal nodes encode a result (allow/deny).
     * Non-terminal nodes encode:

       * `filter` type (path, xattr, file-mode, mach/mach-local, socket-local/remote, signal),
       * `filter_arg` (index into some auxiliary table or immediate),
       * `transition_matched` and `transition_unmatched` (indices into node array).
   * This is a classic decision-tree interpreter optimized for compactness.

3. Regex tables and NFA layout (AppleMatch format):

   * Regexes referenced by filters are serialized into compact NFA objects:

     * A header with counts and indices, followed by arrays of `node` and `cclass` structures.
     * Each `node` has a type, argument, and transition; `cclass` structures list character ranges.
   * `re_cache_init` bridges between sandbox profile layout and AppleMatch’s internal NFA representation using `matchInit` and `matchUnpack`.

### 4.2 Main evaluation algorithm pattern

The evaluation pattern is uniform across operations:

* Dispatch:

  * Operation code indexes into `op_table` to find the root node.

* Node traversal:

  * At each node:

    * If terminal: return decision.
    * If non-terminal: evaluate filter; follow matched/unmatched transitions.

* Filters:

  * Each `filter` value selects a different view of the filter context:

    * Path, xattr, file-mode: likely refer to filesystem-related arguments and might use regex caches (for path) or direct value comparison.
    * Mach-global / mach-local: inspect Mach port names/namespaces.
    * Socket-local / socket-remote: inspect addresses/ports or Unix-domain path.
    * Signal: inspect signal numbers or related metadata.

* Regex involvement:

  * For filters that use regexes (e.g., path, xattr), the evaluator uses `filter_arg` as an index into the regex cache, fetching a `matchExpr_t`, then calling `matchExec` with appropriate `matchInput_t` structures.
  * `matchExec` traverses the NFA and reports a boolean “match” via its `result` argument.

This pattern makes `sb_evaluate` the implementation focal point: it ties together binary profile parsing, filter contexts, AppleMatch regex state, and final decisions.

---

## 5. Repo-alignment, search hints, and priorities

### 5.1 Search hints

Below are concrete grep/inspection strategies. Where they go beyond explicit paper statements, I mark them as inferences.

#### 5.1.1 Userspace (`libSystem`, `libsandbox`, local scripts)

* `sandbox_init`

  * Search in XNU or libSystem sources for the exported `sandbox_init` API.
  * Follow its calls to locate the branch that loads `libsandbox.dylib` and the flag-based dispatch to `sandbox_compile_*` vs `sandbox_ms`.

* `sandbox_compile_string`, `sandbox_compile_file`, `sandbox_compile_named`

  * Search `libsandbox` sources for `sandbox_compile_string` and confirm each ends in `compile`.
  * In this repo, search for these names in any disassembly scripts or documentation; they likely appear in helpers that trace the compile pipeline.

* `compile`

  * In absence of symbols, look at IDA/ghidra function with a large, branching flow graph referenced by all `sandbox_compile_*` wrappers.
  * In this repo, search for scripts that refer to `*rules*` or `%version-1`; these will be adjacent to logic mirroring `compile`’s behaviour.

* TinyScheme and SBPL scripts (`sbpl_stub.scm`, `sbpl_1_prelude.scm`, `sbpl_1.scm`)

  * In this repo, search for these file names; the paper states that all scripts used in the analysis are provided there.
  * Inspect them to see how `%version-1` builds `*rules*` and how `take`, `drop`, and `#"..."` are used.

* `*rules*` and Scheme-level rules

  * In the Scheme sources, grep for `*rules*` and look for comments matching the paper’s description (“last rule must always match or jump”, etc.).
  * This gives you the intermediary format (Scheme decision trees) that parallels the final binary format.

#### 5.1.2 Kernel: Sandbox.kext and TrustedBSD integration

* Policy registration and `Sandbox.kext`

  * Search kernel sources for `"Sandbox"` in the context of MAC policy registration. This should find the `mac_policy_conf` for the sandbox and the call to `mac_policy_register`.
  * Look at the `policy_ops` struct for the sandbox; this will enumerate all hook functions (e.g., vnode, network, Mach).

* `hook policy syscall`

  * In the sandbox policy’s `policy_ops` struct, locate the entry corresponding to the sandbox initialization syscall; its implementation should match the “hook policy syscall” described.
  * From that function, follow calls to `re_cache_init`, `sandbox_create`, and `proc_apply_sandbox`.

* `re_cache_init`

  * Search `Sandbox.kext` sources for a function that iterates over regex entries and calls `matchInit`/`matchUnpack`. It may be named `re_cache_init` or similar.
  * Confirm that it interprets header fields like `re_offset_table_offset` and `re_offset_table_count`.

* `sandbox_create`, `proc_apply_sandbox`

  * Search `Sandbox.kext` for `proc_apply_sandbox` (or variants) and inspect its handling of label slots and state structures.
  * Look for a function allocating a struct with a lock and pointers to the profile blob and regex cache; this is your `sandbox_create`.

* `sb_evaluate`

  * Search the kernel tree or any local disassembly scripts for `_sb_evaluate`. It should be referenced by many hook functions.
  * Inspect its body to confirm it:

    * Uses `op_table` and node encodings described in the paper.
    * Interacts with regex cache when filters require it.

* `cred_check` and hook examples

  * Search for `cred_check` in sandbox-related kernel code.
  * Identify callers like `hook_mount_check_fsctl` and observe how they pass operation codes (e.g., through `edx`) and contexts to `cred_check` and `sb_evaluate`.

* `operation_names` table

  * Search `Sandbox.kext` for data tables containing strings like `"system-fsctl"`, `file-read-data`, etc.
  * These are part of `operation_names`. Cross-reference index of `0x30` with `system-fsctl` to verify the mapping described.

#### 5.1.3 AppleMatch.kext and regex

* `AppleMatch.kext` imports

  * Use tools like `nm` or `kextlibs` on `AppleMatch.kext` to confirm that it exports `matchInit`, `matchUnpack`, `matchExec`, and `matchFree`.
  * In sources or disassembly, locate the corresponding function bodies to compare with the paper’s prototypes.

* NFA layout and `matchExec`

  * Search for the `matchExec` prototype in local scripts or documentation that refers to AppleMatch.
  * Inspect the code that reads fields like `version`, `node_count`, `start_node`, `end_node`, etc., and confirm the NFA encoding matches the paper’s layout.

* Regex table parsing

  * In `Sandbox.kext`, look for code that reads `re_offset_table_offset` and iterates over `re_offset[n]` entries, then passes each blob to `matchInit` and `matchUnpack`.

#### 5.1.4 Inference-based repo hints

* Inference: search hint based on naming/structure patterns — local repo

  * Grep for `apple-scheme`, `*rules*`, `operation_names`, `sb_evaluate`, and `re_cache_init` in this repository. The paper explicitly says all scripts used are hosted there, so you can expect Scheme files, IDA scripts, and possibly C helpers mirroring the described structures.
  * Look for any tool that dumps “intermediary format” of sandbox profiles; the paper’s discussion of displaying `*rules*` hints that such a tool exists and lives in this codebase.

* Inference: search hint based on naming/structure patterns — XNU sources

  * In kernel sources, search for the MAC policy with name `"Sandbox"` and inspect associated structs/functions.
  * Within that policy, look for functions whose bodies mostly:

    * Fetch a per-process state from a label slot,
    * Load a profile header and node entries from memory,
    * Use a switch-like structure over `filter` values,
    * Call AppleMatch functions.

### 5.2 Anchor vs supporting vs peripheral

I’ll categorize symbols and phases by how critical they are for first-pass comprehension and alignment with this project’s tooling.

#### Anchor

These should be located and understood early:

* Phases:

  * SBPL → `*rules*` → binary profile compilation (Sections 3.1–3.2).
  * Sandbox profile installation via `sandbox_apply` / `Sandbox.kext` (Sections 3.3–3.4).
  * `sb_evaluate` decision-tree interpreter (Section 3.6).
  * AppleMatch regex integration (Section 3.7, as far as it interacts with `sb_evaluate`).

* Symbols / structures:

  * `sandbox_init`, `sandbox_compile_*`, `compile`, `sandbox_apply`
  * `Sandbox.kext`, `mac_policy_register`, `hook policy syscall`, `sandbox_create`, `proc_apply_sandbox`
  * `sb_evaluate`, `cred_check`, `policy_ops` table, `operation_names` table
  * Binary profile header (`re_table_offset`, `re_table_count`, `op_table[]`) and node encodings (terminal vs non-terminal, filters, transitions)
  * Regex table layout (`re_offset_table_offset`, `re_offset_table_count`, `re_offset[n]`)

#### Supporting

Helpful after anchor pieces are in place:

* Phases:

  * Detailed SBPL/TinyScheme semantics (beyond understanding `*rules*`).
  * Full AppleMatch NFA encoding (beyond entry points and basic structure).
  * Tracing and Mach message behaviour.

* Symbols / structures:

  * TinyScheme modifications (`take`, `drop`, `#"..."`)
  * `%version-1` and detailed prelude scripts (`sbpl_1_prelude.scm`, `sbpl_1.scm`)
  * Regex NFA headers and `node`/`cclass` layout (version, node_count, etc.)
  * `matchInit`, `matchUnpack`, `matchExec`, `matchFree` prototypes and internal structures
  * `sandboxd`, `sandbox-simplify`, Mach tracing directives

#### Peripheral

Interesting but not crucial for initial code reading:

* Manpages and sample profiles in `/usr/share/sandbox` (useful for context, not necessary for understanding internals).
* GDB/dyldinfo examples used to discover `Sandbox.kext` and policy names.
* Acknowledgements and external references.

### 5.3 Gaps and unknowns

The paper is detailed but leaves some aspects unspecified or only implied:

* Type definitions for sandbox state structures

  * Gap: It does not name the C struct type used by `sandbox_create` to hold the profile pointer, regex cache, and lock.
  * Inference: Recognize it in source as a struct allocated in `Sandbox.kext` near `sandbox_create`, referenced by hooks and `sb_evaluate`, and stored in a TrustedBSD label slot.

* Exact names of some hook functions

  * Gap: Names like “hook mount check fsctl” and “hook policy syscall” are given with spaces, not exact C symbols.
  * Inference: Look for hook functions in the sandbox `policy_ops` whose names match MAC framework naming patterns (e.g., `hook_mount_check_fsctl`, `hook_policy_syscall`).

* Filter argument interpretation

  * Gap: While filter types and `filter_arg` fields are documented, the precise mapping from `filter_arg` to underlying data (e.g., indices into regex table, enums for Mach names, socket address classes) is not fully spelled out.
  * Inference: Identify auxiliary tables in `Sandbox.kext` (like regex cache arrays or Mach-name arrays) and correlate indices used in node structures with these tables.

* Full operation list and codes

  * Gap: The paper mentions that the first 59 entries of `*rules*` correspond to operations and gives a few examples (`file-read-data`, `sysctl-write`, `system-fsctl`) but does not list all operation codes or their numeric values.
  * Inference: Extract full operation lists from `operation_names` table or `libsandbox.dylib` strings in the local tooling.

* Context struct passed to `sb_evaluate`

  * Gap: The structure of the “filter context” (fields for paths, vnodes, Mach ports, socket addresses, etc.) is not described.
  * Inference: In kernel sources, look for a struct passed through `cred_check` to `sb_evaluate` and examine its usage alongside filter-type cases.

* Tracing/logging details

  * Gap: Tracing is acknowledged but not deeply analyzed; the exact Mach message formats and logging structures are not documented.
  * Inference: In `Sandbox.kext` and `sandboxd`, inspect code surrounding Mach ports used when trace directives are present; the local tooling may include scripts to decode these messages.

By treating these gaps explicitly and using the paper’s concrete landmarks as anchors, you can align local tools and XNU sources to reconstruct the full Seatbelt implementation while keeping clear what is grounded in the paper and what is inferred from source patterns.
