>SUBSTRATE_2025-frozen
## 1. APPLESANDBOXGUIDE

Apple Sandbox Guide v1.0 is a reverse-engineered, Snow Leopard–era reference for the Seatbelt sandbox profile language (SBPL) and its operation set. It does not try to describe the full kernel architecture; instead, it catalogs the user-visible policy surface: actions, operations, filters, modifiers, and some special hard-coded behaviors. For a capabilities map, its value is that it defines the operation taxonomy (file, IPC, Mach, network, process, signal, sysctl, system), explains what each operation is supposed to control, shows how operations group kernel entry points via “Applies to” lists, and documents several quirks and bugs that affect how rules actually behave in practice. 

---

## 2. Architecture pipeline (as far as this guide describes)

The guide situates Seatbelt within macOS as a TrustedBSD MAC–based sandbox, but only at a high level. It states that sandboxing was introduced in Leopard, is based on TrustedBSD MAC, and can mediate file, IPC, Mach, network, process, signal, sysctl, and system operations. It notes that sandboxing can be applied either via the `sandbox-exec` utility (for arbitrary binaries) or programmatically via `sandbox_init`, using a small set of pre-defined profiles such as “no-internet”, “no-network”, “no-write”, “no-write-except-temporary”, and “pure-computation”. These built-ins are just SBPL profiles like any other, but exposed as constants for developers. 

Profiles are written in SBPL, a Scheme-flavored DSL parsed and compiled by `libsandbox.dylib`. The guide does not describe the compiler internals, but it does make clear that what actually reaches the kernel is not Scheme source but a compiled representation of rules. At profile author level, you see: `(version 1)`, optional `(debug …)` logging configuration, optional `(import "...")` to include other profiles, a default action `(allow|deny default)`, and a list of `(allow …)` / `(deny …)` rules over operations plus filters and modifiers. The guide repeatedly emphasizes that “Applies to” lists identify kernel functions (e.g., `vn_open_auth`, `chroot`, `task_for_pid`) on which a given operation is enforced, which is the only place it really touches the kernel side.

Enforcement flow as described is purely rule-based: Seatbelt evaluates rules in profile order for a given operation, stops on the first explicit match, and only falls back to the `default` operation if nothing matches. The guide is explicit that rule order is first-match-wins and that the position of `default` in the file does not matter. It gives concrete examples showing that a `(deny op …)` followed by `(allow op …)` on the same target will never allow, because the deny rule matches first and terminates evaluation. Logging is described as going via `sandboxd` into `/var/log/system.log`, with a `debug` directive controlling whether only denials or (theoretically) all events are logged; the author notes that `debug all` does not appear to work, so in practice only `debug deny` is usable. 

Overall, the guide is almost entirely “surface-level” from the kernel’s point of view: it gives syscall–operation mappings and evaluation behavior, but not the internal policy representation or MAC hook layer. For a capability catalog, it is best read as the authoritative definition of policy vocabulary and evaluation semantics, not as an architectural description of Sandbox.kext.

---

## 3. Language and policy model (operations and semantics in this guide)

The guide’s policy model has four main ingredients: actions, operations, filters, and modifiers.

* **Actions.** Only two: `allow` and `deny`. They are always attached to an operation (possibly a global “family” op) and optional filters/modifiers:

  * `(allow default)` / `(deny default)` control the catch-all behavior when no other rule matches.
  * Other examples: `(deny file-read-data (literal "/mach_kernel"))`, `(allow ipc-posix-sem)`, `(deny network-outbound (remote ip "*:80"))`.

* **Operation taxonomy.** Operations are grouped into global “family” operations and more granular ones:

  * **Global operations:**

    * `default` – the fallback case if no explicit rule matches; applies to all operations.
    * `file*` – umbrella over all file operations (read, write, xattrs, metadata, chroot, mount, etc.).
    * `ipc*`, `ipc-posix*`, `ipc-sysv*` – umbrellas over POSIX and SysV IPC operations.
    * `mach*`, `mach-priv*` – Mach IPC and privileged task/host operations.
    * `network*` – umbrella over `network-inbound`, `network-outbound`, `network-bind`.
    * `process*` – umbrella over process creation and exec.
    * `signal` – sending signals.
    * `sysctl*` – umbrella over sysctl read/write.
    * `system*` (mentioned in the top-level list, not detailed in the excerpt) – “system” operations. 

  * **File operations (representative):**

    * `file-read*` groups all read-like operations; its children include:

      * `file-read-data` – reading file contents (e.g., `cat`); “Applies to” includes `vn_open_auth`, `access1`, `getvolattrlist`.
      * `file-read-metadata` – reading filesystem metadata (e.g., listing with `ls`); “Applies to” includes `getattrlist_internal`, `namei`, `vn_stat`. Example shows that denying metadata still allows `cat` to read the file but prevents listing it.
      * `file-read-xattr` – reading extended attributes; applies to `vn_getxattr`, `vn_listxattr`.
    * `file-write*` groups all write-like operations; its children include:

      * `file-write-data` – writing file contents (e.g., truncate, write); applies to `vn_open_auth`, `truncate`, `ftruncate`, etc. The guide explicitly notes that denying `file-write-data` does not work as expected (see quirks below).
      * `file-write-flags`, `file-write-mode`, `file-write-owner`, `file-write-setugid`, `file-write-times` – changing flags, permissions, ownership, suid/sgid bits, timestamps; each mapped to the corresponding kernel entry points such as `chflags1`, `chmod2`, `chown1`, `setutimes`.
      * `file-write-unmount`, `file-write-mount` – controlling mount/unmount operations; tied to `unmount` and `__mac_mount` / related helpers. The guide reports that `file-write-mount` did not appear to block mounts in testing.
      * `file-chroot` – controlling `chroot()` into a directory (and associated link path checks).

    The semantics across this family are consistent: “read” operations govern visibility of metadata vs contents vs xattrs, while “write” operations govern mutating contents, security attributes, or filesystem topology (mount/unmount, ownership, suid bits).

  * **IPC operations:**

    * `ipc-posix-sem`, `ipc-posix-shm` – POSIX semaphores and shared memory; mapped to `sem_open`, `sem_wait`, `shm_open`, `pshm_mmap`, etc.
    * `ipc-sysv-msg`, `ipc-sysv-sem`, `ipc-sysv-shm` – System V message queues, semaphores, and shared memory; each mapped to the usual SysV primitives (`msgget`, `msgrcv`, `semctl`, `shmat`, etc.).
    * The umbrella `ipc*`, `ipc-posix*`, `ipc-sysv*` make it easy to globally cut off these mechanisms.

  * **Mach operations:**

    * `mach-lookup` – Mach service lookup; filtered by Mach service names (e.g., `global-name "com.apple.system.logger"` or `global-name-regex`). This is how profiles whitelist specific Mach services.
    * `mach-priv-host-port`, `mach-priv-task-port` – privileged host and task ports; mapped to `set_security_token` and `task_for_pid`. `mach-priv-task-port` explicitly controls `task_for_pid`, with the note that normal task_for_pid restrictions still apply (root or procmod group).
    * `mach-task-name` – controls `task_name_for_pid`.

  * **Network operations:**

    * `network*` – umbrella, with note that there is “no support for IP filtering, it must be localhost or *”; IP/port filters are done via the network filter syntax, not via per-IP operations.
    * `network-inbound` – reading/receiving data from sockets; applies to `listen`, `soo_read`, `soreceive`, `recv*`.
    * `network-bind` – binding local sockets; applies to `bind`, `unp_bind`.
    * `network-outbound` – connecting/sending; applies to `connect_nocancel`, `sendit`, `soo_write`, `unp_connect`.

    The intended semantics are straightforward: “inbound” governs accepting/reading from sockets, “bind” governs owning a local port, “outbound” governs initiating connections or sending.

  * **Process and signal operations:**

    * `process*` – umbrella; with no filters available here (filters live on `process-exec`).
    * `process-exec` – controls `exec` for specific paths; filters are path/file-mode based. There is a `no-sandbox` modifier that changes how the new process is sandboxed (see below).
    * `process-fork` – controls `fork`/`vfork`. Example shows that denying `process-fork` leaves a test program printing only “parent!” (the child cannot start).
    * `signal` – controls sending signals; filtered by `target` (e.g., `self`, `group`, `others`). Example shows using `(deny signal (target others))` to forbid signaling other processes.

  * **Sysctl and system operations:**

    * `sysctl*` – umbrella over sysctl read/write; and its granular forms: `sysctl-read` and `sysctl-write`. Both apply to `sysctl`, `sysctlbyname`, `sysctlnametomib`.

    The guide notes that `sysctl*` denial affects both read and write pathways and that there is a bug where `(deny sysctl-write)` requires an explicit `(allow sysctl-read)`, even with `(allow default)`.

Invariants the guide states or implies include:

* Rules are evaluated per operation, in order, first match wins.
* When a “family” operation is used (e.g., `file-read*`, `file*`, `ipc*`), it logically covers all of its children; more specific child rules can still be used, but ordering determines which one applies.
* Some operations are pure binary toggles: if no filters exist (e.g., `ipc*`, `process-fork`, many Mach-priv ops), the only meaningful distinction is allowed vs fully denied.

The author also marks a few operations as effectively broken or unreliable under Snow Leopard (e.g., `file-write-data` in deny mode, `file-write-mount`), which is significant for capabilities modeling. 

---

## 4. Filters, context, and evaluation behaviour

The guide divides SBPL “commands” into actions, operations, filters, modifiers, and some other keywords. Filters are per-operation selectors that make capabilities path- or context-sensitive; modifiers alter logging or side effects.

From the operation descriptions and examples, the main filter families are:

* **Path and filesystem filters** (used by most file and `process-exec` operations):

  * `literal` – exact path matching: e.g., `(literal "/mach_kernel")`, `(literal "/private/tmp/test")`.
  * `regex` – regular-expression matching over full paths; examples show anchored patterns and optional `/private` prefixes:

    * `#"^/private/tmp/dump\.c$"` (deny exactly that file).
    * `#"^(/private)?/etc/(resolv\.conf|ntp\.conf)$"`–style multi-pattern rules (from system profiles).
  * `path` / `file-mode` – the operation tables list `path` and `file-mode` as available filter kinds for many file operations; in examples, these appear implicitly when using `literal`/`regex` on paths.

* **Extended attribute filters** (for xattr operations):

  * `xattr` – used in `file-read-xattr` / `file-write-xattr`, allowing selection by attribute name; the example focuses on path and does not exploit xattr-name filtering, but the filter is listed as supported.

* **Network filters** (for `network*`, `network-inbound/outbound/bind`):

  * `local ip` / `remote ip` – for IP/port matching, using strings like `"*:80"` or `"*:22"`. The guide notes that at this level IP filtering is limited to localhost vs wildcard host, with port expressed as `host:port`; there is “no support for IP filtering, it must be localhost or *”.
  * `remote unix-socket (path-literal "...")` – for Unix domain sockets, e.g., allowing outbound to `/private/var/run/syslog`.

* **Mach filters** (for `mach-lookup`):

  * `global-name` – exact Mach service name, e.g., `"com.apple.system.logger"`.
  * `global-name-regex` – regex over Mach service names, e.g., names starting with `"com.apple.DeviceLink.AppleMobileBackup"`.

* **Signal filters** (for `signal`):

  * `target` – selects which targets are affected: `self`, `group`, or `others`. The example denies only `others`, allowing a process to still signal itself or its group.

The guide’s examples show typical rule shapes like:

* `(deny file-read* (literal "/mach_kernel"))` – all file reads against an exact path.
* `(deny file-write* (literal "/test"))` – all file writes against a given path.
* `(deny network-outbound (remote ip "*:80"))` – block outbound HTTP/port-80 to any host.
* `(allow mach-lookup (global-name "com.apple.system.logger"))` – allow logging service access.

**Evaluation behaviour** is described precisely:

* For a given operation, SBPL constructs a rule list. Each rule is either a test `(filter action . modifiers)` or a jump to another operation (used internally; not elaborated in the guide but mentioned conceptually).
* At runtime, Seatbelt walks the list for that operation and stops at the first test whose filter matches. Filters can be `#t` (always match) or path/network/mach/signal selectors.
* If no rule for that operation matches, the engine “jumps” to the `default` operation and evaluates its rules in the same way. The physical location of `(allow|deny default)` in the file does not matter.
* Because evaluation stops at first match, later rules cannot override earlier ones. The guide explicitly warns that a deny followed by an allow for the same operation/target will never allow; the deny will always win.

**Logging and modifiers**:

* Most operations list modifiers `send-signal` and `no-log`. `send-signal` tells Seatbelt to generate a signal on violation; `no-log` prevents logging that rule’s hits (useful when combined with a deny default to avoid noisy logs).
* `process-exec` additionally supports a `no-sandbox` modifier, allowing a rule that both controls exec and disables sandboxing for the new process. The guide lists this but does not go into detail; any catalog that models this should treat it as an escape hatch from the current sandbox.
* At profile scope, `(debug all|deny)` controls what gets sent to `sandboxd`; the author notes `debug all` appears nonfunctional, so reliable tracing is currently only for denies.

**Limitations and caveats in filter behaviour:**

* Path regexes are powerful but easy to over-match; examples from bundled profiles show careful anchoring (`^` / `$`) and explicit optional `/private` prefixes to cope with the `/private` symlink on macOS.
* For network filters, the lack of real IP filtering in operations means capability modeling must treat IP address selection as a coarse “localhost vs anywhere” distinction, with more nuance only at the path/port level.
* The guide mentions a “trace” feature that auto-generates rules for denied operations and a `sandbox-simplify` tool to reduce them, but warns this is not as automatic as it appears; manual simplification is still required.

---

## 5. Patterns and implications for a capability catalog

From the examples, tables, and comments, several patterns emerge that matter for a capability catalog built on top of this guide.

**Default-deny vs default-allow shapes.**

Profiles are explicitly either:

* **Whitelist style**: `(deny default)` followed by a sequence of precise `allow` rules. This is how most system daemon profiles are structured (e.g., those importing `bsd.sb`). In capability terms, such profiles have a small, clearly enumerated set of allowed operations, often tightly scoped by path and Mach/IPC filters.
* **Blacklist style**: `(allow default)` with a handful of focused denies (e.g., “everything is allowed except reading `dump.c`”). This pattern is simpler conceptually but harder to reason about; it makes more sense as “augmentations” (importing a base profile and then denying additional sensitive resources).

For a catalog, this suggests tagging capabilities not only by operation but by whether they appear in explicit allow rules under a default-deny profile vs “holes” left open under default-allow.

**Family vs fine-grained operations.**

Apple’s taxonomy clearly encourages:

* **Family operations** for coarse sandboxing: `file*`, `file-read*`, `file-write*`, `ipc*`, `network*`, `process*`, `sysctl*`. These correspond to “big” capabilities like “any network egress”, “any file writes”, “any sysctl usage”.
* **Fine-grained operations** for tightening: `file-read-metadata` vs `file-read-data`, `file-write-owner` vs `file-write-mode`, separate POSIX vs SysV IPC ops, Mach lookup by service name, etc.

A capabilities map should therefore:

* Group children under family capabilities (e.g., “File read operations → {metadata, data, xattr}”), so agents can reason about both the umbrella and specifics.
* Record where system profiles rely on families vs specific children; that tells you where Apple treats something as a single “capability surface” vs a set of separable privileges.

**Path- and container-shaped idioms.**

Even though the guide predates full macOS/iOS “app containers”, the examples show idiomatic scoping patterns that look very container-like:

* Protecting key system files: `(deny file-read* (literal "/mach_kernel"))`, tailored deny blocks for `/System`, `/private/var/db/…`, etc.
* Allowing or denying operations under directories via regex: e.g., `^(/private)?/var/named/`, `^(/private)?/etc/…`.
* Using imports like `bsd.sb` to pull in shared baseline rules for a whole class of daemons.

Inference: in more modern containerized profiles, these same mechanisms are used to approximate container boundaries (e.g., allowing file access only under a user or app directory, while denying outside paths). A catalog should therefore treat “path filter + file operation” combinations as *contextual* capabilities (e.g., “file write in /var/tmp only”) rather than simple booleans.

**Documented quirks and “soft” capabilities.**

The guide explicitly documents operations and combinations that do not behave as their names suggest:

* `file-write-data` with a deny rule is reported as ineffective; the author shows multiple rule combinations where data can still be written unless `file-write*` is denied instead.
* `file-write-mount` appears not to block mounts despite being defined.
* `sysctl-write` denial requires a compensating `allow sysctl-read` even under default-allow, or sysctl name resolution fails in surprising ways.

For each such operation, a capability catalog should:

* Mark the capability as “unreliable on 10.6.8” (and track OS version, if the catalog is versioned).
* Prefer modeling effective capabilities via the umbrella operations that actually work (e.g., model “no file content writes” via `file-write*` instead of `file-write-data` alone).

**Implications for modeling and downstream agents.**

Given all of the above, a sensible catalog built off this guide should:

* Treat **operation families** as primary capability buckets (file, network, IPC, Mach, process, signal, sysctl, system).
* Within each family, list **semantic sub-capabilities** (metadata vs data vs xattrs; inbound vs outbound vs bind; POSIX vs SysV IPC; host/task ports vs generic Mach lookup, etc.), but always remember the first-match evaluation semantics.
* Attach **context qualifiers** (filters) to capabilities: path patterns, Mach service names, network tuples, signal targets. These qualifiers are as important as the operation itself for understanding real power.
* Annotate **known quirks/bugs** directly on capabilities so that agents analyzing or generating profiles know which operations should not be relied on in isolation.
* Treat modifiers like `no-sandbox` as **structural capabilities** (affecting sandboxing itself) rather than ordinary resource accesses; these deserve special warning flags in any high-level view.

In short, Apple Sandbox Guide v1.0 is best used as the semantic and behavioral ground truth for SBPL’s operation surface: it says what each op is *meant* to control, how rules are matched, where they hook into the kernel, and where reality diverges from the names. A capability catalog layered on top should track operation families, path/Mach/network context, and documented quirks, rather than just enumerating op codes.
