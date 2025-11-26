1. HACKTRICKS_MACOSSANDBOX

The HackTricks macOS Sandbox notes are a practical, exploitation-oriented orientation to the macOS “Seatbelt” sandbox, focusing on how containers, entitlements, sandbox profiles, extensions, and kernel/userland plumbing actually behave in a running system. The document explains where profiles live, how they are compiled and applied, how sandbox checks can be traced and inspected, and how extension tokens and special sandbox management APIs can expand or bypass normal checks. It does not present full exploit chains, but it does highlight concrete behaviors (such as extension token reuse, opt-in sandboxing on macOS, and special “bypass” management operations) and points to real sandbox-escape write-ups, so its main contribution is to show how the nominal SBPL/entitlement model is shaped and sometimes weakened by container metadata, extension mechanisms, privileged management interfaces, and other macOS security subsystems (TCC, SIP, Gatekeeper).

---

2. Architecture pipeline (as seen through this document)

The document models the sandbox as a layered pipeline:

* A process becomes sandboxed if it carries the entitlement `com.apple.security.app-sandbox`. Apple binaries are “usually executed inside a Sandbox,” and all App Store applications have this entitlement, so many user-facing processes are sandboxed by default. At startup on macOS, processes are not sandboxed by the kernel; instead they “must opt-in to the sandbox themselves,” typically via userland code that checks entitlements and calls into `libsandbox.dylib` to compile and apply the profile. App Store apps are called out as always having the sandbox entitlement.

* Once opted in, runtime enforcement is handled in the kernel by `Sandbox.kext`, which uses TrustedBSD MACF hooks “in almost any operation a process might try (including most syscalls).” The kernel extension evaluates sandbox decisions by combining a global “platform profile” (a SIP profile called `platform_profile` defined in `rootless.conf`, applied to all processes) with a process-specific profile derived from entitlements and SBPL. Evaluation flows through functions such as `_cred_sb_evaluate` and `sb_evaluate_internal` using the credentials’ MACF labels.

* Around the kernel, several userland components mediate configuration and enforcement: the private framework `AppSandbox.framework`, `libsandbox.dylib` (with APIs like `sandbox_compile_file`, `sandbox_compile_entitlements`, `sandbox_apply`, tracing functions, and `sandbox_inspect_pid`), a userland daemon `/usr/libexec/sandboxd`, and container management maintained in `~/Library/Containers`. Containers are per-bundleID home directories (e.g., `~/Library/Containers/<CFBundleIdentifier>`), with a `Data` subdirectory and symlinks like `Desktop`, `Downloads`, and `Pictures` back into the user’s actual home. A container metadata file `.com.apple.containermanagerd.metadata.plist` holds the compiled profile (`SandboxProfileData`), the entitlements, and fields like `RedirectablePaths` and `RedirectedPaths`. Access to this metadata requires Full Disk Access; “not even just root can read it” without that.

* The document also describes a separate “sandbox management” plane implemented via `mac_syscall` with module `"Sandbox"` and a set of codes (e.g., `set_profile`, `extension_issue`, `suspend`, `passthrough_access`, various `rootless_*` operations). These are invoked indirectly by helper functions (e.g., `___sandbox_ms_call`) and by privileged components (including `sandboxd`) over a Mach/XPC interface (the daemon exposes a Mach service used by the kernel extension).

From the HackTricks perspective, the key actors in the pipeline are: sandboxed applications and their containers, the entitlement-derived application profile, the global platform profile (SIP), the kernel MACF hooks in `Sandbox.kext`, runtime helpers in `libsandbox.dylib`, and a management plane that can trace, inspect, suspend, or bypass checks for sufficiently privileged callers.

---

3. Language and policy model (as seen here)

The document treats “the sandbox” as an SBPL policy evaluated by `Sandbox.kext` under MACF, with entitlements driving which rules are included. It explains that sandbox profiles are written in Sandbox Profile Language (SBPL), “which uses the Scheme programming language.” An example profile is given with typical structure: a `(version 1)` header, a default `(deny default)` rule, and `allow` forms parameterized by operation families (`network*`, `file*`, `file-read*`, `process*`) and filters such as `subpath`, `literal`, and `regex`. The example shows that a naive profile that only allows access to a target file in `/tmp` will still fail to run `touch` because the process also needs access to binaries (`/usr/bin/touch`), the dynamic loader, `kern.bootargs`, and “/” itself. This demonstrates that real profiles must account for a lot of auxiliary accesses that a naive capability map might ignore.

The policy model links entitlements to SBPL rules. App Store apps use `/System/Library/Sandbox/Profiles/application.sb` as a base profile, and the document notes that you can see “how entitlements such as `com.apple.security.network.server` allows a process to use the network” by looking inside that profile. A special entitlement `com.apple.security.temporary-exception.sbpl` lets certain apps (with Apple’s authorization) embed custom SBPL snippets instead of the standard profile. The compiled profile in container metadata (`SandboxProfileData`) is an opaque CFData blob where “the name of the operations are substituted by their entries in an array known by the dylib and the kext,” making it harder to read directly.

The document also treats sandbox “extensions” as a secondary policy mechanism. Extensions are extra rights (for files, Mach ports, IOKit classes, POSIX IPC, etc.) represented as opaque tokens, issued by APIs like `sandbox_extension_issue_file[_with_new_type]` and `sandbox_extension_issue_mach`. They are stored in a MACF label slot on the process credentials, and can be consumed or released by functions like `sandbox_extension_consume` and `sandbox_extension_release`. Extensions are “very related to entitlements,” and “having certain entitlements might automatically grant certain extensions.” The text explicitly mentions that TCC’s `tccd` daemon grants a Photos extension token (`com.apple.tcc.kTCCServicePhotos`) when a process is allowed access via an XPC message; the process must then “consume the extension token so it gets added to it.”

Finally, the notes position SIP as itself a sandbox profile (`platform_profile`) applied to all processes and evaluated together with the process profile, making SIP a first-class part of the sandbox evaluation logic rather than an entirely separate mechanism. Gatekeeper is also integrated into the effective policy: “Everything created/modified by a Sandboxed application will get the quarantine attribute,” and when the sandboxed app tries to execute something it wrote using `open`, Gatekeeper is triggered “to prevent a sandbox [escape].”

---

4. Enforcement mechanics and bypass chains

This section focuses on what the document actually shows about enforcement behavior and where it points to bypasses or capability escalations.

4.1 Container layout, symlinks, and RedirectablePaths

* Initial state: A sandboxed app has a container in `~/Library/Containers/<CFBundleIdentifier>`, with a `Data` directory. Inside `Data` there are symlinks like `Desktop -> ../../../../Desktop` and `Downloads -> ../../../../Downloads`, and real directories like `Documents`, `Library`, `SystemData` and `tmp`.
* Enforcement: The notes emphasize that “even if the symlinks are there to ‘escape’ from the Sandbox and access other folders, the App still needs to have permissions to access them.” Those permissions are governed by the container metadata’s `RedirectablePaths` plist entries as well as the sandbox profile.
* Effective capability: Symlinks alone do not grant extra capabilities; they only provide paths that can be used if the profile already allows them. A naive capability map that assumes “any symlink inside the container gives free access to that target tree” would be wrong; the effective surface is still constrained by entitlements and `RedirectablePaths`.

4.2 Quarantine attribute and execution

* Initial state: A sandboxed app creates or modifies a file.
* Enforcement: The document states that “everything created/modified by a Sandboxed application will get the quarantine attribute.” If the app later tries to execute that file via `open`, Gatekeeper is invoked and can block it.
* Effective capability: The sandbox alone might allow `exec` of a file the app just wrote, but the effective system behavior is stricter because Gatekeeper interposes based on quarantine metadata. Inference: For capability cataloging, “can write file + can exec file” is not sufficient to assert a working self-bootstrap to arbitrary code execution; Gatekeeper must be considered.

4.3 External sandbox escape examples via policy quirks

* The document explicitly lists two external “bypasses examples” and mentions that in one of them “they are able to write files outside the sandbox whose name starts with `~$`.”
* Preconditions and mechanism (as implied here): A sandboxed application has a narrow exception in its profile allowing writes outside its container for certain filenames (e.g., special temporary file patterns). Abuse consists of creating files under that pattern to obtain write access outside the nominal container boundaries.
* Effective capability: This is a pattern where a narrowly tailored exception (for app-specific temp files) effectively widens the file-write capability surface when combined with attacker-controlled filenames. The document does not provide full details but confirms that such behavior exists.

4.4 Opt-in sandboxing and “Debug & Bypass”

* The notes stress that “on macOS, unlike iOS where processes are sandboxed from the start by the kernel, processes must opt-in to the sandbox themselves. This means on macOS, a process is not restricted by the sandbox until it actively decides to enter it, although App Store apps are always sandboxed.” Processes are “automatically Sandboxed from userland when they start if they have the entitlement `com.apple.security.app-sandbox`.”
* A section titled “Debug & Bypass Sandbox” points to an external deep-dive for the detailed mechanics.
* Inference: This establishes a potential bypass surface at initialization time—any code that runs before the sandbox is entered (or that interferes with the userland sandbox initialization path) executes without sandbox constraints. The document does not itself present a concrete exploit, but it clearly distinguishes macOS’s opt-in model from iOS’s kernel-enforced model in a section explicitly labeled “Debug & Bypass.”

4.5 Sandbox extensions and token reuse

* Preconditions: A process is allowed to access a protected resource via TCC or other policy (for example, Photos). According to the notes, an allowed process receives an extension token (e.g., for the Photos service) from `tccd` in an XPC message.
* Mechanism:

  1. The extension is issued with APIs like `sandbox_extension_issue_file` or a service-specific variant and stored as a long hexadecimal token.
  2. The process (or some code with access to the token) calls `sandbox_extension_consume`, which causes the extension to be attached to the process’ MACF label.
  3. The key property the document calls out is that extension tokens “don’t have the allowed PID hardcoded,” and “any process with access to the token might be consumed by multiple processes.”
  4. Extensions are “usually granted by allowed processes,” and some entitlements automatically grant certain extensions.
* Resulting effective capability: An extension token is a transferable capability: if it leaks to another process, that process can consume it and gain the corresponding extra rights, even if its own entitlements and base sandbox profile would not allow that resource. This is a concrete mechanism by which the effective sandbox surface can be larger than what entitlements alone suggest. The document does not show a full attack chain, but it explicitly highlights the process-agnostic nature of tokens and their relationship to entitlements and TCC.

4.6 Management APIs: suspend, passthrough, and profile changes

Through the `mac_syscall` “Sandbox” module and related wrappers, the document lists management operations:

* `suspend` (#10): “Temporarily suspend all sandbox checks (requires appropriate entitlements).”
* `unsuspend` (#11): Resume previously suspended checks.
* `passthrough_access` (#12): “Allow direct passthrough access to a resource, bypassing sandbox checks.”
* `set_profile` (#0): Apply a compiled or named profile to a process.
* Various `extension_*` operations (#5–9) to issue, consume, release, and update extensions.
* Several `rootless_*` operations (#30–34) that interact with SIP (e.g., `rootless_whitelist_check`, `rootless_protected_volume`, `rootless_mkdir_protected`).
* `builtin_profile_deactivate` (#20), only on macOS < 11, to deactivate named profiles such as a debug profile.

The notes also mention that suspending the sandbox via `sandbox_suspend` requires entitlements like `com.apple.private.security.sandbox-manager` or `com.apple.security.temporary-exception.audio-unit-host`.

Mechanically, a privileged caller can:

1. Invoke `sandbox_suspend` (or the corresponding `mac_syscall` code) to disable sandbox checks for itself.
2. Perform operations that would normally be evaluated by the sandbox.
3. Use `sandbox_unsuspend` to restore enforcement.
4. Alternatively, use `passthrough_access` to bypass checks for particular resources without globally suspending the sandbox.

Effective capability: For processes with these management entitlements, the sandbox becomes advisory; they can temporarily or selectively bypass checks via documented APIs. From a catalog perspective, “has sandbox-manager entitlements” is itself a super-capability that dominates most SBPL-level restrictions. The document does not claim these entitlements are widely available, but it clearly describes the bypass semantics.

4.7 Versioning and platform differences

The document includes specific version/platform notes that affect applicability:

* `builtin_profile_deactivate` (#20) is explicitly marked “macOS < 11,” and is used to deactivate named profiles such as `pe_i_can_has_debugger`.
* Some `___sandbox_ms` codes are marked iOS-only, such as `set_container_path` (#13) and `container_map` (#14).
* Another operation (`sandbox_user_state_item_buffer_send` #15) is tagged as “iOS 10+.”
* `Sandbox.kext` on iOS is described as having all profiles hardcoded into a read-only segment to prevent modification, unlike macOS where profiles reside in files under `/System/Library/Sandbox/Profiles`.

Outside of these, the document does not systematically map techniques to specific macOS minor versions or give mitigation timelines; it mainly flags when an operation is tied to “macOS vs iOS” or to “macOS < 11.”

---

5. Patterns, idioms, and implications for a capability catalog

From these notes, several recurring patterns emerge that matter for a capability catalog that wants to reflect real behavior rather than a purely SBPL/entitlement-level model.

5.1 Capabilities are shaped by container metadata and symlink overlay
The document shows that a sandboxed app’s effective file system surface is jointly determined by:

* The SBPL profile (allow/deny rules for `file*` operations).
* Container symlinks into user directories.
* `RedirectablePaths` and related fields in container metadata.

Symlinks alone do not grant capabilities; they are potential paths gated by both container config and profile. For cataloging, any capability like “can read Desktop” should be conditioned on both the profile and whether the container’s redirectable paths include that location, not just on the presence of a `Desktop` symlink.

5.2 Entitlements → profiles → extensions → effective rights
There is a multi-stage chain:

* Entitlements determine which high-level capabilities are intended (e.g., network server, Photos access).
* `application.sb` and other profiles map entitlements into SBPL rules.
* Extensions provide additional, often more fine-grained, rights that can be issued dynamically (e.g., “Photos access now” via TCC).
* Extension tokens are transferable because they are not bound to a single PID.

For a capability catalog, this means:

* The naive “entitlement → capability” mapping is incomplete; you must model extension issuance and consumption as a separate dimension.
* A higher-level capability concept like “can hold and reuse sandbox extension tokens of type X” is needed, since the document shows tokens can be consumed by “any process with access to the token” and reused across processes.

5.3 Management super-capabilities
APIs like `sandbox_suspend`, `passthrough_access`, and `set_profile`, as well as `rootless_*` functions, are effectively super-capabilities for processes that can invoke them:

* “Can suspend sandbox checks” (requires sandbox-manager-style entitlements).
* “Can bypass checks for specific resources” via `passthrough_access`.
* “Can change its own sandbox profile” via `set_profile` or custom SBPL entitlements.
* “Can alter SIP behavior” via `rootless_*` operations.

In a capability catalog, these should be modeled explicitly as distinct capabilities that dominate ordinary permissions. An app with such entitlements cannot be reasoned about purely in terms of SBPL allow/deny rules; the ability to suspend or bypass the sandbox changes the effective model entirely.

5.4 Initialization and opt-in behavior as an attack family
Because macOS uses an opt-in sandbox model, there is a distinct attack family around “code before the sandbox.” The HackTricks notes explicitly distinguish this from iOS and point to a separate “Debug & Bypass” write-up. Even without the external details, the catalog should recognize:

* A capability “runs unsandboxed before calling sandbox_init / applying profile,” which all sandboxed processes effectively have on macOS.
* A more powerful capability “can influence its own sandbox initialization path,” which might exist for debuggable or specially configured processes.

Inference: These should be modeled as separate from ordinary “sandboxed process” capabilities because they allow (at least in principle) behaviors that cannot be captured by the steady-state profile alone.

5.5 Policy quirks and exception-based bypasses
The document’s reference to real-world escapes via narrowly scoped exceptions (such as being able to write files outside the container whose names match a particular pattern) suggests an idiom where:

* A profile includes special allowances for “legitimate” operational needs (temp files, caches, Office document helpers, etc.).
* Attackers repurpose those narrow exceptions by controlling the parameters (e.g., filenames) to achieve broader data-flow than intended.

Even though the document does not spell out the full chains, the inclusion of that example implies that catalog entries like “can write outside container, but only under specific naming conventions/location constraints” should be annotated as high-risk: a small exception can be turned into a general-purpose write primitive by a determined attacker.

5.6 Cross-system interactions (TCC, SIP, Gatekeeper)

Finally, the notes highlight that effective capabilities are mediated by other subsystems:

* SIP’s platform profile is part of sandbox evaluation for all processes.
* TCC grants extension tokens that extend sandbox rights after user consent.
* Gatekeeper interposes on execution of quarantined content, even when the sandbox would otherwise allow it.
* Access to container metadata (`containermanagerd` plist) is gated by Full Disk Access, which matters for both attackers and analysts.

For a capability catalog, this suggests adding higher-level concepts such as:

* “Sandboxed capability constrained by SIP (platform_profile).”
* “Capability extended via TCC-issued sandbox extensions.”
* “Dropper/execution capabilities constrained by Gatekeeper/quarantine.”

Where the HackTricks document is silent—e.g., it does not detail specific XPC confused-deputy services beyond `tccd`, nor does it enumerate which third-party apps have dangerous temporary exceptions—the catalog must explicitly note “not in this document” rather than assuming additional attack surfaces.
