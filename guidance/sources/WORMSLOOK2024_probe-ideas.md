1. WORMSLOOK2024

WORMSLOOK2024 is an implementation-focused walkthrough of how Apple’s Sandbox is wired into the system on macOS and iOS, covering containers, entitlements, libsystem_secinit/libsandbox, containermanagerd, Sandbox.kext, MACF hooks, and sandbox extensions. You can treat it as a description of the “intended” modern design: when and how processes become sandboxed, what data structures (profiles, labels, extensions, container metadata) look like, and which operations are controlled.

In this report, the same text is re-read as a source of empirical hypotheses rather than general architecture. Each claim below is turned into “If A,B,C → then R” form, grouped into probe families, and annotated for likely stability vs drift. Where the paper is silent, this is noted explicitly; where a small extrapolation is useful, it is prefixed with “Inference:”.

2. Extracted testable claims

Hypotheses are labeled H1, H2, … and framed for modern macOS; iOS-specific ones are marked as such.

1. H1 – Container location for sandboxed macOS apps
   Hypothesis: If a user-level app on macOS is signed with the com.apple.security.app-sandbox entitlement set to true and is launched, then the system will create (if not already present) and use a per-app container directory rooted under `~/Library/Containers/<application-identifier>` for that app’s data.
   OS-version constraints: Described as “macOS” behaviour; the paper does not give an explicit version number.

2. H2 – Container creation timing on macOS
   Hypothesis: If a macOS app is sandboxed via com.apple.security.app-sandbox = true and has never been run before for that user, then the container directory under `~/Library/Containers/<application-identifier>` will be created at first launch, not at installation time.
   OS-version constraints: Presented in contrast to iOS; no explicit macOS version given.

3. H3 – Container layout resembles a private home
   Hypothesis: If a sandboxed macOS app’s container at `~/Library/Containers/<application-identifier>` is examined, then it will contain a directory structure similar to a home directory (e.g., Documents, Library, Downloads), and the app’s normal file accesses will be directed into these container paths rather than the user’s real home equivalents.
   OS-version constraints: Paper treats this as the current design; no explicit version.

4. H4 – Unsandboxed macOS apps lack App Sandbox entitlement
   Hypothesis: If a macOS system binary such as Terminal, Finder, or Activity Monitor is examined, then it will not carry the com.apple.security.app-sandbox entitlement, and when these binaries run, they will not be subject to the App Sandbox container restrictions described for sandboxed apps.
   OS-version constraints: Presented as examples of “not sandboxed”; no explicit version.

5. H5 – secinit uses com.apple.security.app-sandbox on macOS
   Hypothesis: If a macOS process’s main binary has com.apple.security.app-sandbox = true, then libsystem_secinit (loaded via dyld/libSystem) will decide that the process should be sandboxed and will arrange for libsandbox to initialize a sandbox before user code runs. If the entitlement is absent, then secinit will not initialize the App Sandbox for that process.
   OS-version constraints: Described as “how it’s done on macOS”; no explicit version.

6. H6 – com.apple.private.security.no-sandbox gate on iOS (iOS-only)
   Hypothesis: If an iOS process’s binary carries com.apple.private.security.no-sandbox = false (or lacks an internal permission to bypass it), then libsystem_secinit will treat it as requiring sandboxing and will not allow the process to run without a sandbox; com.apple.private.security.no-sandbox is honored only for Apple-signed system binaries, so third-party iOS apps cannot use it to escape the sandbox—the practical pattern is that third-party iOS apps are always sandboxed and this entitlement is an Apple-only escape hatch for select system processes.
   OS-version constraints: Marked as iOS behaviour; macOS instead uses SBPL profiles. Treat the Apple-only applicability as part of the model unless probes show drift.

7. H7 – seatbelt-profiles entitlement selects profile (iOS-only)
   Hypothesis: If an iOS app’s entitlements include a seatbelt-profiles entitlements key, then at exec time Sandbox will use that value (together with container metadata such as SandboxProfileData and SandboxProfileDataValidationInfo) to select and compile the sandbox profile applied to that process.
   OS-version constraints: Described as iOS-only; macOS uses on-disk SBPL profiles instead.

8. H8 – Container metadata includes profile blobs (iOS-only)
   Hypothesis: If an iOS app’s container metadata property list is inspected, then it will include keys such as SandboxProfileData (a base64-encoded profile blob) and SandboxProfileDataValidationInfo (inputs for libsandbox’s compiler), which are used at exec time to compile the sandbox profile for that app.
   OS-version constraints: iOS; no explicit version.

9. H9 – SIP (“rootless”) enforced via sandbox profile
   Hypothesis: If a macOS process (even one not using the App Sandbox) attempts to write to certain protected system locations (e.g., /System or other SIP-protected directories), then the kernel will deny these operations according to a system-level sandbox profile (platform_profile, from rootless.conf) that forbids writes to those paths.
   OS-version constraints: Described as “System Integrity Protection” implemented partly as a sandbox profile; no version numbers.

10. H10 – SBPL default rule semantics
    Hypothesis: If a sandbox profile’s SBPL declarations include “deny default”, then for a process running under that profile, any operation not explicitly allowed by at least one rule will be denied; conversely, “allow default” will allow operations unless explicitly denied.
    OS-version constraints: Described generically for current SBPL; no OS version restriction.

11. H11 – File operation families with path filters
    Hypothesis: If a sandbox profile for a macOS process contains rules that allow file-read* and file-write* operations only when combined with home-subpath or container-subpath filters, then that process will be able to read/write files only under the specified subpaths of the user home or container, and attempts to access other filesystem locations will be denied by Sandbox.
    OS-version constraints: Presented as example SBPL behaviour; no explicit version.

12. H12 – device-microphone and device-camera operations
    Hypothesis: If a sandbox profile for a macOS process includes unconditional deny rules for device-microphone and device-camera, then the process will be unable to access microphone and camera devices regardless of its other file or network permissions.
    OS-version constraints: Presented as example SBPL rules; no explicit version. The mapping from entitlements to these operations is not described in this paper.

13. H13 – appleevent-send is macOS-only and sandboxed
    Hypothesis: If a sandboxed macOS process attempts to send Apple Events to other processes, then the allow/deny decision will be controlled by the appleevent-send operation in its sandbox profile; iOS does not support this operation.
    OS-version constraints: Explicitly stated as macOS-only; no macOS version given.

14. H14 – user-preference-* operations scope access by domain
    Hypothesis: If a sandbox profile for a macOS process contains an allow user-preference-read rule scoped to a particular preference domain identifier, then the process will be able to read preferences for that domain (e.g., com.apple.Messages) even when it cannot freely read arbitrary preference files; without that rule, such access will be denied.
    OS-version constraints: Presented as example SBPL pattern; no version given.

15. H15 – Sandbox is attached at exec via cred_label_update_execve
    Hypothesis: If a macOS process execs a binary whose entitlements indicate that it should be sandboxed, then during exec Sandbox’s cred_label_update_execve MACF hook will create a sandbox struct, associate it with the process’s credentials by storing it in slot 1 of the kauth_cred_t label, and issue basic sandbox extensions for the process’s own executable and container paths. Subsequent sandbox decisions for that process will reference this attached sandbox struct.
    OS-version constraints: Described as current behaviour; no explicit version.

16. H16 – All Sandbox MACF hooks funnel through cred_sb_evaluate
    Hypothesis: If any MACF-mediated operation (e.g., a vnode write check) is performed by a sandboxed process on macOS, then Sandbox’s MACF hook will call cred_sb_evaluate with the process’s credentials, an internal operation number, and an argument buffer, and cred_sb_evaluate will in turn call an internal evaluator to return allow/deny for that operation.
    OS-version constraints: Presented as current internal structure; no explicit version.

17. H17 – Sandbox implements a subset of MACF operations
    Hypothesis: If the list of MACF operations is examined on a current macOS system, then Sandbox will implement hooks for only a subset of them (around half, according to the paper), and only those operations will be evaluated through the Sandbox profile; other MACF hooks may be implemented by different policies.
    OS-version constraints: The paper gives approximate counts for “current” systems; exact numbers may vary by version.

18. H18 – sandbox extensions grant specific additional capabilities
    Hypothesis: If a process that already has access to a resource (e.g., a file) issues a sandbox extension of the appropriate type and class for that resource, passes the resulting token string to a sandboxed process that lacks direct access, and that consumer explicitly consumes the token via the extension API, then subsequent attempts by that same consumer to access that specific resource will be allowed where they were previously denied; extensions do not create transferable capabilities beyond what the issuer could already reach.
    OS-version constraints: Described as current extension mechanism; no explicit version. The paper notes tokens embed a boot-time secret and are not reusable across reboot, though finer-grained lifetime or revocation details remain under-specified.

19. H19 – Userland Sandbox APIs reflect kernel allow/deny
    Hypothesis: If a sandboxed macOS process calls userland APIs such as sandbox_check to test an operation that would be denied by its active sandbox profile, then sandbox_check will report denial consistent with what the kernel would enforce for the corresponding operation.
    OS-version constraints: Described as current userland interaction; no explicit version.

20. Probe families

Family F1 – Container layout and visibility (macOS)

Description: Probes that compare filesystem behaviour inside and outside the per-app container for sandboxed vs unsandboxed macOS processes.

Member hypotheses: H1, H2, H3, H11.

Probe shapes:

1. Probe F1-A: A tiny sandboxed test app (with com.apple.security.app-sandbox = true) that on first run prints whether `~/Library/Containers/<bundle-id>` exists before and after launch, then creates files in its container “Documents” and in the real `~/Documents`, and reports success/failure and errno.
2. Probe F1-B: Companion unsandboxed test app (no App Sandbox entitlement) that attempts the same file creations and prints results, including directory listings for `~/Library/Containers` and the real home subdirectories.
3. Probe F1-C: A sandboxed app that enumerates and prints its accessible file paths under what it believes are “Documents”, “Downloads”, etc., to see whether these map to container paths or real home paths.

Key observables:

* Existence and path of the container directory at first launch and subsequent runs.
* Ownership and permissions of container vs home directories.
* Success/failure (errno) for reads/writes inside and outside container paths.
* Differences between sandboxed and unsandboxed variants for identical file operations.

Family F2 – secinit / launch-time sandboxing behaviour (macOS vs iOS conceptual)

Description: Probes that test whether entitlement configuration at process start governs whether a process is sandboxed at all and how.

Reminder: entitlements are inputs to sandbox policy rather than permissions by themselves; these probes observe how platform and app profiles respond to different entitlement sets rather than treating entitlements as direct allow/deny switches.

Member hypotheses: H4, H5, H6 (iOS-only), H7 (iOS-only), H15.

Probe shapes:

1. Probe F2-A (macOS): Two otherwise-identical command-line programs, one signed with com.apple.security.app-sandbox = true and one without; both perform a set of privileged operations (e.g., writes outside the home directory, access to /System) and print whether they succeed.
2. Probe F2-B (macOS concept of H15): A process that execs a helper binary with different entitlements (sandboxed vs unsandboxed) and prints whether the helper’s behaviour changes (e.g., ability to write to a test path) and whether the helper appears to share or differ in sandbox restrictions.
3. Probe F2-C (iOS-only, conceptual): Equivalent pair of apps with different values for com.apple.private.security.no-sandbox and seatbelt-profiles on an iOS device, testing whether one can run unsandboxed and how profiles differ. (Not runnable on macOS; included to keep the hypothesis explicit.)

Key observables:

* Success/failure (errno) of privileged operations under different entitlement configurations.
* Presence/absence of container directories.
* Inference: if available, OS-level metadata (e.g., from ps or procfs equivalents) that indicates sandbox presence.

Family F3 – SIP / system-protected paths

Description: Probes that test behaviour of writes to SIP-protected locations as described by the platform_profile sandbox profile.

Member hypotheses: H9.

Probe shapes:

1. Probe F3-A: Unsandboxed program that attempts to create, modify, and delete files under /System and other known-protected directories, printing errno.
2. Probe F3-B: Sandboxed program (App Sandbox enabled) that attempts the same operations, printing errno.
3. Probe F3-C: Both variants try writes to a control location that is not SIP-protected (e.g., within /usr/local, if allowed) to establish contrast.

Key observables:

* Success/failure (errno) of write operations to protected vs unprotected paths.
* Whether behaviour differs between sandboxed and unsandboxed programs (expected: both denied under SIP).
* Evidence that failures align with sandbox restrictions rather than only filesystem permissions.

Family F4 – SBPL profile semantics: default and file operations

Description: Probes that test how SBPL rules affect file operations, focusing on default rules and file-read*/file-write* with path filters.

Member hypotheses: H10, H11.

Probe shapes:

1. Probe F4-A: Series of test profiles (applied via sandbox-exec or equivalent mechanism) with (deny default) and specific allow rules for file-read* and file-write* under certain directories; the test program attempts file operations in- and out-of-scope and prints results.
2. Probe F4-B: Profiles with (allow default) and explicit deny rules for particular subpaths; test program again attempts operations and prints results.
3. Probe F4-C: Profiles that switch between home-subpath and container-subpath filters to see how path resolution behaves for the same code when run sandboxed vs unsandboxed.

Key observables:

* Success/failure and errno for each file operation under each profile.
* Which paths are permitted vs denied as rules change.
* Whether unspecified operations truly inherit the default action.

Family F5 – Higher-level operations (Apple Events, preferences, devices)

Description: Probes that test sandbox control over non-filesystem operations.

Member hypotheses: H12, H13, H14.

Probe shapes:

1. Probe F5-A (Apple Events): Sandboxed macOS app that tries to send Apple Events to various targets (e.g., another user app, Finder), with and without explicit appleevent-send allowances in its profile, and prints success/failure.
2. Probe F5-B (Preferences): App that attempts to read and write preferences in its own domain and in another app’s domain, under profiles with and without user-preference-read / user-preference-write rules scoped to those domains.
3. Probe F5-C (Devices): App under profiles that explicitly deny vs allow device-microphone and device-camera, attempting to open audio/video capture and reporting success/failure at the API level.

Key observables:

* Whether Apple Event sends succeed or fail, and any error codes.
* Which preference domains are readable/writable; presence/absence of changes.
* Ability to open microphone/camera devices under different rule configurations.

Family F6 – MACF / Sandbox evaluation path and coverage

Description: Probes that compare sandboxed vs unsandboxed behaviour across operations that are supposed to be mediated by MACF and Sandbox.

Member hypotheses: H16, H17, H19.

Probe shapes:

1. Probe F6-A: Battery of syscalls and operations (file, process, network, IPC) from sandboxed and unsandboxed processes, logging outcomes and errno, to identify operations whose behaviour changes when Sandbox is present.
2. Probe F6-B: For sandboxed processes, comparison of sandbox_check results (userland) with actual syscalls for the same operation, to verify alignment.
3. Probe F6-C: Where practical, instrumentation (e.g., dtrace) to see which MACF hooks fire for various operations, confirming that only a subset is bound to Sandbox.

Key observables:

* Differential success/failure patterns between sandboxed and unsandboxed processes per operation.
* Cases where sandbox_check predicts denial vs actual kernel behaviour.
* Observed mapping from OS-level operations to Sandbox-enforced decisions, highlighting coverage gaps.

Family F7 – Sandbox extensions and delegated access

Description: Probes that exercise sandbox extension issuance and consumption to observe delegated capabilities.

Key behaviours to validate include that the issuer must already have access and the consumer must explicitly consume the token, and whether tokens remain valid across reboot or process changes consistent with the boot-secret/non-reuse model.

Member hypotheses: H18 (and related constraints implied by H11/H12/H13/H14 where extended).

Probe shapes:

1. Probe F7-A: Privileged issuer process that can read a target file and a sandboxed consumer process that cannot; issuer calls sandbox_extension_issue_file* (or equivalent) and passes the token to consumer, which consumes it and attempts read/write operations, printing results.
2. Probe F7-B: Consumer process that tries to re-use an already consumed token or use a token for a different resource than issued, printing whether these operations succeed or fail.
3. Probe F7-C: Issuer that attempts to issue an extension for a resource it itself cannot access, observing whether issuance fails or yields a token that is ineffective. (Inference: this tests implied constraints about issuer capabilities.)

Key observables:

* Whether consumers gain access to specific resources after consuming a token.
* Error codes or failure modes when tokens are misused or re-used.
* Whether issuing extensions for inaccessible resources is prevented or results in impotent tokens.

Family F8 – Exec-time changes in sandbox state

Description: Probes that observe how sandboxing behaves across exec, focusing on the cred_label_update_execve hook’s described semantics.

Member hypotheses: H15 (and partially H5).

Probe shapes:

1. Probe F8-A: Parent process that starts unsandboxed, then execs into a sandboxed binary (with App Sandbox entitlement) and records changes in its ability to access files and system resources before and after exec.
2. Probe F8-B: Parent that starts sandboxed and execs into a binary without the App Sandbox entitlement, checking whether it remains sandboxed (as implied by sandbox being attached during exec based on the new binary’s entitlements).
3. Probe F8-C: Variants where the binary’s entitlements differ only in subtle ways (e.g., presence/absence of some capability-related entitlements) and comparing resulting access patterns.

Key observables:

* Change (or lack thereof) in observed sandbox restrictions across exec.
* Whether the presence/absence of App Sandbox entitlement at the new binary actually flips sandboxing on/off as described.
* Any asymmetries between starting sandboxed vs becoming sandboxed via exec.

4. Stability vs drift analysis

Here each hypothesis is tagged and briefly justified.

* H1 (Container location for sandboxed macOS apps)
  Tag: Likely version-fragile detail.
  Justification: Relies on a specific path under `~/Library/Containers`, which is a naming/layout choice that Apple could change without altering the conceptual role of containers.

* H2 (Container creation timing on macOS)
  Tag: Likely structural invariant.
  Justification: The distinction “container created on first launch, not install” is tied to the model of user-specific containers; changing this would affect install vs first-run semantics system-wide.

* H3 (Container layout resembles a private home)
  Tag: Likely version-fragile detail.
  Justification: The presence and names of subdirectories (Documents, Library, etc.) are convenient but easy to modify without architectural change.

* H4 (Unsandboxed apps lack App Sandbox entitlement)
  Tag: Likely structural invariant.
  Justification: The design intent is that App Sandbox is opt-in on macOS via entitlement; flipping this would be a major policy change.

* H5 (secinit uses com.apple.security.app-sandbox on macOS)
  Tag: Likely structural invariant.
  Justification: Ties sandboxing to secinit and entitlements; those are core pieces of the trust chain and expensive to re-architect.

* H6 (no-sandbox gate on iOS)
  Tag: Explicitly versioned in this paper (platform-specific) + likely structural invariant for iOS.
  Justification: Described as “on iOS” with a particular entitlement; the pattern “third-party apps are always sandboxed” is fundamental there.

* H7 (seatbelt-profiles entitlement selects profile)
  Tag: Likely version-fragile detail.
  Justification: Relies on a specific entitlement name and its precise meaning; Apple could change how profile selection is expressed while keeping the underlying concept.

* H8 (Container metadata includes profile blobs)
  Tag: Likely version-fragile detail.
  Justification: Depends on property list keys and the exact shape of metadata for containermanagerd; these are easier to change than overall architecture.

* H9 (SIP enforced via sandbox profile)
  Tag: Likely structural invariant.
  Justification: Using a platform-wide profile to protect system paths is a deep integration of SIP and Sandbox; changing this would alter core system-hardening semantics.

* H10 (SBPL default rule semantics)
  Tag: Likely structural invariant.
  Justification: Default-allow vs default-deny is fundamental to the policy language and evaluator; any change would break existing profiles.

* H11 (File operation families with path filters)
  Tag: Likely structural invariant, with version-fragile details.
  Justification: The idea of path-scoped file operation families is central; specific filter names or additional operations may evolve.

* H12 (device-microphone/device-camera operations)
  Tag: Likely version-fragile detail.
  Justification: These are specific operations; new devices or access models may be added, and the mapping from entitlements to these operations is not specified here.

* H13 (appleevent-send is macOS-only and sandboxed)
  Tag: Likely structural invariant (for macOS) with platform constraint.
  Justification: Apple Events are macOS-specific IPC; the operation name and existence are unlikely to move platforms but could be refined.

* H14 (user-preference-* scoped by domain)
  Tag: Likely structural invariant.
  Justification: Scoping preferences by domain is a natural and stable abstraction; redesigning it would affect many apps.

* H15 (Sandbox attached at exec via cred_label_update_execve)
  Tag: Likely structural invariant.
  Justification: Attachment of sandbox state to credentials at exec is central to the design; changing it would require reworking how processes inherit policy.

* H16 (All Sandbox MACF hooks funnel through cred_sb_evaluate)
  Tag: Likely structural invariant.
  Justification: A central evaluator is a key internal structuring choice; while implementation details may change, the pattern “all hooks call a core evaluator” is hard to discard.

* H17 (Sandbox implements a subset of MACF operations)
  Tag: Explicitly versioned in this paper.
  Justification: The approximate counts given are explicitly about “current systems”; the exact size of the subset is expected to drift as Apple adds/removes hooks.

* H18 (Sandbox extensions grant specific additional capabilities)
  Tag: Likely structural invariant with unknown fine details.
  Justification: Delegation via extensions across processes is a core mechanism; token formats and specific extension kinds may drift.

* H19 (Userland Sandbox APIs mirror kernel decisions)
  Tag: Likely structural invariant.
  Justification: The stated goal is for sandbox_check and similar APIs to expose the same decisions as the kernel; divergence would be a serious bug in the design model.

Where extrapolations (e.g., issuer capabilities for extensions, extension lifetime) are desirable to test but not clearly stated, they should be treated as “provisional, inferred from design intent” and explicitly tagged as such in your own catalog.

5. Risk register and catalog notes

Below are mechanism areas/themes and how to treat WORMSLOOK2024’s claims when building a capability catalog.

1. App Sandbox entitlement as the macOS gate (H4, H5, H15)

   * Paper’s claim: com.apple.security.app-sandbox controls whether secinit and libsandbox initialize the App Sandbox for macOS processes; sandbox is attached at exec via cred_label_update_execve.
   * Stability: High-confidence design intent, likely structural invariant.
   * Catalog treatment: Model as a stable capability boundary (“App Sandbox on/off”). For each capability, record whether it is observed under sandboxed vs unsandboxed runs; assume the presence of this entitlement is the primary macOS gate unless probes suggest otherwise.

2. Containers and per-app filesystem isolation (H1, H2, H3, H11)

   * Paper’s claim: Sandboxed macOS apps get per-app containers under `~/Library/Containers`; those are created on first launch and act like a private home; SBPL rules use container-relative filters.
   * Stability: Conceptual isolation is stable; exact paths and layout are version-fragile.
   * Catalog treatment: Model container-scoped capabilities (read/write within container) as stable conceptual capabilities, but treat any hard-coded path layout as provisional. Probes should detect container roots instead of assuming exact locations.

3. SIP / system-level sandbox profile (H9)

   * Paper’s claim: System Integrity Protection is partly implemented as a Sandbox profile that denies writes to critical system paths, even for non-App-Sandbox processes.
   * Stability: High-confidence design intent.
   * Catalog treatment: Represent SIP-based protections as a separate, always-on capability layer that applies regardless of App Sandbox; mark it as stable, but keep specific protected path sets as potentially drifting and subject to empirical confirmation.

4. SBPL language semantics and operation families (H10, H11, H12, H13, H14)

   * Paper’s claim: Profiles have a default rule and per-operation-family allow/deny rules with filters; there are operations for files, devices, Apple Events, preferences, etc.
   * Stability: Core semantics (default rule, operation families, filter types) look stable; the list of operations and some higher-level ones (devices, Apple Events) may evolve.
   * Catalog treatment: Treat the existence of operation families and their basic semantics as stable design; treat the membership and detailed effects of individual operations as provisional, to be validated via probes. Where the paper only gives examples (preferences, devices), mark those as “needs empirical confirmation”.

5. secinit behaviour and iOS differences (H6, H7, H8)

   * Paper’s claim: On macOS, secinit uses com.apple.security.app-sandbox to decide sandboxing; on iOS, com.apple.private.security.no-sandbox and seatbelt-profiles plus container metadata govern sandboxing and profile selection.
   * Stability: Concept (launch-time entitlement-based decisions) is stable; specific entitlement names and metadata keys are version-fragile, especially on iOS.
   * Catalog treatment: For macOS, treat “secinit gate on App Sandbox” as strong design intent. For iOS-specific details, model them as hypotheses only and keep them clearly partitioned from macOS entries, marked as “platform-specific, confirm on target OS”.

6. MACF integration and central evaluator (H16, H17, H19)

   * Paper’s claim: Sandbox is a MACF policy module; its hooks call cred_sb_evaluate, which calls an internal evaluator; only some MACF operations are covered. Userland APIs query the same decisions.
   * Stability: Core design is likely stable; exact hook coverage drifts with OS versions.
   * Catalog treatment: Assume Sandbox decisions are mediated through MACF for a defined set of operation types; mark the coverage list as “empirically mapped per version”. For capability catalog entries, link each capability to both its conceptual operation and the MACF hook(s) observed in probes, not to the paper’s static counts. Treat observed decisions as the product of both platform-wide profiles and app-specific profiles, where any deny from those layers or other MAC policies blocks the operation.

7. Sandbox extensions and delegated access (H18)

   * Paper’s claim: Extensions are tokens granted to delegate specific access (e.g., to user-selected files) from a process that already has that access to one that does not; consuming a token associates extra rights with the sandbox.
   * Stability: Delegation mechanism is likely stable; token formats, classes, and fine-grained rules may drift.
   * Catalog treatment: Treat “extension-mediated capabilities” as a distinct class: not baseline, not entitlement-only, but dynamic grants. Mark this area as “provisional, confirm with probes,” especially around lifetime, revocation, and issuer constraints, since WORMSLOOK2024 does not fully specify these.

Overall, WORMSLOOK2024 is a strong guide to structural mechanisms (entitlement-driven sandboxing, containerization, MACF-based enforcement, SBPL semantics) and a suggestive but incomplete source for fine details (exact paths, ent names, counts of hooks, extension nuances). A capability catalog built on this paper should treat structural patterns as design intent, but should attach a “needs empirical confirmation” flag to anything that depends on specific names, directory layouts, numeric counts, or under-specified extension behaviour.
