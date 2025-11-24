# Overview

Apple’s macOS sandbox (codenamed **Seatbelt**) is a kernel-level mandatory access control system that confines processes according to fine-grained policies. The classic public reverse-engineering of its design is Blazakis’s 2011 Black Hat paper, *The Apple Sandbox* ([Blazakis 2011](/mnt/data/BLAZAKIS2011.pdf)). A large-scale empirical view of sandbox usage and entitlements in the wild comes from *State of the Sandbox: Investigating macOS Application Security* ([Blochberger et al. 2019](/mnt/data/STATEOFSANDBOX2019.pdf) and [online](https://doi.org/10.1145/3338498.3358654)). For the modern pipeline around containers, extensions, and secinit/containermanagerd, we have *A Worm’s Eye View of the Apple Sandbox* ([Worm’s Eye 2024](/mnt/data/WORMSLOOK2024.pdf)) plus current Apple behavior as observed in macOS 14–15 (e.g. container behavior in Sonoma as described in [what-are-all-those-containers](https://eclecticlight.co/2024/08/05/what-are-all-those-containers)).

This report treats those three as **time-stamped anchors**:

- **2011** – internal Seatbelt implementation (TinyScheme/SBPL, AppleMatch, Sandbox.kext, libsandbox, sandboxd).
- **2019** – real-world sandbox adoption and entitlement practice across MAS vs third-party ecosystems.
- **~2024+** – modern pipeline: code signing → secinit → containers/containermanagerd → libsandbox/profiles → Sandbox.kext/MACF → TCC/hardened runtime.

We focus on:

1. How internals around 10.6–10.7 compare to modern macOS (Ventura/Sonoma).
2. How sandbox and entitlement usage evolved from ~2019 to ~2025.
3. How today’s sandbox pipeline is structured and which components are stable vs high-churn.

---

## 1. Seatbelt Internals “2011 vs 2020s”

### 1.1 2011 architecture (10.6–10.7 snapshot)

Blazakis 2011 gives a detailed map of the Seatbelt internals on Snow Leopard / Lion:

- **Policy language (SBPL) and TinyScheme**

  - Profiles were expressed in a private **Sandbox Profile Language (SBPL)**, a Scheme-like EDSL.
  - `libsandbox.dylib` embedded a modified **TinyScheme 1.38** interpreter. The Scheme stub and SBPL body (`sbpl_1.scm`) compile a profile into a table `*rules*` mapping operation codes (e.g. `file-read-data`, `network-outbound`) to lists of rules and jumps.
  - At compile time, the Scheme EDSL builds a decision graph; at runtime the kernel never runs Scheme, only this compiled graph.

- **libsandbox and `sandbox_init`**

  - The public entry point `sandbox_init()` lived in **libSystem** and delegated to **libsandbox.dylib**.
  - Depending on flags, libsandbox:
    - Interpreted the profile argument as a literal SBPL string (`SANDBOX_NAMED` vs “profile as string” mode).
    - Looked up named built-in profiles like `no-internet` that correspond to C strings (e.g. `kSBXProfileNoInternet`).
    - Or loaded `.sb` files from `/usr/share/sandbox/` (e.g. `named.sb`, `sshd.sb`).
  - After TinyScheme evaluation, libsandbox produced a **binary profile blob** and passed it to a generic `__mac_syscall` stub (`sandbox_ms`) with policy name `"Sandbox"` and a “call number” for sandbox install.

- **Sandbox.kext and MACF hooks**

  - The sandbox was implemented as a MACF policy module in kernel extension **Sandbox.kext**.
  - On load, Sandbox.kext called `mac_policy_register` with a config struct that:
    - Registered the policy under name `"Sandbox"`.
    - Provided a function pointer table (`policy_ops`) implementing hooks for MAC operations (e.g. file open, network operations, process control).
    - Used a per-credential label slot to store sandbox state (compiled profile and extensions).
  - For sandboxed processes, each hooked operation routed into a **common evaluator** (e.g. functions often called `cred_sb_evaluate` internally), which walked the compiled rules to decide allow/deny.

- **AppleMatch.kext (regex engine)**

  - Profiles could define regex-like path filters `(regex "^/private/var/...")`.
  - These compiled to a sub-format used by **AppleMatch.kext** in the kernel, which provided functions like `matchUnpack` and `matchExec`.
  - Userspace **libMatch.dylib** compiled regexes into a binary NFA form AppleMatch understood. Sandbox.kext called into AppleMatch for path matching.

- **sandboxd (logging daemon)**

  - A Mach server **sandboxd** received trace/log messages from Sandbox.kext when a profile was installed or a decision was made.
  - Tracing could be enabled in profiles (e.g. via SBPL debug directives) to log decisions, useful for profile debugging.
  - Enforcement itself remained entirely in kernel; sandboxd was diagnostic.

Overall, 2011 Seatbelt is a **user-space compiler (TinyScheme/SBPL)** feeding a **closed-source kernel policy engine (Sandbox.kext + AppleMatch)**, with **sandboxd** for logging and **`sandbox-exec`** as a CLI wrapper over `sandbox_init`.

### 1.2 2020s status of those components

On modern macOS (Ventura/Sonoma and likely onwards), most of those pieces still exist conceptually, but with additional layers and some refactoring.

#### SBPL and TinyScheme

- The underlying **SBPL language persists**:
  - System sandbox profiles in `/System/Library/Sandbox/Profiles` / `/usr/share/sandbox` are still Scheme-like `.sb` files.
  - iOS and macOS share similar SBPL semantics; tools such as SandBlaster confirm a consistent compiled graph representation from iOS 7 onward.
- The embedded interpreter (TinyScheme-derived) in libsandbox remains the mechanism for Apple’s internal policies and generic “container” profiles.
- Crucially, **third-party Mac apps no longer supply arbitrary SBPL**:
  - For App Store apps, the profile is a template chosen by Apple, parameterized by entitlements.
  - This dramatically reduces SBPL surface exposed to untrusted data; most SBPL evaluation is driven by Apple-provided profiles.

**Stability:** High at the conceptual level. The language and “compile to decision graph” design have survived >10 years. Binary profile format evolved once (iOS 7 era) but is not frequently changed now.

#### libsandbox, secinit, and automatic sandboxing

- Modern macOS loads `libsystem_secinit.dylib` early via `dyld`. Secinit:
  - Reads entitlements from the code signature.
  - On macOS, checks `com.apple.security.app-sandbox` (App Sandbox entitlement).
  - If present, calls into libsandbox to initialize the sandbox **before** `main()` or C++ static initializers run.
- For App Store apps, developers rarely call `sandbox_init` directly; the runtime applies the sandbox automatically based on entitlements.
- Profiles are now **compiled and cached**:
  - On first launch, libsandbox and containermanagerd work together to compile a profile from a base template plus entitlements.
  - The compiled blob and validation info are stored in the app’s container metadata plist (see below).
  - Subsequent launches reuse the compiled profile.

A notable bug here was the **UTF-8 BOM bug** (CVE-2018-4229):

- Some apps contained a BOM at the start of the embedded entitlements plist.
- `libsystem_secinit` failed to parse entitlements correctly, silently **skipping sandbox initialization**.
- This allowed MAS apps to appear sandboxed (entitlement present) but run unsandboxed at runtime.
- Reported and fixed around macOS 10.13.5; modern secinit is hardened to handle BOM and malformed entitlements, closing this escape.

**Stability:** High. secinit’s job (read entitlements → apply sandbox/hardened runtime) is stable; implementation has been hardened but not conceptually altered.

#### Sandbox.kext and MACF enforcement

- Sandbox enforcement remains in the kernel as a policy module (built into the kernel or kernel collection; historically exposed as Sandbox.kext).
- It still:
  - Registers with MACF under the sandbox policy name.
  - Uses a label slot in `ucred`/credentials for sandbox state.
  - Defines a large table of **hook functions** for MAC operations; the set has grown (roughly 150+ operations enforced in macOS 14).
- Internals (function names, structure fields) have evolved, but patterns are the same:
  - `cred_label_update_execve` builds a sandbox for new processes (reading entitlements, assigning containers, issuing sandbox extensions).
  - Common evaluator logic (`sb_evaluate_internal`–style) walks the profile decision graph.
  - Returns allow/deny/“defer” decisions to MACF.

**Stability:** Very high conceptually. The hook-based, policy-graph evaluation model has remained intact from 10.5 through 14.x.

#### AppleMatch / regex matcher

- Profiles still contain regex and wildcard path rules, so an internal regex/NFA engine still exists.
- On older macOS, this clearly lived in **AppleMatch.kext**; modern kernels may inline that implementation or keep it as a private kernel extension.
- There are no prominent public changes to the regex semantics; Apple appears to have kept the regex engine as an internal dependency with occasional hardening/performance tweaks.

**Stability:** Medium-high. The existence of regex-backed filters and a compiled regex subformat is stable; the exact kext/module packaging may have changed.

#### sandboxd

- `sandboxd` still exists on macOS as a Mach service.
- It primarily receives logging and trace messages from Sandbox.kext; enforcement remains purely in kernel.
- With the advent of unified logging, sandboxd’s output integrates into the log system rather than standalone logs.
- It is not on the critical path for decisions; if sandboxd dies, enforcement continues.

**Stability:** High, but low impact; sandboxd is a diagnostic component.

#### New: containermanagerd

The biggest new piece compared to 2011 is **containermanagerd**:

- A daemon and private framework (`ContainerManagerCommon`) that manages app **containers**:
  - Mac app containers live in `~/Library/Containers/<bundle-id>`.
  - On first launch/installation, containermanagerd creates the container directory structure and writes a metadata plist inside it.
- That metadata plist typically contains:
  - The app’s identifier.
  - `SandboxProfileData` (Base64 compiled sandbox profile).
  - `SandboxProfileDataValidationInfo` (inputs for libsandbox to regenerate/validate the profile).
  - Possibly a copy of the entitlements.
- containermanagerd then:
  - Exposes an interface used at exec time when Sandbox.kext asks for container info.
  - Supplies sandbox extensions that grant access to the container path.
  - Manages cleanup/migration of container content on updates and uninstalls.

Recent macOS releases have extended containermanagerd’s role:

- In macOS 14 Sonoma, Apple added **cross-app container access protection**:
  - Each container is associated with a specific app (by code signature).
  - Attempts by another app to access that container trigger an OS dialog like “Allow X to access data from Y?” as described in [what-are-all-those-containers](https://eclecticlight.co/2024/08/05/what-are-all-those-containers).
  - containermanagerd participates by enforcing per-app association and mediating extension issuance.

**Stability:** Medium. The high-level contract (“daemon that owns container metadata and provides container sandbox extensions”) is stable, but its privacy policies (e.g. container access prompts) evolve with OS versions.

---

## 2. Sandbox & Entitlement Practice “2019 vs 2025”

### 2.1 2019 baseline: adoption and entitlements

The *State of the Sandbox* paper (WPES 2019) systematically measured sandbox adoption and entitlements across ~13,000 macOS apps from two sources: the Mac App Store (MAS) and MacUpdate (MU) as a third-party catalog.

Key findings circa Mojave/Catalina:

- **Adoption in Mac App Store vs outside**

  - **MAS:** Over 93% of MAS apps in the dataset were sandboxed, matching Apple’s post-2012 rule that MAS apps must enable the App Sandbox entitlement.
  - **MU (third-party):** Around 89% of apps downloaded from MU were **not sandboxed**. Sandboxing remained optional and rarely used voluntarily outside MAS.

- **Consistency across versions**

  - For MAS apps, once an app became sandboxed, subsequent versions usually stayed sandboxed.
  - Only a handful of MAS apps showed both sandboxed and unsandboxed versions; these often corresponded to early releases or anomalies like the BOM bug.

- **Entitlement usage patterns**

  Among MAS sandboxed apps, entitlements were used relatively conservatively:

  - **Network client** (`com.apple.security.network.client`):
    - Enabled in ~65% of sandboxed apps; reflects need for at least outbound connections in many categories.
  - **User Selected Files** entitlements:
    - Read/write user-selected files via PowerBox were enabled in ~45% of sandboxed apps, read-only variant in ~7–8%.
    - This is the default mapping Xcode applies when enabling the App Sandbox: apps can access only files the user explicitly selects in open panels.
  - **Printing, server, downloads, media folders**:
    - Printing entitlements appeared in roughly 13–14% of sandboxed apps.
    - Network server entitlements (~13%) were rarer; only apps that truly needed to listen on sockets requested them.
    - Downloads folder or media folder entitlements were used in single-digit percentages, mostly in obvious categories (e.g. Video apps with Movies folder access).
  - **Co-occurrence:** Camera and Microphone entitlements co-occurred frequently; if an app recorded video, it almost always declared both.

- **Temporary exception & private entitlements**

  - **Temporary exceptions:**
    - Used rarely; only a few percent of MAS apps.
    - A common example: temporary exception for automation (AppleEvents) so a sandboxed app could script other apps.
    - These exceptions highlight places where sandbox rules were too strict for existing workflows; Apple intended them to be phased out over time.
  - **Private entitlements:**
    - Only Apple’s own apps used private entitlements (e.g. for direct TCC DB access or privileged hardware).
    - Third-party apps in MAS did not have private entitlements except in extraordinary cases (e.g. special partner agreements on iOS, not seen in this macOS dataset).

- **Privilege separation via XPC**

  - MAS apps frequently used XPC helpers (`*.xpc` bundles) with **reduced entitlements** compared to the main app, implementing proper privilege separation.
  - Outside MAS, many XPC helpers were **unsandboxed** even when the main app was sandboxed (for some MU apps), weakening their security.

- **Sandbox bypass (BOM bug)**

  - The authors discovered apps with the app-sandbox entitlement set but not actually sandboxed at runtime.
  - Root cause: entitlements plist started with a UTF-8 BOM; secinit failed and sandbox initialization didn’t happen.
  - This bug allowed MAS apps to bypass mandatory sandboxing until Apple patched it.

### 2.2 2019–2025: tightening environment and evolving practice

Between 2019 and 2025, Apple significantly tightened the environment, especially for non-MAS apps:

#### Hardened Runtime & notarization

- Starting with macOS 10.15 Catalina, **notarization** and the **Hardened Runtime** became effectively mandatory for most third-party apps (Gatekeeper defaults).
- The Hardened Runtime introduces its own set of entitlements (similar keys) that:
  - Govern access to supposedly sensitive behaviors (JIT, dynamic library loading, debug permissions).
  - Govern access to user-facing resources (camera, microphone, location, contacts, calendars, photos, screen recording, input monitoring).
- Critical point: without the appropriate hardened-runtime entitlement plus Info.plist usage strings, **no TCC prompt is shown**—access is silently denied. This mirrors sandbox entitlements but applies to unsandboxed apps as well.
- Effect by 2025:
  - Most third-party apps outside MAS ship with some entitlements anyway, even if not sandboxed, to ensure TCC prompts can appear.
  - Security posture of unsandboxed apps is closer to “sandbox-like permissions + full disk access toggles” rather than the older “no constraints” model.

#### Expanded TCC coverage

- Mojave (2018) introduced TCC prompts and protection for:
  - Contacts, calendars, reminders, photos, camera, microphone, mail, messages, Safari data, files in Documents/Desktop/Downloads, and more.
- Catalina/Big Sur/Monterey further added:
  - Screen recording, input monitoring, Bluetooth, and local network access prompts.
- Sonoma (2023–2024) extended TCC-like controls to **other apps’ containers**:
  - Attempts to access another app’s container can trigger an OS-level prompt or be blocked, as described in [what-are-all-those-containers](https://eclecticlight.co/2024/08/05/what-are-all-those-containers).
- By 2025, whether or not an app is sandboxed, **TCC acts as a second sandbox for private data**.

#### Entitlement ecosystem maturity

- For MAS apps:
  - The set of App Sandbox entitlements has been stable since roughly 2018, with only incremental additions (e.g. for new APIs).
  - Developer tooling (Xcode’s capabilities UI) makes entitlement use more systematic; category-specific combos (e.g. Photos app needs Photos + Camera + User Selected Files) are common and documented.
- For non-MAS apps:
  - Hardened runtime entitlements make previously unregulated capabilities (e.g. injecting code, unrestricted AppleEvents, screen recording) require explicit declaration and, often, user approval.
  - Many vendors have rationalized their privilege usage; for example:
    - VPN clients use specific network extension entitlements.
    - Backup tools request Full Disk Access in addition to entitlements.

### 2.3 What a “typical” sandboxed macOS app can do today

For a few categories, here’s how a modern (~2025) app looks compared to 2019:

#### Productivity apps (editors, office suites)

- **2019 (MAS):**
  - Sandboxed app, with:
    - App Sandbox enabled.
    - Network client entitlement for sync/licensing.
    - “User Selected Files” read/write; maybe Downloads folder access.
    - Printing entitlement if needed.
  - Could not freely traverse `~/Documents` or arbitrary paths; user needed to open/import files via system dialogs (PowerBox).
  - Automation/AppleEvents limited; temporary exceptions used for some scripts.

- **2025 (MAS):**
  - Very similar sandbox story; the seatbelt side is stable.
  - Integrates more deeply with TCC:
    - Access to contacts/calendars, etc., always mediated by TCC prompts and corresponding entitlements.
  - Automation is now more constrained:
    - Even with an entitlement/temporary exception, user must approve one app controlling another in System Settings (Automation section).
  - iCloud/CloudKit usage has expanded, reducing the need for broad local file entitlements.

- **2025 (outside MAS):**
  - Typically unsandboxed, but:
    - Must be hardened/notarized to run smoothly.
    - Needs hardened runtime entitlements for: AppleEvents automation, camera/microphone, screen recording, etc.
    - Needs Full Disk Access granted by user to index or backup all files.
  - In practice, they now operate behind TCC and hardened runtime, even without App Sandbox.

#### Browsers

- **2019:**
  - Safari: Apple-signed, heavily sandboxed multi-process architecture.
  - Chrome/Firefox: Not App-Sandboxed as a whole, but used Seatbelt for renderer processes via custom SBPL profiles; main process unsandboxed.
  - TCC starting to gate camera/mic access.

- **2025:**
  - Safari: continues to harden internal sandboxes (per-tab, per-extension), plus strict TCC integration for camera/mic, screen share.
  - Chrome/Chromium-based browsers:
    - Use sandboxed renderer processes on macOS aggressively.
    - Have adopted hardened runtime entitlements and proper info.plist usage descriptions for all privacy-sensitive APIs.
    - Unsandboxed main process still has broad system access, but sensitive resources (input monitoring, screen, camera) require TCC approval.
  - The net effect: **renderer exploits must chain a sandbox escape**; browser sandboxes are narrower and less forgiving than in 2011–2013.

#### Utilities and developer tools

- **2019:**
  - Many were unsandboxed to support tasks like:
    - Traversing entire filesystem.
    - Injecting into other processes.
    - Using kexts for low-level hooks.
  - TCC existed but had fewer categories; Full Disk Access was newly introduced.

- **2025:**
  - Many remain unsandboxed by necessity, but:
    - Gatekeeper and hardened runtime are mandatory.
    - Full Disk Access, Automation, Screen Recording, Input Monitoring must be explicitly granted by the user in System Settings.
    - Some tasks moved to controlled frameworks (EndpointSecurity, System Extensions), which themselves have dedicated entitlements and APIs.
  - Some tools adopt a **split model**:
    - Sandbox the GUI front-end.
    - Communicate with a privileged helper via XPC or a launchd service to perform restricted operations.

Overall, the **gap between MAS and non-MAS apps has narrowed** in terms of what they can silently do. MAS apps have always been sandboxed; non-MAS apps now face strong TCC/hardened-runtime constraints.

---

## 3. Modern Pipeline & Moving Parts

Using Worm’s Eye and current behavior as the spine, the modern macOS sandbox pipeline looks like this:

1. **Code signing & Gatekeeper**
2. **Process launch & secinit**
3. **Container management via containermanagerd**
4. **Profile selection & compilation via libsandbox**
5. **Kernel enforcement via Sandbox.kext (MACF hooks) and sandbox extensions**
6. **Overlay of TCC and hardened runtime**

### 3.1 Code signing, Gatekeeper, and hardened runtime

- Before execution, macOS verifies:
  - Code signature (Developer ID or App Store).
  - Notarization status for downloaded apps.
- If notarized, **Hardened Runtime** is enabled:
  - Restricts dynamic code behavior unless entitlements permit it.
  - Governs whether TCC prompts can appear (e.g., camera/mic entitlements).
- Gatekeeper and hardened runtime are **preconditions**: they determine which entitlements are active and which behaviors are allowed at all.

**Stability:** High. Notarization/hardened runtime have been in place since Catalina with incremental refinements.

### 3.2 secinit (libsystem_secinit.dylib)

- During `execve`, `dyld` loads `libSystem`, which pulls in **libsystem_secinit.dylib**.
- secinit:
  - Reads entitlements from the code signature.
  - On macOS:
    - If `com.apple.security.app-sandbox=true`, marks the process as needing a sandbox.
  - Sets up hardened runtime gates (e.g., library validation) according to entitlements.
- For sandboxed apps, secinit is the user-space place where libsandbox is invoked automatically to prepare sandboxing early.

**Stability:** High role; implementation hardened over time (e.g. BOM fix) but behavior consistent across recent macOS.

### 3.3 containermanagerd and containers

- If App Sandbox is enabled, the system ensures the app has a container:
  - `~/Library/Containers/<bundle-id>` on macOS.
- **containermanagerd**:
  - Creates and manages containers for apps and helpers.
  - Writes metadata plist files in each container:
    - Includes `SandboxProfileData` (compiled SBPL) and `SandboxProfileDataValidationInfo`.
    - Possibly caches entitlement info and other runtime parameters.
  - Provides an IPC interface used at exec time:
    - When Sandbox.kext’s exec hook decides to sandbox a process, it calls into containermanagerd to:
      - Get or create the container path.
      - Obtain sandbox extensions that represent “container access” tokens.
- In Sonoma and later:
  - Container metadata is associated with the owning app identity.
  - Attempts by other apps to read that container are mediated and can be blocked or require user consent (see [what-are-all-those-containers](https://eclecticlight.co/2024/08/05/what-are-all-those-containers)).

**Stability:** Medium. The container model is long-term; privacy policies around cross-app access are actively evolving.

### 3.4 Profile selection & compilation

At exec time, Sandbox.kext and libsandbox cooperate to choose and compile the profile:

- **Profile selection:**
  - On macOS:
    - Third-party apps default to a generic “container” profile (App Sandbox) whose behavior is modulated by entitlements.
    - Apple’s system processes or apps may use specific SBPL files with imports and custom rules.
- **Compilation:**
  - libsandbox takes:
    - The SBPL base profile(s).
    - Entitlements (converted into SBPL rules).
    - Possibly other config (debug, tracing).
  - Produces:
    - A binary decision graph/profile compatible with Sandbox.kext.
  - This result is stored in `SandboxProfileData` and reused until something changes (e.g. entitlements change, OS update).

**Stability:** Medium. The pipeline and language are stable; new operations/filters and small format changes are introduced as macOS evolves.

### 3.5 Kernel enforcement: Sandbox.kext, MACF hooks, and sandbox extensions

Once a process is sandboxed, every relevant kernel operation triggers a sandbox check:

- **MACF operations and hook table**

  - Sandbox.kext implements hooks for ~160 MAC operations (file, network, IPC, etc.).
  - Each hook:
    - Extracts context (e.g. path, socket address, target PID).
    - Invokes the common evaluator with operation code and arguments.
    - Returns allow/deny/“defer” results back to the MACF dispatcher.

- **Sandbox decision graph**

  - Compiled profile is a graph of nodes (tests and jumps).
  - Tests can check:
    - Operation and basic parameters.
    - Path matches (possibly calling regex engine).
    - Entitlements or bundle identifiers (for some policies).
    - Presence/contents of sandbox extensions.
  - Graph executes until a terminal rule (allow/deny) or jump target is reached.

- **Sandbox extensions**

  - Extensions are tokens representing capabilities:
    - Common types: file path access, container access, Mach service lookup.
  - Issued by kernel or privileged daemons (e.g. PowerBox for file dialogs).
  - Consumed by sandboxed processes at runtime to gain access beyond the default profile.
  - Extension tokens are:
    - Signed or MAC’d using a boot-specific secret.
    - Often tied to specific paths or services and a particular process or session.
  - Used heavily for:
    - Container access at process start.
    - Access to user-selected files.
    - Some cross-process communication patterns.

**Stability:** High in concept. Many details (extension format, set of operations covered) are incremental; the overall mechanism is consistent.

### 3.6 TCC and hardened runtime overlay

Parallel to sandbox enforcement:

- **TCC (Transparency, Consent, Control)**

  - Enforces per-app permissions for private data:
    - Contacts, calendars, photos, camera, microphone, screen recording, input monitoring, Bluetooth, local network, etc.
  - Uses:
    - A database of decisions (per service, per app).
    - A set of kernel or user-space hooks to intercept access and route decisions through `tccd`.
  - For sandboxed apps:
    - TCC acts on top of sandbox: if sandbox allows an API, TCC can still deny it.
  - For unsandboxed apps:
    - TCC is often the *only* barrier between the app and user data.

- **Hardened runtime entitlements**

  - Control whether an app can even invoke certain high-risk behaviors:
    - Debugging, JIT, DYLD injection, etc.
    - Access to camera, mic, location, etc. (mirroring sandbox entitlements).
  - Without the appropriate entitlements and usage descriptions, the OS will not show a TCC prompt, resulting in silent denial.

**Stability:** Medium. TCC categories and hardened entitlements have reached a relatively mature set, but Apple continues to refine them (e.g. new categories like cross-app container access).

---

## 4. Implications

### 4.1 Stable anchors for code archeology and tooling

For XNUSandbox work and related reverse-engineering, some parts of Seatbelt are good long-term anchors:

- **MACF hook model**

  - The fundamental design—kernel hooks plus a policy module—has been stable since Leopard.
  - XNU headers (`mac_policy.h`) expose the list of MAC operations across versions.
  - Sandbox’s hook set is supersets of earlier ones; new operations are added, old ones rarely removed.

- **Profile language and compiled format**

  - SBPL remains the configuration language for system policies.
  - The compiled graph representation is stable enough that tools like SandBlaster can decompile across iOS/macOS generations with minor adjustments.
  - For repo work like XNUSandbox, investing in a robust SBPL/bytecode parser continues to pay off; diffing profiles across OS versions is a powerful way to observe policy evolution.

- **Sandbox evaluator structure**

  - The presence of a central evaluator (`sb_evaluate_internal`-style functions) that interpret the graph simplifies reverse-engineering.
  - For kernel analysis, looking at how this evaluator branches and where it queries extensions or entitlements has changed slowly.
  - XNUSandbox archeology can safely target these core paths; they rarely move in a way that breaks conceptual understanding.

- **Sandbox extensions**

  - The “tokenized capability” model is now deeply baked into macOS and iOS.
  - File/open dialogs, container binding, and many cross-process capabilities rely on extensions.
  - Understanding extension types and consumption APIs is future-proof for tooling; even if tokens change format, the concept will persist.

- **Container semantics**

  - The existence of per-app containers and group containers is now fundamental.
  - Apple is adding *more* structure here (Sonoma cross-app prompts) rather than removing it.
  - Observing and mapping container layouts, metadata plists, and containermanagerd interactions will remain relevant for both security and forensics work.

### 4.2 Version-sensitive surfaces to probe empirically

Other parts of the sandbox ecosystem are **high-churn** and should be treated as empirically probed surfaces on each OS release:

- **Concrete sandbox profiles (allow/deny rules)**

  - Apple frequently adjusts system profiles:
    - Tightening Safari/webcontent sandboxes.
    - Updating profiles for system daemons in response to new features or bug reports.
  - Any assumptions about “sandbox X allows Y” should be validated per OS release by:
    - Diffing `.sb` files or compiled profiles.
    - Running targeted probes from within sandboxed processes.

- **Temporary exception entitlements**

  - These are explicitly transitional.
  - Some have already been effectively deprecated or made no-ops.
  - Security research should not assume they continue to grant the same privileges; they may be ignored or blocked by notarization rules.

- **TCC-protected areas and behavior**

  - The set of TCC services and the enforcement points can change:
    - New categories (e.g. container access, new sensor types).
    - Changed semantics of existing categories (e.g. what “Full Disk Access” covers).
  - Tools and probes should:
    - Query TCC DB schemas per OS.
    - Test real behavior (e.g. can unsandboxed app read path X without a prompt?).

- **containermanagerd behavior**

  - Apple is actively changing how containers are associated with apps and how cross-app access works.
  - Future versions may:
    - Encrypt container paths transparently.
    - Introduce new metadata fields or structural changes.
  - Probes should track:
    - Container creation/update lifecycles.
    - Responses to cross-app access attempts (prompts, errors, logs).

- **Launch Services, PowerBox, and other “glue” services**

  - Several recent sandbox escapes have targeted logic flaws in:
    - Launch Services (`open`/`LSOpen*` behavior).
    - PowerBox (file dialogs and the associated extension issuance).
    - Other system services that mediate between sandboxed and unsandboxed contexts.
  - Apple tends to patch these in point releases, so:
    - They are good candidates for **regression testing** via probes.
    - Probing should be automated per OS version and updated when Apple modifies the relevant daemons or APIs.

### 4.3 How to use this for XNUSandbox / probe design

Given this landscape:

- Use **MACF hooks and evaluator logic** as your “ground truth” for how Seatbelt actually works in the kernel.
- Use **profile diffing** anchored on Blazakis 2011 and later SBPL dumps to:
  - Understand how Apple has hardened or relaxed policies over time.
  - Identify potential regressions or forgotten deny rules.
- Use **entitlement behavior** from 2019 and forward to design probes that:
  - Exercise “typical” app patterns (e.g. MAS productivity app vs unsandboxed developer tool).
  - Reconstruct practical power of different entitlement sets.
- Treat **TCC and hardened runtime** as a second layer:
  - When a probe fails, determine whether sandbox or TCC blocked it.
  - Design probes that isolate these factors (e.g. unsandboxed tool with minimal entitlements vs fully sandboxed MAS-style app).
- For **high-churn areas** (temporary exceptions, container access, Launch Services, PowerBox):
  - Maintain a versioned test suite.
  - On each OS major/minor update, rerun probes to detect changes and feed them back into your capabilities catalog.

In short: the **core Seatbelt machinery** from 2011 remains a reliable substrate for research and tooling. The interesting, fragile, and exploitable behavior tends to live in the **policy edges and integration layers**—entitlements, containers, TCC, and system daemons bridging between sandboxed and unsandboxed worlds. Those are where empirical probing and continuous tracking pay off most for modern macOS security work.
