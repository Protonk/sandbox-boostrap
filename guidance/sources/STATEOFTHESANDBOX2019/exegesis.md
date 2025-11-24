1. STATEOFTHESANDBOX2019

This paper empirically studies how Apple’s macOS App Sandbox is actually used in practice, and how well its intended restrictions are reflected in real-world apps. It has two main contributions: (1) a technical but high-level description of the App Sandbox mechanism and lifecycle (configuration via entitlements, initialization via the dynamic linker and libsandbox, and enforcement in the Sandbox kernel extension), and (2) a large-scale measurement of sandbox adoption and entitlement usage across 8366 free Mac App Store (MAS) apps (≈25% of all MAS apps) and 4672 apps from the third-party store MacUpdate (MU), including per-category entitlement patterns, privilege separation through XPC helpers, and a concrete sandbox-bypass bug where apps with sandbox entitlements sometimes ran unsandboxed.

---

2. Architecture pipeline (as far as this paper describes)

The paper treats the App Sandbox as a lifecycle that starts with static configuration, continues with initialization at process start, and ends with runtime enforcement on each protected operation.

On macOS, all processes conceptually start unsandboxed. Early during startup, the dynamic linker (dyld) loads libSystem and, as part of that, libsystem_secinit. This initialization stack inspects the process’s embedded entitlements; if the key `com.apple.security.app-sandbox` is present and enabled, libsandbox is invoked to compile the app’s entitlements into a concrete sandbox profile. This compilation happens in userland and the resulting profile is cached so subsequent launches can skip recompilation. Once a compiled profile is available, dyld performs a system call to initialize the sandbox for the process, before control is handed to the app’s `main()` or other third-party code.

At runtime, when an app requests a protected operation—such as file, network, or IPC access—the kernel consults the Sandbox kernel extension. The extension uses the compiled profile installed during initialization to decide whether the operation is allowed or denied, and returns either the resource or an error code to the app. The sandbox is therefore a per-process policy, enforced by a kernel module but configured via user-space entitlements and libsandbox.

The paper contrasts this with iOS only briefly: on iOS the sandbox is kernel-enforced to a degree that processes without a container are terminated, whereas on macOS sandbox initialization is delegated to the dynamic linker within the app’s own process. The authors explicitly note that if sandbox initialization fails, or if app code can run before initialization completes, the App Sandbox protections for that process are effectively lost.

---

3. Language and policy model (as seen here)

The paper focuses on entitlements as the primary, supported policy interface for third-party developers, rather than on low-level SBPL profiles. Entitlements are represented as key–value pairs embedded into the app’s executable as a property list and protected by the code signature. Each entitlement key denotes a capability (e.g., network client, camera, microphone, file access modes, container access), and the corresponding value configures it (often just a boolean).

To satisfy the MAS requirement, an app must enable `com.apple.security.app-sandbox`. This entitlement flips the process into sandboxed mode and, by default, heavily constrains access: without additional entitlements, the app cannot freely access user files, camera, microphone, or network. Developers then selectively re-enable needed capabilities by adding further entitlements (around 50 sandbox-related ones are documented), such as network client/server entitlements, user-selected file access, specific folder access (Downloads, Music, Pictures, etc.), and device entitlements (camera, microphone, Bluetooth). These entitlements are the only official and supported way to configure the sandbox on macOS.

Internally, libsandbox translates entitlements into a sandbox profile that the kernel module can interpret. The paper does not reconstruct the concrete SBPL rules generated from each entitlement, but it makes the mapping clear at a conceptual level: entitlements define what high-level resources the app may access, and libsandbox converts those into low-level checks enforced by the Sandbox kernel extension. Containers enter this picture as the default file-system scope: for sandboxed apps, the effective “home” is inside `~/Library/Containers/<bundleId>/Data`, and many file-access entitlements are about carefully punching holes out of that container—for example, allowing user-selected files outside it, or specific folders like Downloads or Music.

The authors also discuss two special classes of policy objects. Temporary exception entitlements are high-privilege allowances (e.g., AppleEvents scripting) marked as transitional; they exist to cover functionality that cannot yet be expressed cleanly in the standard entitlement set, and are intended to be phased out. Private entitlements are undocumented and intended only for Apple’s own apps; in the observed dataset only Apple apps used them.

---

4. Empirical findings and enforcement mechanics in practice

4.1 Scope, platforms, and methodology

The empirical analysis covers macOS apps; iOS is considered only in the conceptual background. The authors crawl:

* 8366 free MAS apps (15 832 versions total), representing about 25% of all MAS apps, by repeatedly scanning the store between November 2017 and September 2018 and downloading all free apps visible in the German storefront.
* 4672 macOS apps from MacUpdate (MU), obtained in a single crawl (from 37 238 candidates; many URLs were invalid, files corrupted, or apps too old to run).

They statically extract entitlements and Info.plist metadata from main binaries and XPC helpers, and dynamically determine whether an app is sandboxed by launching it, waiting ~30 seconds, and then asking the OS via a private API (`sandbox_check`) whether the process is currently sandboxed. An app counts as sandboxed only if both the entitlement is present and the runtime check reports an active sandbox.

4.2 Ecosystem adoption and coverage

The main adoption numbers are:

* MAS: 7825 of 8366 apps (93.53%) are sandboxed. 535 (6.39%) are not sandboxed; almost all of these are “legacy” apps first released before sandboxing became mandatory for MAS submissions in 2012. Only nine apps in the MAS dataset have a mixed history (both sandboxed and unsandboxed versions); 7818 apps had all observed versions sandboxed, and 539 had no sandboxed version at all.
* MU: Only 511 of 4672 apps (10.94%) are sandboxed; 4150 apps (88.83%) run unsandboxed.

Among 173 apps that appear in both datasets (same bundle identifier), 53 are sandboxed in both places, 94 are sandboxed only on MAS, and 26 are unsandboxed in both. This highlights that the same logical app often ships in a sandboxed variant through the MAS and an unsandboxed variant through third-party distribution.

The paper interprets these findings as strong evidence that MAS requirements drive sandbox adoption: once Apple enforces the sandbox for store submissions, most apps comply, while outside that regime developers rarely opt in voluntarily. Legacy unsandboxed MAS apps remain in circulation and can be updated without being forced into the sandbox.

4.3 Entitlement usage and capability shapes

For entitlement analysis, the authors restrict to the latest version of each app and to apps that are actually sandboxed at runtime. They focus on the entitlements exposed in Xcode’s “App Sandbox” UI and group read-only vs read/write file entitlements together.

Global distribution (MAS + MU combined, sandboxed apps):

* Network client entitlement (“Client”): 5493 apps (65.88%).
* User-selected files (Read/Write): 3787 apps (45.42%).
* Printing: 1165 apps (13.97%).
* Network server entitlement (“Server”): 1082 apps (12.98%).
* Security-scoped bookmarks: 882 apps (10.58%).
* Application groups: 676 apps (8.11%).
* User-selected files (read-only): 634 apps (7.60%).
* Downloads folder (read/write): 458 apps (5.49%).
* Microphone: 427 apps (5.12%).

From co-occurrence analysis, the paper reports several strong pairing patterns:

* Camera and microphone entitlements often appear together; nearly half the apps with one also have the other.
* Bluetooth and USB entitlements often co-occur.
* Calendar and Contacts entitlements often co-occur.
* Movies folder entitlement tends to co-occur with Pictures folder entitlement.

Per-category patterns (MAS categories, sandboxed apps) align with intuitive expectations:

* Weather: nearly 60% of apps have the Location entitlement.
* Social Networking: about 25% of apps have camera, microphone, and Downloads-folder entitlements.
* Music, Photography, Video: >20% of apps in each category have access to Music, Pictures, or Movies folders respectively; ≈22% of Video apps also have microphone access.
* Games: use comparatively few entitlements; they are the least privileged category.

Version history analysis shows that entitlements tend to accumulate: between successive versions of MAS apps, more than twice as many entitlements are added as removed. This indicates a general trend towards increasing privilege over time, even under sandboxing.

Temporary exception entitlements appear infrequently; the most common are scripting/automation exceptions used by about 3.2% of apps. Private entitlements are observed only in Apple’s own apps. The authors attempt to detect anomalous entitlement profiles via clustering, but conclude that the dataset is too heterogeneous; a manual inspection of high-privilege, unique entitlement combinations also does not reveal obviously over-privileged apps. They therefore conclude that, once constrained to configure via entitlements, developers generally choose capabilities sensibly.

4.4 Privilege separation and helpers

The paper examines privilege separation through XPC helpers, which are separate binaries that can each have their own entitlements and sandbox. For MAS apps, the App Sandbox is disabled by default for XPC services in Xcode, but Apple’s documentation encourages developers to sandbox helpers individually with minimal needed privileges.

The authors compare helper entitlements to those of the main app and classify helpers as having more, fewer, equal, or mixed privileges. For MAS apps with XPC helpers, most helpers have fewer entitlements than the parent app: they commonly lack User-selected files, network client, and printing entitlements even when the main app has them. For MU apps, by contrast, most helpers have more privileges than the main app, and many helpers are entirely unsandboxed.

They note that the effective capability surface of an app should include the union of entitlements across all helpers reachable via IPC. Recomputing their entitlement analyses on this “overall privilege” basis does not materially change the earlier patterns: category- and co-occurrence-level observations remain similar.

4.5 Sandbox-bypass and enforcement anomalies

While scanning apps, the authors discover a critical anomaly: a small number of apps (six MAS apps and eleven MU apps in the dataset) contain the sandbox entitlement but are not sandboxed at runtime, according to the dynamic `sandbox_check` test. They interpret this as a sandbox-bypass situation where sandbox initialization fails or is skipped, leaving the process effectively unsandboxed despite its static configuration. The details of the vulnerability and its root cause are discussed later in the paper; the authors note that it has been fixed by Apple, “improving the security of millions of systems.”

---

5. Patterns, idioms, and implications for a capability catalog

5.1 Recurring patterns in sandbox and entitlement use

From the paper’s findings, several practical idioms in real-world sandbox use emerge:

* **Store-driven adoption.** Sandbox adoption is near-universal for MAS apps created or significantly updated after sandboxing became mandatory, but very low for third-party distribution (MU). Legacy unsandboxed MAS apps continue to exist and be updated outside the sandbox.
* **Baseline capabilities for sandboxed apps.** Among sandboxed apps, network client access and user-selected file access are effectively baseline: roughly two-thirds of apps use the network client entitlement, and nearly half use read/write user-selected files. Printing and network server entitlements also appear in a non-trivial fraction of apps (~13%).
* **Category-shaped privilege profiles.** Entitlement profiles follow app genres: weather apps commonly request locations, social apps camera + microphone + downloads, and media apps request access to corresponding media folders. Games tend to be minimally privileged.
* **Privilege growth over time.** Entitlement sets grow across versions (more added than removed), even under the MAS sandbox regime.
* **Helpers used for least-privilege (MAS) vs privilege escalation (MU).** MAS apps often use XPC helpers that are more constrained than the main app, while MU apps frequently have helpers with higher privileges or no sandbox at all.

The sandbox-bypass bug shows that the enforcement pipeline (entitlements → libsandbox → dyld init → kernel profile) can fail, leaving an app fully unsandboxed despite static configuration saying otherwise. This underscores the importance of treating runtime status, not just entitlements, as authoritative when reasoning about capabilities.

5.2 Implications for a macOS capability catalog

For someone building a capability catalog of macOS sandbox operations and enforcement behavior, this paper suggests several concrete structuring choices:

* **Baseline vs elevated capabilities.**

  * Treat network client access and user-selected file access as baseline capabilities for most sandboxed desktop apps: they are common and often necessary for typical functionality.
  * Printing and network server capabilities sit in a middle tier: not universal but widely present and relatively routine.
  * Entitlements for direct folder access (Downloads, Music, Pictures, Movies), device access (microphone, camera, Bluetooth), and contacts/location/calendar represent more sensitive, less commonly granted capabilities that should be highlighted as elevated in the catalog.

* **Category-aware expectations.**

  * For each entitlement, the catalog can capture “typical” categories where it appears (e.g., `Location` heavily associated with Weather; `Camera`/`Microphone` with Social and Video; media-folder access with Music/Photography/Video).
  * Deviations (e.g., a game with extensive contacts or location entitlements) would stand out in such a catalog as worth closer scrutiny.

* **Version-sensitive annotations.**

  * Given the observed drift towards increasing privileges, catalog entries tied to entitlements and operations should allow for noting how often capabilities are introduced in later versions. This is relevant to tracking “privilege creep” over an app’s lifecycle.

* **Helper-aware capability aggregation.**

  * The catalog should explicitly model that effective process capabilities are the union of entitlements across the main binary and all associated helpers and XPC services. The MAS vs MU contrast shows that helpers can either reduce or expand the effective privilege surface, depending on ecosystem norms.

* **Runtime vs static state.**

  * Finally, the discovered sandbox-bypass bug implies that a capability catalog should distinguish between “declared” capabilities (entitlements) and “enforced” capabilities (what the sandbox actually restricts at runtime). The paper’s methodology—checking both entitlements and runtime sandbox status—provides a concrete pattern for this distinction.

Overall, the paper does not extend the low-level operation vocabulary of the sandbox, but it supplies a detailed empirical map of how entitlements, containers, and sandbox initialization interact with real apps at scale. That map can be used to prioritize which capabilities matter most in practice, which are rarely used but high-impact, and where to expect mismatches between theoretical sandbox surfaces and actual developer behavior.
