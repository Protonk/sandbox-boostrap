>SUBSTRATE_2025-frozen
# Sandbox Environment

This document collects three pieces of context that sit around the core Seatbelt semantics in the Appendix:

1. How containers and filesystem views are actually laid out for sandboxed apps.
2. Which structural aspects of the system are stable vs high-churn.
3. How adjacent security layers (TCC, hardened runtime, SIP) interact with Seatbelt.

---

## 1. Containers and the filesystem view

### 1.1 Why containers exist

The App Sandbox is primarily enforced by Seatbelt policies, but on macOS there is a second, very visible shaping of what an app can see: per-app containers.

The practical goals are:

* Give each sandboxed app a private, isolated subtree where it has broad read/write access.
* Keep most of the user’s home directory and system paths off-limits unless explicitly allowed.
* Provide a predictable place for logs, caches, and application support data.

On macOS, this is implemented with per-app directories under the user’s home directory; on iOS, containers live under system paths like `/var/mobile/Containers/...`. WORMSLOOK2024 and STATEOFSANDBOX2019 both emphasize that containers are not just a convention but a key part of how the sandboxed filesystem view is shaped.

### 1.2 macOS container layout in practice

On modern macOS versions, a sandboxed app typically has a container at:

* `~/Library/Containers/<CFBundleIdentifier>/`

Within that container, you usually see at least:

* A `Data` subtree:

  * `Data/Documents/` – the app’s private “Documents”-like directory.
  * `Data/Library/` – with subdirectories such as `Caches/`, `Preferences/`, `Application Support/`.
  * `Data/tmp/` – app-scoped temporary files.

This structure may be accompanied by additional directories or symlinks that tie the container into the user’s home environment, but the exact set and layout of those are high-churn implementation details and not treated as architectural invariants here.

From the app’s perspective:

* The sandbox profile and container layout together determine where it can read/write:

  * The container’s `Data` subtree is generally writable (subject to per-operation restrictions).
  * Access to locations outside the container (even if reachable via symlinks) is still mediated by Seatbelt rules; a symlink does not bypass sandbox restrictions.

From Seatbelt’s perspective:

* SBPL filters frequently reference container paths explicitly, e.g.:

  * `(subpath "/Users/<user>/Library/Containers/<bundle>/Data")`
  * Or equivalent patterns built via `(param "container-root")` and `string-append`.

* The container root is often derived from the bundle identifier and other metadata at profile compile time, as described in the lifecycle and entitlements sections.

### 1.3 iOS vs macOS container timing and location

WORMSLOOK2024 and STATEOFSANDBOX2019 note that:

* On iOS:

  * Containers are typically created at install time.
  * They live under system paths such as `/var/mobile/Containers/Bundle/Application/...` and `/var/mobile/Containers/Data/Application/...`.
  * The exact layout has evolved over iOS releases, but the “one container per app” idea is stable.

* On macOS:

  * Containers are usually created on first launch of a sandboxed app.
  * They live under `~/Library/Containers/` for each user account.

The important invariant is that, on both platforms, container paths are stable enough for SBPL profiles and tools like containermanagerd to reference them structurally, even if specific directory names or intermediate levels change over time.

### 1.4 Containers, user-selected files, and extensions

Not all file access happens through the container:

* When the user picks a file via an open/save panel, additional access is often granted via sandbox extensions tied to that file or directory.
* WORMSLOOK2024 shows that:

  * The app’s base profile might prevent access to arbitrary paths outside the container.
  * The system issues an extension covering the selected file or subtree, and Seatbelt uses extension filters (e.g., `(extension "...")`) to treat those paths as allowed for that process.

In other words, the container defines a default filesystem view; extensions and specific App Sandbox entitlements widen that view in controlled, traceable ways.

---

## 2. Structural invariants vs high-churn surfaces

The sources disagree on many details, but they converge on a small set of invariants that have held across macOS 10.6–14 and multiple iOS releases. STATEOFSANDBOX2019 and WORMSLOOK2024 are explicit about separating what they consider “structural” from what they expect to change, and State builds on that distinction.

### 2.1 Structural invariants

The following properties are treated as stable architecture:

* **Seatbelt as a MACF policy module**

  * Seatbelt is implemented as a TrustedBSD MAC policy inside `Sandbox.kext`.
  * It registers hooks for file, process, IPC, and other sensitive operations, and mediates them via internal policy graphs.

* **SBPL as the policy language**

  * Sandbox policies are written (or represented) as Scheme-like SBPL, compiled by a TinyScheme-derived interpreter in `libsandbox`.
  * The language uses operations, filters, and metafilters (`require-any/all/not`) that map directly onto compiled graph structures. APPLESANDBOXGUIDE, BLAZAKIS2011, ROWE_SANDBOXING

* **Compiled policy graphs**

  * SBPL is compiled into serialized graphs:

    * A header with counts and offsets.
    * An operation pointer table.
    * Arrays of filter and decision nodes.
    * Shared literal and regex tables (AppleMatch NFAs).

  * These graphs are the unit that `Sandbox.kext` actually evaluates.

* **Entitlement-driven parameterization**

  * Entitlements and metadata drive both selection of profile templates and the parameterization of SBPL via `(param "…")`.
  * Many system profiles are not usable without the correct parameter dictionaries at compile time.

* **Per-app containers**

  * Sandboxed apps get dedicated container directories whose roots (and sometimes internal layout) are tied to bundle identifiers and managed by containermanagerd-style components.
  * SBPL profiles encode container paths explicitly or derive them via parameters.

* **Policy stacking**

  * Processes see an effective policy stack of:

    * Platform profiles.
    * App or custom profiles.
    * Optional auxiliary policies.
    * Sandbox extensions.

  * Denies in higher-priority layers dominate allows in lower layers.

* **Adjacency of TCC/hardened runtime**

  * TCC (Transparency, Consent, and Control) and hardened runtime exist as separate systems that enforce user consent and code-signing constraints alongside Seatbelt. STATEOFSANDBOX2019

These are the assumptions the Appendix and Environment documents rely on; they are unlikely to change without Apple redesigning Seatbelt at a fundamental level.

### 2.2 High-churn surfaces

By contrast, the following surfaces are explicitly treated as high-variance:

* **Exact SBPL profile contents**

  * The specific allow/deny rules, path patterns, and service names in Apple’s shipped profiles change frequently across minor OS releases.
  * Even within a release, updates can introduce new operations or adjust filters.

* **Operation and filter inventories**

  * The set of operations (`file-read*`, `mach-lookup`, `sysctl-read`, etc.) and filters (path, vnode-type, global-name, entitlement-based filters) grows and shifts.
  * Numeric IDs and argument encodings are version-specific.

* **Entitlement catalogue**

  * New entitlements appear (public and private), and existing ones may change in meaning or scope.
  * Internal entitlements used by Apple’s own binaries are particularly fluid.

* **Container layout details**

  * The high-level “one container per app” idea is stable, but:

    * Subdirectory names and the presence/absence of specific symlinks can differ.
    * System updates may rearrange where auxiliary data is stored.

* **TCC service taxonomy and UX**

  * The set of TCC “services” (Camera, Microphone, Photos, etc.) and how they are presented to the user changes over time.
  * Under the hood, database formats and decision paths evolve.

* **Hardened runtime and SIP policy details**

  * The precise set of restrictions enforced by hardened runtime flags (e.g., around JIT, injection, debugging) and SIP’s protected paths/modes is fine-grained and version-specific.

For purposes of this project, the Appendix focuses on invariants and the structure they imply. Anything in the high-churn list should be treated as provisional and checked empirically (via tools and probes) rather than assumed from a static description.

---

## 3. Adjacent security controls: TCC, hardened runtime, SIP

Seatbelt is only one layer of the macOS security model. STATEOFSANDBOX2019 and related work make it clear that, for many real-world questions (“why did this access fail?”), you must also consider:

* TCC (Transparency, Consent, and Control).
* The hardened runtime and code-signing model.
* System Integrity Protection (SIP) and platform binaries.

This section gives short structural summaries of each and how they interact with Seatbelt.

### 3.1 TCC (Transparency, Consent, and Control)

TCC is a user-consent system that governs access to certain data and devices, such as:

* Camera, microphone, screen recording.
* Contacts, calendars, reminders, photos.
* Some file system locations (Desktop, Documents) and automation targets.

Key structural points:

* **Service-centric model**

  * Each protected capability is a TCC “service” with its own authorization state per app.
  * Approvals are recorded in per-user (and sometimes system) databases.

* **Entitlements and usage strings**

  * Apps must declare certain entitlements and `NS*UsageDescription` strings to be eligible for access.
  * The UI the user sees draws on those strings.

* **Enforcement path**

  * For a TCC-governed operation, the system:

    * Checks whether the app has the relevant entitlement and usage string.
    * Consults the TCC database for a recorded decision.
    * Prompts the user if no decision exists, and records the result.

Relation to Seatbelt:

* TCC is effectively an additional gate on top of the sandbox:

  * Even if the sandbox profile would allow an operation (e.g., reading a file), TCC can block it until the user consents.
  * Conversely, TCC cannot grant access beyond what the sandbox and OS policies allow; it only withholds permitted capabilities until approved.

For analysis, it is often useful to separate:

* “Denied by Seatbelt” (EPERM with no TCC prompt, matching sandbox filters).
* “Denied by TCC” (prompt appears or logs show TCC denial) even though sandbox rules would allow.

### 3.2 Hardened runtime and code signing

The hardened runtime is an extension of macOS code signing that enforces additional constraints on how a process can behave at runtime. STATEOFSANDBOX2019 and Apple’s documentation describe it as:

* A set of flags in the code signature that:

  * Require all code to be signed (no unsigned memory pages in key regions).
  * Restrict runtime modification of code (e.g., limit or forbid certain forms of JIT, injection, or debugging).
  * Gate the use of sensitive entitlements.

Structurally:

* Hardened runtime decisions happen very early, alongside entitlements and `secinit`.
* Certain sensitive entitlements (like those for debugging, JIT, or specific hardware access) are only permitted for hardened binaries with additional conditions.

Relation to Seatbelt:

* Hardened runtime is orthogonal to the sandbox’s allow/deny graph:

  * It does not replace operations/filters; it constrains the process’s execution environment.
  * Some entitlements that influence sandbox profiles are only valid under hardened runtime, tying the two together indirectly.

For tooling and capability catalogs:

* It is often sufficient to record whether a binary uses hardened runtime and which entitlements depend on it, without modeling every detailed restriction.

### 3.3 System Integrity Protection (SIP) and platform binaries

System Integrity Protection (SIP) is a kernel-enforced mechanism that:

* Protects certain filesystem locations (e.g., `/System`, parts of `/usr`, some kernel extensions).
* Restricts what even root can do (e.g., disallowing unauthorized injection into protected processes).
* Interacts with how platform binaries are signed and allowed to perform sensitive operations.

Key structural points:

* **Protected paths**

  * Writes (and sometimes reads) to specific directories are blocked unless the process has the right platform entitlements and flags.
  * This operates below or alongside Seatbelt: even an unsandboxed process may be prevented from modifying SIP-protected paths.

* **Platform binary concept**

  * Some Apple binaries are marked as “platform” and enjoy privileges not available to third-party apps, even if they are sandboxed.
  * STATEOFSANDBOX2019 and WORMSLOOK2024 point out that platform status often correlates with internal entitlements and special sandbox treatment.

Relation to Seatbelt:

* For many system processes, Seatbelt and SIP both apply:

  * Seatbelt defines what the process can do in terms of named operations and filters.
  * SIP adds additional “no, even if Seatbelt would say yes” constraints on protected paths and operations.

When diagnosing behavior, it is therefore possible to see:

* A Seatbelt allow + SIP deny (e.g., root process sandboxed but blocked from modifying `/System`).
* A SIP allow + Seatbelt deny (e.g., non-platform process allowed by SIP but denied by its sandbox profile).

---

### 3.4 Putting the layers together

For any given operation by a sandboxed app, the effective pipeline often looks like:

1. **Code signature + entitlements + hardened runtime flags**

   * Decide whether the app is eligible for certain capabilities at all.
   * Select and parameterize the sandbox profile (Appendix lifecycle and entitlements).

2. **Seatbelt (sandbox) evaluation**

   * Apply platform and app profiles plus extensions.
   * Produce an allow/deny decision based on operations, filters, and policy graphs.

3. **TCC checks (if service-relevant)**

   * Require user consent before granting access to protected data or devices.

4. **SIP and platform checks**

   * Enforce additional system-level protections for certain paths and operations, even for root or platform binaries.

For the purposes of this project, the Appendix focuses on step 2 (Seatbelt’s structure and behavior), while this Environment document sketches enough of steps 1, 3, and 4 to keep interpretations grounded and to reduce the temptation to fill gaps from vague or outdated mental models.
