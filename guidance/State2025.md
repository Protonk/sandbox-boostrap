# State of the macOS sandbox, ~2025

This document summarizes how Apple’s macOS “Seatbelt” sandbox behaves in practice around 2024–2025. It assumes familiarity with Seatbelt as a TrustedBSD MAC policy module, SBPL/profile semantics, and the binary profile format. The focus here is “what the world actually looks like now”: who is sandboxed, what other systems sit around Seatbelt, and which parts of the stack are stable versus volatile.

The summary is anchored in three kinds of evidence:

* Internal architecture and historical reverse engineering of Seatbelt and SBPL [BLAZAKIS2011] [ROWESANDBOXING] [APPLESANDBOXGUIDE].
* Empirical measurement of sandbox and entitlement usage in real apps [STATEOFSANDBOX2019].
* Modern accounts of the secinit/containermanagerd pipeline, containers, and current macOS behavior [WORMSLOOK2024] [HACKTRICKSSANDBOX].

---

## 1. Platform and version scope

This snapshot is primarily about macOS 13–14 on Apple Silicon, with older releases used as historical baselines rather than primary targets. The core architecture described in 10.6–10.7—Sandbox.kext as a TrustedBSD MACF module, SBPL compiled by libsandbox, and a profile evaluation graph driven by operation IDs—still exists and still shapes how decisions are made [BLAZAKIS2011] [ROWESANDBOXING].

What has changed since those early versions is not the existence of Seatbelt but its surroundings:

* Code signing and hardened runtime are now mandatory in practice for most distributed software.
* TCC (Transparency, Consent, and Control) wraps sensitive resources like camera, mic, contacts, and screen recording.
* A dedicated container-management service (containermanagerd) owns creation and bookkeeping of per-app containers on macOS, closer in spirit to iOS than 10.6-era macOS [WORMSLOOK2024].

When this document talks about “modern macOS” or “today,” it means this family of releases, not 10.9 or 10.11-style systems. Older behavior remains relevant mainly for understanding legacy ACLs, profiles, and past bypasses.

---

## 2. Who is actually sandboxed

### 2.1 App Store vs outside the store

The clearest dividing line is still distribution channel:

* **Mac App Store (MAS).** Since Apple’s 2012 rule change, MAS apps are expected to enable the App Sandbox entitlement unless they fit tightly controlled exceptions. Empirical work around Mojave/Catalina found that over 90% of MAS apps in the studied dataset were sandboxed, and once an app became sandboxed it almost always stayed that way in subsequent versions [STATEOFSANDBOX2019]. The modern ecosystem has only reinforced this pattern.
* **Outside the store (direct / third-party catalogues).** For third-party distribution sites, sandboxing has historically been optional and rare. The same empirical study found that only a small minority of MacUpdate apps were sandboxed, with most tools shipping unsandboxed binaries that rely entirely on code signing, TCC prompts, and user-granted “Full Disk Access” [STATEOFSANDBOX2019].

In 2025 this gap essentially persists: if you install from MAS, you should assume Seatbelt is in play; if you install from a vendor disk image or Homebrew, you should generally assume it is not.

### 2.2 System services and helpers

Apple ships a large number of system services and helper binaries with custom profiles, many of them using private entitlements and tightly tailored SBPL templates [BLAZAKIS2011] [APPLESANDBOXGUIDE]. Patterns include:

* GUI apps running under app sandbox profiles with entitlements similar to third-party MAS apps.
* Privileged daemons (e.g., update agents, system management) that may be unsandboxed, or sandboxed only partially, but whose behavior is constrained by SIP (System Integrity Protection) and platform profiles [APPLESANDBOXGUIDE].
* Small, single-purpose helpers (e.g., codecs, thumbnail generators) that run under very tight, purpose-specific profiles.

These system profiles are not public, but reverse engineering and logging show a wide variety of custom rules and private extensions that go beyond what third-party developers can request [BLAZAKIS2011] [SANDBLASTER2016].

### 2.3 macOS vs iOS at a glance

Conceptually, iOS and macOS now share a container-centric, entitlement-driven sandbox model, but they differ in defaults and strictness:

* On iOS, almost everything is sandboxed and runs in a container; the platform is designed around that assumption.
* On macOS, sandboxed containers are common for MAS apps and Apple’s own apps, but much ordinary desktop software still runs unsandboxed, interacting with TCC and SIP instead.

From a “what is Seatbelt actually doing?” standpoint, macOS is thus a mixed ecosystem, with Seatbelt having very strong influence in some domains (MAS productivity apps, system services) and almost none in others (traditional developer tools, backup software, virtualization tools).

---

## 3. How sandboxing is wired up today

### 3.1 Code signing, Gatekeeper, and hardened runtime

Modern macOS treats code signatures and hardened runtime flags as the entry gate for everything else:

* Binaries are signed and often notarized; Gatekeeper enforces that on first execution.
* Hardened runtime imposes constraints on how the process can behave (e.g., JIT usage, dynamic libraries, debugging) unless special entitlements are present [APPLESANDBOXGUIDE].
* Entitlements live in the signed code signature blob. The presence of `com.apple.security.app-sandbox` is the key signal that triggers automatic sandboxing by the OS.

This means the “shape” of the sandbox is partially fixed at signing time; even if the SBPL profile can be adjusted by Apple’s templates, an unsigned entitlement cannot be added later by the process itself.

### 3.2 secinit and early process setup

The **secinit** subsystem (libsystem_secinit.dylib) runs very early in process startup [ROWESANDBOXING]:

* It inspects the code signature, reads entitlements, and decides whether the process must be sandboxed.
* It prepares data structures that identify the base profile template and parameters for profile compilation.
* Historically, parsing bugs in this stage (such as mis-handling of UTF-8 BOMs) led to cases where apps that should have been sandboxed ran unsandboxed. These were serious regressions and have since been fixed, but they illustrate how crucial this step is [STATEOFSANDBOX2019].

From a 2025 perspective, secinit is a stable conceptual choke point: if you want to know whether a process will be sandboxed, start here.

### 3.3 containermanagerd and containers

The biggest visible addition compared to the 10.6–10.7 era is **containermanagerd**, the user-space service that manages app containers on macOS [WORMSLOOK2024]:

* For sandboxed apps, it creates and maintains a per-app container under `~/Library/Containers/<AppID>` on first launch, writing metadata plists that record the app’s identity and associations.
* It cooperates with Seatbelt and higher-level APIs to issue and track sandbox extensions (tokens that grant scoped access outside the container, such as PowerBox-mediated file selections).
* It ensures the container structure and metadata stay coherent across reinstallations, updates, and user account changes.

iOS has long used container directories created at install time; macOS historically lagged behind. By 2024, the macOS behavior is much closer to the iOS model, just with looser defaults for unsandboxed apps [WORMSLOOK2024].

### 3.4 Profile selection and compilation

Profile handling is still rooted in the same SBPL/TinyScheme architecture documented in early reverse-engineering work [BLAZAKIS2011] [ROWESANDBOXING]:

* A small set of base profiles (for app sandbox, various system roles, etc.) is stored in the OS.
* At launch, libsandbox combines a base profile template with the app’s entitlements to produce a concrete policy. This compilation step resolves `allow/deny` rules, filters, and parameterized expansions.
* Compiled profiles are cached and attached to the process as part of its credential label state so that kernel enforcement can be fast.

Third-party developers never see raw SBPL, but the semantics of the resulting policies still follow the SBPL model: a decision graph over operation IDs (e.g., `file-read-data`, `network-outbound`) plus filters over paths, sockets, or other attributes [BLAZAKIS2011] [APPLESANDBOXGUIDE].

### 3.5 Kernel enforcement and sandbox extensions

In the kernel, Seatbelt remains a MACF module that:

* Registers a set of hooks (now on the order of hundreds of operations) with MACF; these hooks are invoked whenever sensitive operations occur (file I/O, socket I/O, process control, etc.) [BLAZAKIS2011].
* Evaluates the attached profile against operation arguments, returning allow/deny/defer decisions.
* Integrates with sandbox extensions: sealed tokens that encode limited access rights for specific paths, file descriptors, or services. Extensions are typically minted in user space (e.g., by PowerBox or containermanagerd) and validated in the kernel [APPLESANDBOXGUIDE] [WORMSLOOK2024].

Structurally, this is almost unchanged from the early documentation: the set of hooks has grown, and internal names have shifted, but the overall model is stable.

---

## 4. What sandboxed apps can actually do

### 4.1 MAS productivity apps

A “typical” modern MAS productivity app (editor, note-taking tool, small IDE) usually runs with:

* A container for its own documents and support files.
* PowerBox-mediated access to user-selected files and directories outside the container.
* Outbound network access by default, unless explicitly restricted.
* Limited or no direct access to system configuration, other apps’ windows, or automation targets, unless it declares the relevant entitlements.

Empirical entitlement surveys show that such apps rarely request powerful device or automation entitlements: file access is mediated primarily through the container plus document pickers [STATEOFSANDBOX2019].

### 4.2 Apps with richer device and system access

Apps that record audio/video, manage photos, or control hardware may request a bundle of extra entitlements:

* Camera and microphone entitlements, often together, to support recording [STATEOFSANDBOX2019].
* Media library or Photos access entitlements.
* Network server entitlements if they need to listen on ports (e.g., collaboration tools, development proxies).
* Printing, Bluetooth, or USB accessory entitlements in specific niches.

These entitlements unlock capabilities, but use is still gated by TCC prompts at runtime (see Section 5.1). In practice, this means that even within the sandbox, an app cannot silently start using the microphone or camera without first passing through TCC’s consent model.

### 4.3 Unsandboxed but hardened tools

Many developer tools, backup utilities, and system management tools still run unsandboxed:

* They rely on code signing, hardened runtime, and TCC (plus sometimes SIP exceptions) for protection boundaries.
* Users frequently grant them “Full Disk Access” or Accessibility permissions to allow deep system integration.
* From Seatbelt’s perspective, these processes are simply not in a sandbox; the relevant MACF hooks never consult an app sandbox profile.

For this class of software, understanding macOS security is more about TCC tables, SIP restrictions, and entitlement-driven hardened runtime behavior than about SBPL rules.

---

## 5. Security layers around Seatbelt

### 5.1 TCC (Transparency, Consent, and Control)

TCC is a database-driven access control system that sits alongside Seatbelt [APPLESANDBOXGUIDE]:

* It tracks user consent for specific services (camera, microphone, contacts, calendars, screen recording, input monitoring, etc.).
* A typical access check for a sensitive resource consults both entitlements (does the app declare it may use camera?) and TCC (has the user granted permission?).
* TCC applies to both sandboxed and unsandboxed apps. Seatbelt can prevent access even if TCC allows it, but not the reverse.

Many real-world “permission denied” scenarios on macOS are TCC rather than Seatbelt decisions. Any analysis should distinguish them carefully.

### 5.2 Hardened runtime and notarization

Hardened runtime is an extension of code signing that:

* Disallows certain behaviors (e.g., unsigned code injection, arbitrary JIT, some forms of introspection) unless specific hardened runtime entitlements are present [APPLESANDBOXGUIDE].
* Is effectively required for notarized apps distributed to end users.
* Interacts with Seatbelt by controlling what the process can do to itself and other processes, even before sandbox checks are considered.

For example, a debugger or virtualization tool may need special entitlements to function under hardened runtime, independently of whether it is sandboxed.

### 5.3 SIP and platform profiles

System Integrity Protection (SIP) and platform profiles create a top-level barrier above both Seatbelt and TCC [APPLESANDBOXGUIDE]:

* They protect key system directories, processes, and kernel interfaces from modification, even by root.
* Some Apple processes run under special “platform” sandbox profiles or exemptions that allow them to bypass restrictions ordinary apps cannot.
* In combination with signed system volume layouts and read-only system partitions, they limit what even unsandboxed, privileged processes can do.

These mechanisms matter because they define what “unsandboxed” really means: it is not “no restrictions,” but “no app sandbox profile,” in a still-constrained environment.

---

## 6. Stable invariants vs high-churn surfaces

### 6.1 Structural invariants

As of 2025, several aspects of Seatbelt and its ecosystem can be treated as structural:

* Seatbelt remains a MACF module mediating operations through hooks and per-process profile labels [BLAZAKIS2011].
* SBPL-style policy graphs compiled by libsandbox are the underlying representation of application profiles, even though not exposed directly to third-party developers [ROWESANDBOXING].
* Entitlements, stored in the code signature, remain the main way for developers to request capabilities and for Apple to parameterize profiles [APPLESANDBOXGUIDE].
* Sandboxed apps on macOS receive per-app containers managed by containermanagerd [WORMSLOOK2024].
* TCC and hardened runtime are now permanent fixtures in the macOS security landscape; any realistic threat model must include them.

For tool and probe design, these invariants can be assumed unless Apple signals a major architectural change.

### 6.2 High-churn surfaces

Other aspects are volatile and must be treated as empirical:

* The exact SBPL rules for specific system services and Apple apps. These change across OS releases and patches [SANDBLASTER2016] [HACKTRICKSSANDBOX].
* The set of available entitlements, especially temporary exceptions and private/internal entitlements [STATEOFSANDBOX2019].
* TCC service categories, defaults, and UI behavior (e.g., which prompts are shown, when “One more time” prompts appear).
* Notarization and app review policies, including what combinations of entitlements and capabilities Apple is willing to approve.
* Container layout details and metadata conventions, which have evolved as containermanagerd has taken on more responsibilities [WORMSLOOK2024].

Any claim in these areas should be re-checked against the current OS version, preferably with direct probes and logging.

### 6.3 Implications for empirical work

For empirical mapping of the sandbox surface:

* Treat Seatbelt’s core architecture and the presence of containers and TCC as baseline facts.
* Target high-churn behaviors—entitlement combinations, system daemon policies, TCC edge cases—with probes that record results as versioned boundary objects.
* Expect that what passes or fails today may change subtly with each OS update, even though the conceptual description of the system remains the same.

---

## 7. Threat model and historical failure modes

### 7.1 Apple’s implicit threat model

Apple’s public materials and the structure of the system imply a layered threat model [APPLESANDBOXGUIDE] [ROWESANDBOXING]:

* The sandbox is meant to limit the damage a compromised or malicious app can do, not to prevent compromise in the first place.
* Entitlements and app review are intended to keep most apps within least-privilege bounds.
* TCC, hardened runtime, and SIP provide separate lines of defense that assume apps will occasionally behave badly or be taken over.

In practice, this means that “sandboxed” should be read as “coarsely constrained and easier to reason about,” not “strongly contained with no escape.”

### 7.2 Historical bugs and bypasses

The historical record shows multiple ways in which Seatbelt has been bypassed or mis-configured [BLAZAKIS2011] [SANDBLASTER2016] [STATEOFSANDBOX2019]:

* Parsing and initialization bugs (e.g., secinit mishandling of UTF-8 BOMs) that led to apps running unsandboxed when they should not have.
* Profile design flaws that allowed privilege escalation via unusual combinations of entitlements or helper tools.
* Implementation bugs in individual MACF hooks or filter paths that allowed specific classes of operations to slip past checks.

These examples are relevant not as exploit recipes but as reminders that “is this app sandboxed?” and “what can it actually do?” are empirical questions, not purely declarative ones.

### 7.3 Working assumptions for analysis

Reasonable working assumptions include:

* Never infer capabilities solely from the presence of `com.apple.security.app-sandbox` or a particular entitlement; verify with real operations and logs.
* Treat private and temporary exception entitlements as red flags that require closer scrutiny [STATEOFSANDBOX2019].
* Assume there are edge cases and bugs in any non-trivial policy graph; part of the point of probing is to discover them.

---

## 8. Evidence map and further reading

For orientation and evidence:

* **Architecture and implementation.** [BLAZAKIS2011], [ROWESANDBOXING], and [APPLESANDBOXGUIDE] for Seatbelt internals, SBPL, and policy mechanics.
* **Offensive/operational guidance.** [SANDBLASTER2016] and [HACKTRICKSSANDBOX] for how real attackers and red teams interact with Seatbelt and related mechanisms.
* **Empirical adoption and practice.** [STATEOFSANDBOX2019] for quantitative data on sandbox adoption and entitlement usage in MAS vs third-party ecosystems.
* **Modern pipeline and containers.** [WORMSLOOK2024] for the secinit/containermanagerd pipeline, containers, and how modern macOS organizes sandboxed apps.

This document is intended as a time-stamped snapshot of that landscape; the canonical references remain the deeper sources for architecture and detailed case studies.
