# Canon

This document lists the seven canonical macOS sandbox (“Seatbelt”) references used in this project. Together they cover architecture and implementation details, profile language and tooling, offensive/operational guidance, and empirical studies of sandbox usage and weaknesses. Later readers and agents should treat these as primary references when interpreting XNUSandbox artifacts, Codex sandbox behavior, and the project’s capability catalogs.

---

## A canon for macOS v2 capability catalog

As a group, these sources give an unusually clear, internally consistent picture of Seatbelt at the level that matters for a capability catalog: concrete operations, filters, entitlements, and the kernel/userland plumbing that decides “allow vs deny.” They converge on the same core architecture (Sandbox.kext as a TrustedBSD MAC module, libsandbox and SBPL as the policy front-end, App Sandbox/entitlements as the app-facing layer) from different angles, which helps triangulate semantics instead of relying on any one author’s guesswork. For a system that must reason over capabilities as structured objects, this shared backbone is more valuable than a broader but shallower survey.

The canon also deliberately combines three vantage points that are unusually complementary for structured security work: (1) profile authorship and language-level detail (APPLESANDBOXGUIDE, BLAZAKIS2011), (2) reverse-engineering and decompilation of real-world profiles across OS versions (SANDBLASTER2016), and (3) empirical measurement of how sandboxing is actually used and misused in the wild (STATEOFSANDBOX2019, HACKTRICKSSANDBOX). That mix grounds the catalog not just in what the sandbox is supposed to do, but in what Apple ships, how developers deploy it, and how attackers see it. This is exactly the triangulation you want if you are trying to reason about capabilities and risk rather than blindly trusting documentation.

Temporal skew toward 10.x–early 11.x macOS and contemporary iOS is a feature as well as a limitation. Most of the low-level machinery that matters for capability semantics—the SBPL primitives, operation and filter taxonomies, MAC hook structure, basic container and entitlement model—has been relatively stable across these releases, even as higher-level platform features evolved. That makes this corpus a good “stable core” on which to define and normalize capability families, while still leaving room to tack on newer, more volatile behaviors (Apple Silicon quirks, hardened runtime, entitlement review changes) as separate, explicitly versioned deltas in the catalog.

Finally, these sources are largely self-contained, technically precise, and available as durable open artifacts (papers, guides, and long-lived web posts). That is crucial for a machine-readable catalog or any other structured artifact built on them: every capability or rule in the catalog can be tied back to a small, finite set of stable texts that other agents—or humans—can re-parse, re-interpret, or re-derive from scratch when needed. In other words, this canon gives a compact, well-anchored semantic spine for Seatbelt: detailed enough to support fine-grained capability modeling, yet small and coherent enough that we can realistically encode, audit, and iteratively refine it as the project (and macOS itself) evolves.

## Reading the canon

Treat this canon as a small, structured corpus rather than seven isolated texts. One useful lens is “intended audience”: APPLESANDBOXGUIDE and ROWESANDBOXING are written for implementers and app developers; BLAZAKIS2011 and SANDBLASTER2016 address reverse engineers and internals-focused security researchers; STATEOFSANDBOX2019 and HACKTRICKSSANDBOX emphasize empirical practice and offense; WORMSLOOK2024 tries to connect architecture to everyday platform behavior. When the catalog asserts something about how Seatbelt “really” works, a skeptical reader can ask: which of these audiences does that claim rely on, and how do the other audiences talk about (or conspicuously ignore) the same point?

A second lens is abstraction level. The corpus covers: (a) language and policy structure (SBPL primitives, operations, filters), (b) compilation and representation (binary profiles, `sandbox-simplify`, libsandbox), (c) enforcement (Sandbox.kext, MAC hooks, syscall mediation), and (d) ecosystem usage (entitlement sets, containers, app categories, common deployment patterns). APPLESANDBOXGUIDE and BLAZAKIS2011 inhabit the language and enforcement layers; SANDBLASTER2016 binds language to compiled artifacts; WORMSLOOK2024 and ROWESANDBOXING bridge enforcement to platform stories; STATEOFSANDBOX2019 and HACKTRICKSSANDBOX live at the ecosystem layer. When you see a capability in the catalog, it is worth asking which of these layers is directly supported by text and which require inference across layers; that gives you a principled way to distinguish “well-grounded semantics” from “plausible extrapolation.”

A third axis is time and platform evolution. The early sources (APPLESANDBOXGUIDE, BLAZAKIS2011) give a detailed snapshot of language and architecture in the 10.x era; SANDBLASTER2016 traces profile evolution across iOS versions; STATEOFSANDBOX2019 captures macOS App Sandbox usage at a particular moment; WORMSLOOK2024 and ROWESANDBOXING provide more recent but higher-level overviews. A careful reader should treat these as a time series: when the catalog describes an operation, filter, or entitlement, check whether its description is anchored in early technical detail, in mid-period reverse engineering, in later ecosystem observation, or in some combination. Where all eras agree you can treat stability as a working assumption; where only the early or only the late sources speak, you should read the catalog’s claims as more contingent on OS version and platform context.

Threat and trust models offer another cross-cutting lens. Some texts assume cooperative developers trying to sandbox themselves correctly (APPLESANDBOXGUIDE, ROWESANDBOXING), others assume analysts or adversaries probing for weaknesses (BLAZAKIS2011, HACKTRICKSSANDBOX), and still others study aggregate behavior and policy effectiveness at the ecosystem level (STATEOFSANDBOX2019). WORMSLOOK2024 sits between architectural description and security evaluation. When a catalog entry encodes an operation or entitlement, you can ask: is this framed primarily as a safety boundary, as an attack surface, or as a fact about how apps are actually configured in practice? Noting which threat model underwrites a given description will help you see both the strength of the supporting evidence and its likely blind spots.

Finally, use the corpus to calibrate your skepticism about the catalog itself. For any nontrivial capability, imagine tracing it through four questions: Which audiences talk about it? At which abstraction layers? In which time slices? Under which threat models? The catalog’s annotations should give you some of that mapping explicitly; where they do not, this canon is small enough that you can realistically reconstruct the mapping yourself. Read the catalog’s “facts” as claims that are strong where the corpus converges and explicitly provisional where it does not, and treat the references to these seven sources not as ornamental citations but as invitations to re-run the reasoning from first principles whenever a claim looks surprisingly strong, surprisingly weak, or surprisingly silent.

## Scope and blind spots

Taken together, these sources give a strong but partial view of the Apple sandbox: they emphasize architectural overviews, reverse-engineering of profiles and internals, and high-level empirical measurements of macOS App Sandbox adoption. They are heavily weighted toward “Seatbelt as a security mechanism” in the classic desktop/app sense, and toward the SBPL/profile machinery as it appears in 10.x–early 11.x era systems. They say almost nothing about Codex- or LLM-specific runtimes, but that is by design for this project and not a gap we expect the canon itself to fill.

In terms of time and platform coverage, the corpus is anchored in 2010–2019 macOS and iOS with one more recent synthetic overview. That means later evolutions—Apple Silicon-specific behavior, tighter ties with TCC, hardened runtime, notarization, SIP interactions, and per-release quirks of macOS 12–15—are mostly inferred rather than documented. iOS is present but always as a twin of macOS Seatbelt; mobile-only phenomena (e.g., complex app groups, background modes, modern extension points) are not explored deeply.

On the “what the sandbox does” axis, the canon is strongest on the SBPL language, binary profile format, and core enforcement pipeline (libsandbox, Sandbox.kext, MACF hooks). It is weaker on higher-level system layers that shape effective sandbox behavior in practice: container / containerized filesystem layout over time, modern XPC and service management patterns, LaunchServices and login items, and the way third-party frameworks layer their own permission models on top of the sandbox. It also does not fully map the growing ecosystem of private entitlements, entitlement review practice, or real-world entitlement abuse patterns beyond what shows up in the 2019 adoption study.

On the “how it fails” axis, we have one systematic empirical study and scattered offensive notes, but not a comprehensive exploit canon. There is limited coverage of modern sandbox escapes and bypass chains, threat models involving malicious but sandboxed plugins or helper tools, or the interaction between sandboxing and newer macOS attack surfaces (e.g., kernel extensions’ slow deprecation, system extensions, virtualization frameworks). Formal verification, static analysis frameworks for profile correctness, and rigorous performance/overhead characterizations are also largely out of frame.

Finally, the corpus is skewed toward specialist and research perspectives: reverse engineers, security researchers, and power users. It underrepresents the day-to-day experience of ordinary macOS developers wrestling with entitlements and containers, and it largely ignores policy, usability, and ecosystem dynamics (how Apple’s evolving rules and review practices actually shape what gets shipped). When we encode this canon into a machine-readable catalog or use it to interpret one, we should treat it as authoritative on the existence and semantics of many operations and hooks, but explicitly uncertain about (a) post-2019 evolution, (b) real-world entitlement usage and misusage outside the studied samples, and (c) higher-level platform behaviors that sit above the core Seatbelt machinery.

## Listing by SHORTNAME

The SHORTNAME identifiers below are the canonical labels used throughout this project and in the macOS capability catalog; use them as stable handles when cross-referencing catalog entries with these sources.

### ROWESANDBOXING

**Citation**
Mark Rowe. “Sandboxing on macOS.” bdash.net blog, 2024.

**Public link**
[https://bdash.net.nz/posts/sandboxing-on-macos/](https://bdash.net.nz/posts/sandboxing-on-macos/)

**Summary**
This piece explains what the macOS sandbox is in practical terms, focusing on how it limits the impact of code execution bugs and what kinds of operations (process launching, file access, user data) are meant to be constrained. It motivates sandboxing both as an exploit-mitigation tool and as a way for third-party apps to signal seriousness about user privacy. It then walks through how Apple’s App Sandbox, entitlements, and filesystem constraints work in practice, highlighting trade-offs and common pitfalls for developers.

**Guide**

Look to ROWESANDBOXING to find a clear, practical explanation of how the macOS sandbox shows up in day-to-day application behavior, especially around file access and user data. Use it when you want a straightforward mental model of App Sandbox constraints, how entitlements and containers affect what an app can see, and what kinds of operations the system is trying to fence without going deep into SBPL or kernel internals. It is a good reference for connecting abstract “sandbox” talk to concrete effects a Mac user or developer would actually notice.

You can expect this source to contain especially good, intuition-building discussion of why sandboxing exists, what kinds of bugs and privacy problems it is meant to mitigate, and where developers commonly run into its edges. Read it with the posture that it is a grounded, opinionated field note: treat its examples and explanations as a way to calibrate your expectations about real-world behavior and developer experience, while relying on the more formal and reverse-engineering-heavy sources in the canon for exhaustive operation lists, low-level mechanisms, and strict semantics.


---

### HACKTRICKSSANDBOX

**Citation**
HackTricks contributors. “macOS Sandbox.” HackTricks, last updated 2024.

**Public link**
[https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox)

**Summary**
This document summarizes the macOS Seatbelt sandbox from an attacker/penetration-tester perspective, describing what the sandbox is, how profiles and entitlements govern allowed actions, and which system components are involved. It exists to give practitioners a quick field guide for recognizing when a process is sandboxed and what that practically restricts. It shows how to enumerate sandboxed processes, inspect containers and profiles, and outlines common misconfigurations and avenues for probing or bypassing restrictions.

**Guide**

Look to HACKTRICKSSANDBOX to find a concise, practitioner-oriented view of the macOS sandbox from an attacker and operator perspective. Use it when you want to see how to recognize that a process is sandboxed, how to inspect its container and associated files, and which basic commands and techniques people actually use in the field to poke at sandbox boundaries. It is also a useful reference for the “shape” of typical misconfigurations and weak spots as they show up in offensive playbooks.

You can expect this source to contain especially good, concrete enumeration and inspection techniques for sandboxed processes, including how to list containers, inspect entitlements, and spot obvious over-privileging or gaps. Read it with the posture that it is an applied checklist rather than a formal treatment: treat its guidance as a reality check on what security-aware users and red-teamers see as important in practice, and as a source of examples and failure modes that can help you interpret and stress-test more abstract capability descriptions from the rest of the canon.

---

### SANDBLASTER2016

**Citation**
Răzvan Deaconescu, Luke Deshotels, Mihai Bucicoiu, William Enck, Lucas Davi, and Ahmad-Reza Sadeghi. “SandBlaster: Reversing the Apple Sandbox.” arXiv preprint arXiv:1608.04303, 2016.

**Public link**
[https://arxiv.org/abs/1608.04303](https://arxiv.org/abs/1608.04303)

**Summary**
This paper presents Apple’s iOS/macOS sandbox at a high level and identifies the opacity of compiled binary sandbox profiles as a barrier to analysis. It aims to make Apple’s built-in sandbox rules auditable by security researchers instead of remaining an undocumented black box. It introduces SandBlaster, a toolchain that parses the binary profile format, reconstructs the underlying SBPL (Sandbox Profile Language), and uses it to reverse all built-in profiles for multiple iOS versions so their policies can be studied and compared.

**Guide**

Look to SANDBLASTER2016 to find a concrete, reverse-engineering-based account of how Apple’s sandbox profiles are stored, compiled, and represented across multiple iOS versions. Use it when you want to understand the binary profile format, how SBPL rules turn into low-level decision tables, and how Apple’s stock profiles actually look once decompiled back into a human-readable form. It is the main source for seeing policy evolution over time in practice: which operations and filters appear, how rules change between OS releases, and where Apple tightens or relaxes constraints.

You can expect this source to contain especially good methodology for reconstructing and comparing real-world profiles at scale, including the tooling and approach used to go from binary blobs to structured SBPL-like representations. Read it with the posture that it is your “ground truth” for what Apple actually ships, not what the language guide says is possible: treat its decompiled profiles and cross-version comparisons as the empirical backbone behind any catalog claim about built-in policies, while remembering that its view is iOS-centric and time-bounded, so later macOS-specific evolution and newer platforms may extend or diverge from the patterns it documents.

---

### APPLESANDBOXGUIDE

**Citation**
fG!. “Apple’s Sandbox Guide v1.0.” reverse.put.as, 2011.

**Public link**
[https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)

**Summary**
This guide systematizes what the Apple sandbox is by cataloging the SBPL language, the full set of operations (file, IPC, Mach, network, process, sysctl, system), filters, and modifiers, with examples of each. It was written to fill the documentation gap for people writing or reverse-engineering custom profiles, explaining why sandboxing matters and how default vs. explicit rules interact in practice. It then shows how to actually build and debug profiles with `sandbox-exec`, tracing, and `sandbox-simplify`, including practical recipes and notes about quirks and bugs in Snow Leopard’s implementation.

**Guide**

Look to APPLESANDBOXGUIDE to find a systematic catalog of the Apple sandbox profile language as it existed around the 10.6/10.7 era: SBPL syntax, operation names, filters, and modifiers, with concrete examples. Use it when you want to understand what the core operation families are (file, IPC, Mach, network, process, sysctl, system), how rules are structured, and how default vs. explicit allow/deny interacts in the policy model. It is also the right place to see how Apple’s own stock profiles were constructed conceptually, before you dive into more automated reverse-engineering work.

You can expect this source to contain especially good, worked examples of writing and debugging sandbox profiles using sandbox-exec, tracing tools, and sandbox-simplify, including small recipes and notes about known quirks in Snow Leopard’s implementation. Read it with the posture that it is a language-and-idiom guide: treat its operation and filter taxonomy as the baseline vocabulary for the catalog, and its examples as canonical patterns for how rules are intended to be composed, while mentally bracketing any version-specific details or missing post-2011 features as things that later sources and catalog annotations may refine.

---

### WORMSLOOK2024

**Citation**
Osama Alhour. “A Worm’s Look Inside: Apple’s Sandboxing security measures on macOS & iOS.” nsantoine.dev, 2024.

**Public link**
[https://nsantoine.dev/SandboxPaper.pdf](https://nsantoine.dev/SandboxPaper.pdf)

**Summary**
This paper describes Apple’s sandbox as a TrustedBSD-based kernel MAC policy (Sandbox.kext) plus userland machinery (containers, entitlements, containermanagerd, libsandbox) that together confine apps on macOS and iOS. It is motivated by understanding not just that apps are “sandboxed,” but who gets sandboxed, how containers and entitlements are wired up at process launch, and how the sandbox interacts with other subsystems like dyld and MACF. It walks through how profiles are stored and compiled, how sandbox hooks are invoked on operations, how sandbox extensions and XPC/container services punch controlled holes, and what that implies for security boundaries and potential attack surfaces.

**Guide**

Look to WORMSLOOK2024 to find a modern, narrative-style walkthrough of how Apple’s sandbox fits into the broader macOS/iOS security stack: it ties together containers, entitlements, containermanagerd, libsandbox, sandboxd, and Sandbox.kext in a single story. Use it when you want concrete details about how containers are laid out on disk on macOS vs iOS, how containers are created and registered, and how property lists and UUIDs bind bundle identifiers to specific container directories. It is also your main reference for a step-by-step account of process startup: how the dynamic linker, entitlements, and sandbox profile selection interact when a process is launched, and where in that path the kernel’s MAC hooks and sandbox checks actually fire.

You can expect this source to contain especially good “lifecycle” explanations that bridge userland and kernel: what happens from the moment an app is installed, to container creation, to first launch, to runtime interactions with the filesystem and services. Read it with the posture that its strength is in connecting components and flows that other, more formal or RE-heavy sources describe in isolation; treat it as a modern architectural snapshot and glue text, using it to cross-check your mental model of “who gets sandboxed, when, and how,” while relying on the rest of the canon for exhaustive SBPL, binary-profile, and ecosystem-level detail.

---

### BLAZAKIS2011

**Citation**
Dionysus Blazakis. “The Apple Sandbox.” Black Hat DC, 2011.

**Public link**
[https://www.ise.io/wp-content/uploads/2017/07/apple-sandbox.pdf](https://www.ise.io/wp-content/uploads/2017/07/apple-sandbox.pdf)

**Summary**
This work gives a deep architectural overview of the Apple sandbox, from the public `sandbox_init`/`sandbox-exec` interface through libsandbox’s TinyScheme-based SBPL compiler down into the TrustedBSD MAC hooks in Sandbox.kext. It was written to explain why the sandbox matters as a post-exploitation mitigation and to document an otherwise private, undocumented system that security researchers needed to reason about. It traces how human-readable policies become compact rule tables, how the kernel enforces them on syscalls via MAC hooks and a regex engine kext, and how logging/tracing infrastructure and built-in profiles fit into real-world use.

**Guide**

Look to BLAZAKIS2011 to find a deep architectural tour of the Apple sandbox from userland entry points down into kernel enforcement. Use it when you want to see how `sandbox_init`/`sandbox-exec`, libsandbox’s TinyScheme-based SBPL compiler, and the TrustedBSD MAC hooks in Sandbox.kext fit together into a single pipeline, and how human-readable rules become compact decision structures the kernel can apply on syscalls. It is also a key reference for understanding how Apple originally positioned the sandbox as a post-exploitation mitigation, and how early built-in profiles were structured conceptually.

You can expect this source to contain especially good, concrete linkage between profile language constructs and the underlying enforcement machinery, including details about MACF hook placement, the regex engine kext, and logging/tracing behavior. Read it with the posture that it is your architectural spine for the classic Seatbelt design: treat its model of data flow and control flow as the default mental map when the catalog talks about “how a rule gets enforced,” while remembering that the specific OS vintage and examples are early and may need to be supplemented with later sources for modern features and platform nuances.

---

### STATEOFSANDBOX2019

**Citation**
Maximilian Blochberger, Jakob Rieck, Christian Burkert, Tobias Mueller, and Hannes Federrath. “State of the Sandbox: Investigating macOS Application Security.” In Proceedings of the 2019 ACM Workshop on Privacy in the Electronic Society (WPES), 2019.

**Public link**
[https://svs.informatik.uni-hamburg.de/publications/2019/2019-11-Blochberger-State-of-the-Sandbox.pdf](https://svs.informatik.uni-hamburg.de/publications/2019/2019-11-Blochberger-State-of-the-Sandbox.pdf)

**Summary**
This paper first recaps the macOS App Sandbox model (containers, entitlements, initialization and enforcement path) and then positions it as a key privacy/least-privilege mechanism. Its goal is to empirically assess how widely and how well the sandbox is actually used, both in the Mac App Store (MAS) and in a third-party catalog (MacUpdate), and to uncover concrete weaknesses. It combines static and dynamic analysis of over 13,000 apps to measure sandbox adoption and entitlement use, reports that MAS apps are mostly sandboxed while third-party apps rarely are, analyzes entitlement patterns and privilege separation, and documents a critical sandbox-bypass bug that the authors responsibly disclosed.
