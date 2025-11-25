# Canon

This document lists the seven canonical macOS sandbox (“Seatbelt”) references used in this project. Together they cover architecture and implementation details, profile language and tooling, offensive/operational guidance, and empirical studies of sandbox usage and weaknesses. Later readers and agents should treat these as primary references when interpreting XNUSandbox artifacts, Codex sandbox behavior, and the project’s capability catalogs.

---

## A canon for a substrate

As a group, these sources give an unusually clear, internally consistent picture of Seatbelt at the level that matters for a capability catalog: concrete operations, filters, entitlements, and the kernel/userland plumbing that decides “allow vs deny.” They converge on the same core architecture (Sandbox.kext as a TrustedBSD MAC module, libsandbox and SBPL as the policy front-end, App Sandbox/entitlements as the app-facing layer) from different angles, which helps triangulate semantics instead of relying on any one author’s guesswork. For a system that must reason over capabilities as structured objects, this shared backbone is more valuable than a broader but shallower survey.

The canon also deliberately combines three vantage points that are unusually complementary for structured security work: (1) profile authorship and language-level detail (APPLESANDBOXGUIDE, BLAZAKIS2011), (2) reverse-engineering and decompilation of real-world profiles across OS versions (SANDBLASTER2016), and (3) empirical measurement of how sandboxing is actually used and misused in the wild (STATEOFSANDBOX2019, HACKTRICKSSANDBOX). That mix grounds the catalog not just in what the sandbox is supposed to do, but in what Apple ships, how developers deploy it, and how attackers see it. This is exactly the triangulation you want if you are trying to reason about capabilities and risk rather than blindly trusting documentation.

Temporal skew toward 10.x–early 11.x macOS and contemporary iOS is a feature as well as a limitation. Most of the low-level machinery that matters for capability semantics—the SBPL primitives, operation and filter taxonomies, MAC hook structure, basic container and entitlement model—has been relatively stable across these releases, even as higher-level platform features evolved. That makes this corpus a good “stable core” on which to define and normalize capability families, while still leaving room to tack on newer, more volatile behaviors (Apple Silicon quirks, hardened runtime, entitlement review changes) as separate, explicitly versioned deltas in the catalog.

Finally, these sources are largely self-contained, technically precise, and available as durable open artifacts (papers, guides, and long-lived web posts). That is crucial for a machine-readable catalog or any other structured artifact built on them: every capability or rule in the catalog can be tied back to a small, finite set of stable texts that other agents—or humans—can re-parse, re-interpret, or re-derive from scratch when needed. In other words, this canon gives a compact, well-anchored semantic spine for Seatbelt: detailed enough to support fine-grained capability modeling, yet small and coherent enough that we can realistically encode, audit, and iteratively refine it as the project (and macOS itself) evolves.

## A stopping point

The canon is deliberately small and fixed because its primary purpose is to define a stable substrate, not to maximize coverage. Seven documents are enough to span the main axes this project needs: internal architecture, policy language and compiler, binary profile formats, macOS/iOS policy content, and concrete system behaviour. With those axes covered, additional sources usually add detail, corroboration, or alternative framings rather than genuinely new dimensions. Fixing the canon at this size makes it practical for an agent to read across the whole substrate, hold it in working memory, and treat “what the canon says” as a well-defined object.

A stopping rule also protects the structure of the downstream work. Orientation, concept inventory, example selection, and probe design are all keyed to this specific set of documents. If the canon were allowed to drift every time a useful paper or blog post appeared, each later addition would force a retroactive re-interpretation of earlier layers: concept clusters would shift, examples would become misaligned, and cross-references would slowly lose their footing. By stopping early and intentionally, we accept that the canon is partial, in exchange for keeping the derived artifacts coherent and internally comparable over time.

The stopping rule is not a claim that everything important about the Apple sandbox is inside these seven documents. It is a claim that, for the purpose of this textbook and its probe machinery, these seven are sufficient to define the “world” that the rest of the project is accountable to. Many adjacent sources—formal analyses, vulnerability case studies, broader iOS security work—could plausibly have been included and would have enriched the substrate. They are instead treated as external evidence and inspiration. Their exclusion from the canon is not a judgement on their quality; it is a constraint on what counts as foundational for this particular construction.

This constraint is especially important for agents that are synthesizing, generalizing, or proposing new tools. When an agent reasons “according to the canon,” it should be able to trace any claim back to one or more of these seven documents and to the interpretations built on top of them. If an idea cannot be grounded that way, it may still be valuable, but it belongs to a different layer of the project: commentary, adjacent work, or future directions. The stopping rule therefore sharpens the distinction between substrate and superstructure, which is essential for debugging both the textbook and any automated probes or evaluators derived from it.

Finally, the stopping rule turns omissions into deliberate objects of study rather than accidental gaps. When the canon is fixed, “things the canon does not say” becomes a meaningful category: places where the documents are silent, inconsistent, or outdated can be identified, annotated, and explored using other sources without ever confusing those explorations with the substrate itself. For textbook-building agents, the task is then clear: learn this bounded world as thoroughly as possible, make its internal structure explicit, and treat everything else as commentary that must declare its distance from the canon rather than silently rewriting it.

## Scope and blind spots

Taken together, these sources give a strong but partial view of the Apple sandbox: they emphasize architectural overviews, reverse-engineering of profiles and internals, and high-level empirical measurements of macOS App Sandbox adoption. They are heavily weighted toward “Seatbelt as a security mechanism” in the classic desktop/app sense, and toward the SBPL/profile machinery as it appears in 10.x–early 11.x era systems. They say almost nothing about Codex- or LLM-specific runtimes, but that is by design for this project and not a gap we expect the canon itself to fill.

In terms of time and platform coverage, the corpus is anchored in 2010–2019 macOS and iOS with one more recent synthetic overview. That means later evolutions—Apple Silicon-specific behavior, tighter ties with TCC, hardened runtime, notarization, SIP interactions, and per-release quirks of macOS 12–15—are mostly inferred rather than documented. iOS is present but always as a twin of macOS Seatbelt; mobile-only phenomena (e.g., complex app groups, background modes, modern extension points) are not explored deeply.

On the “what the sandbox does” axis, the canon is strongest on the SBPL language, binary profile format, and core enforcement pipeline (libsandbox, Sandbox.kext, MACF hooks). It is weaker on higher-level system layers that shape effective sandbox behavior in practice: container / containerized filesystem layout over time, modern XPC and service management patterns, LaunchServices and login items, and the way third-party frameworks layer their own permission models on top of the sandbox. It also does not fully map the growing ecosystem of private entitlements, entitlement review practice, or real-world entitlement abuse patterns beyond what shows up in the 2019 adoption study.

On the “how it fails” axis, we have one systematic empirical study and scattered offensive notes, but not a comprehensive exploit canon. There is limited coverage of modern sandbox escapes and bypass chains, threat models involving malicious but sandboxed plugins or helper tools, or the interaction between sandboxing and newer macOS attack surfaces (e.g., kernel extensions’ slow deprecation, system extensions, virtualization frameworks). Formal verification, static analysis frameworks for profile correctness, and rigorous performance/overhead characterizations are also largely out of frame.

Finally, the corpus is skewed toward specialist and research perspectives: reverse engineers, security researchers, and power users. It underrepresents the day-to-day experience of ordinary macOS developers wrestling with entitlements and containers, and it largely ignores policy, usability, and ecosystem dynamics (how Apple’s evolving rules and review practices actually shape what gets shipped). When we encode this canon into a machine-readable catalog or use it to interpret one, we should treat it as authoritative on the existence and semantics of many operations and hooks, but explicitly uncertain about (a) post-2019 evolution, (b) real-world entitlement usage and misusage outside the studied samples, and (c) higher-level platform behaviors that sit above the core Seatbelt machinery.

### Leakage and ambient knowledge

Even with a fixed canon, the substrate is not hermetic. Agents arrive with priors, training data, and external tools; humans arrive with experience, habits, and half-remembered sources. As they read, summarize, or extend the canonical documents, they inevitably draw on that ambient knowledge to fill gaps, smooth transitions, or propose examples. The resulting text can be structurally faithful to the canon while still containing claims, distinctions, or stories that never actually appear in any of the seven documents. This is “leakage”: information that seeps into the project from outside the substrate, independent of whether it is correct.

Leakage can enter at several points. During close reading or summarization, an agent can interpolate missing context (“this probably refers to XNU internals” or “Apple must implement this with a BPF-like filter”) that feels natural given its priors but is not grounded in the canon. When retrieval or search is available, an agent may silently pull in details from non-canonical sources to resolve ambiguities or enrich an explanation. When a human or supervising “proctor” interjects domain knowledge, patterns, or warnings that are not explicitly tied back to canonical passages, those also become latent influences. Over time, these leaks can accumulate into a parallel, implicit substrate that feels as authoritative as the canon because it is never marked as such.

Finding leakage is not the same task as finding errors. Wrong information is judged against some notion of truth: either it contradicts the canon, contradicts observed system behaviour, or is internally inconsistent. Leaked information is judged genealogically: it may be entirely accurate, but it has no traceable origin in the canonical documents. An agent scanning for wrongness asks “is this claim false or incoherent?”; an agent scanning for leakage asks “can I derive this claim (or its key parts) from the canon, or is it standing on unstated supports?” Those are different questions, and both matter for a project that treats the canon as a deliberately bounded world.

Because of this distinction, handling leakage requires different tools than handling mistakes. Suppressing all non-canonical content would destroy useful context and intuition, but letting it flow unmarked would gradually erase the boundary the canon is meant to provide. A more appropriate stance is to surface provenance: when a claim depends on ambient knowledge, label it as such or attach it to an “adjacent work” rather than silently blending it into canonical exposition. That way, later agents can distinguish between “the substrate says this” and “this is a plausible extension or imported pattern,” and can decide which layer to trust, revise, or replace without needing to untangle them after the fact.

## Reading the canon

Treat this canon as a small, structured corpus rather than seven isolated texts. One useful lens is “intended audience”: APPLESANDBOXGUIDE and ROWESANDBOXING are written for implementers and app developers; BLAZAKIS2011 and SANDBLASTER2016 address reverse engineers and internals-focused security researchers; STATEOFSANDBOX2019 and HACKTRICKSSANDBOX emphasize empirical practice and offense; WORMSLOOK2024 tries to connect architecture to everyday platform behavior. When the catalog asserts something about how Seatbelt “really” works, a skeptical reader can ask: which of these audiences does that claim rely on, and how do the other audiences talk about (or conspicuously ignore) the same point?

A second lens is abstraction level. The corpus covers: (a) language and policy structure (SBPL primitives, operations, filters), (b) compilation and representation (binary profiles, `sandbox-simplify`, libsandbox), (c) enforcement (Sandbox.kext, MAC hooks, syscall mediation), and (d) ecosystem usage (entitlement sets, containers, app categories, common deployment patterns). APPLESANDBOXGUIDE and BLAZAKIS2011 inhabit the language and enforcement layers; SANDBLASTER2016 binds language to compiled artifacts; WORMSLOOK2024 and ROWESANDBOXING bridge enforcement to platform stories; STATEOFSANDBOX2019 and HACKTRICKSSANDBOX live at the ecosystem layer. When you see a capability in the catalog, it is worth asking which of these layers is directly supported by text and which require inference across layers; that gives you a principled way to distinguish “well-grounded semantics” from “plausible extrapolation.”

A third axis is time and platform evolution. The early sources (APPLESANDBOXGUIDE, BLAZAKIS2011) give a detailed snapshot of language and architecture in the 10.x era; SANDBLASTER2016 traces profile evolution across iOS versions; STATEOFSANDBOX2019 captures macOS App Sandbox usage at a particular moment; WORMSLOOK2024 and ROWESANDBOXING provide more recent but higher-level overviews. A careful reader should treat these as a time series: when the catalog describes an operation, filter, or entitlement, check whether its description is anchored in early technical detail, in mid-period reverse engineering, in later ecosystem observation, or in some combination. Where all eras agree you can treat stability as a working assumption; where only the early or only the late sources speak, you should read the catalog’s claims as more contingent on OS version and platform context.

Threat and trust models offer another cross-cutting lens. Some texts assume cooperative developers trying to sandbox themselves correctly (APPLESANDBOXGUIDE, ROWESANDBOXING), others assume analysts or adversaries probing for weaknesses (BLAZAKIS2011, HACKTRICKSSANDBOX), and still others study aggregate behavior and policy effectiveness at the ecosystem level (STATEOFSANDBOX2019). WORMSLOOK2024 sits between architectural description and security evaluation. When a catalog entry encodes an operation or entitlement, you can ask: is this framed primarily as a safety boundary, as an attack surface, or as a fact about how apps are actually configured in practice? Noting which threat model underwrites a given description will help you see both the strength of the supporting evidence and its likely blind spots.

Finally, use the corpus to calibrate your skepticism about the catalog itself. For any nontrivial capability, imagine tracing it through four questions: Which audiences talk about it? At which abstraction layers? In which time slices? Under which threat models? The catalog’s annotations should give you some of that mapping explicitly; where they do not, this canon is small enough that you can realistically reconstruct the mapping yourself. Read the catalog’s “facts” as claims that are strong where the corpus converges and explicitly provisional where it does not, and treat the references to these seven sources not as ornamental citations but as invitations to re-run the reasoning from first principles whenever a claim looks surprisingly strong, surprisingly weak, or surprisingly silent.

## Listing by SHORTNAME

The SHORTNAME identifiers below are the canonical labels used throughout this project and in the macOS capability catalog; use them as stable handles when cross-referencing catalog entries with these sources.

### ROWESANDBOXING

**Citation**
Mark Rowe. “Sandboxing on macOS.” bdash.net blog, 2024. Practitioner-level explanation of macOS sandboxing from an application and user perspective.

**Public link**
[https://bdash.net.nz/posts/sandboxing-on-macos/](https://bdash.net.nz/posts/sandboxing-on-macos/)

**Version / platform window**
Targets modern macOS as of 2024, with emphasis on contemporary App Sandbox behaviour, entitlements, and filesystem constraints seen by third-party applications.

**Primary axes / authority tags**
`App Sandbox behaviour (macOS)` · `entitlements and user data access` · `filesystem constraints and containers` · `exploit-mitigation intuition` · `developer / user experience`

**Reliability and blind-spot notes**
Treat this as a clear, grounded account of how sandboxing manifests in day-to-day macOS application behaviour: what kinds of file and data access are restricted, how entitlements shape those restrictions, and how the sandbox interacts with ordinary user workflows. Its focus is practical and explanatory rather than exhaustive or formal; it does not describe SBPL, binary profile formats, or kernel internals, and it largely ignores iOS. Some views are deliberately opinionated (trade-offs, pain points) and should be read as calibrated field observations rather than normative specifications.

**Usage guidance for builders**
Use ROWESANDBOXING when you need to connect abstract sandbox concepts to what a Mac user or developer actually sees: prompts for file access, entitlement-driven capabilities, and the ways sandboxing limits the impact of code execution bugs in real applications. Reach for it when writing about “why sandboxing exists” in practice, how App Sandbox constraints feel from the outside, or where developers typically encounter and work around sandbox boundaries. Treat it as an intuition-building lens for macOS-specific behaviour and developer experience, and pair it with the more formal and reverse-engineering-heavy canonical sources when you need detailed operation sets, internal mechanisms, or precise policy semantics.


### HACKTRICKSSANDBOX

**Citation**
HackTricks contributors. “macOS Sandbox.” HackTricks, last updated 2024. Practitioner-oriented notes on macOS Seatbelt from an attacker/ops perspective.

**Public link**
[https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox)

**Version / platform window**
Targets modern macOS releases as of 2024, with emphasis on how sandboxing appears and behaves on current desktop systems rather than historical OS X or iOS variants.

**Primary axes / authority tags**
`practitioner / attacker viewpoint` · `sandboxed process recognition` · `container and entitlement inspection` · `quick enumeration techniques` · `common misconfigurations and weak spots`

**Reliability and blind-spot notes**
Treat this as a concise field guide rather than a complete or formally precise description of the sandbox. It is strong on “what a security practitioner actually does” to recognize sandboxed processes, list containers, and inspect entitlements, and on highlighting the kinds of misconfigurations and weak spots that show up in offensive playbooks. Its blind spots are depth and completeness: it does not attempt exhaustive coverage of SBPL, binary formats, or kernel internals, and some details may be tuned to particular macOS versions or toolchains without explicit versioning.

**Usage guidance for builders**
Use HACKTRICKSSANDBOX when you need concrete, command-level examples of how to observe and poke at the sandbox on a live macOS system: listing sandboxed processes, locating and inspecting containers, dumping entitlements, and spotting obvious over-privileging. Reach for it when you are writing about “how this looks from a terminal” or about practical failure modes and attack surfaces, especially where you want examples that align with current red-team and operator practice. Treat it as an applied checklist and a source of realistic examples to stress-test more abstract capability descriptions from the rest of the canon, not as a primary source for language semantics or internal architecture.

### SANDBLASTER2016

**Citation**
Răzvan Deaconescu, Luke Deshotels, Mihai Bucicoiu, William Enck, Lucas Davi, and Ahmad-Reza Sadeghi. “SandBlaster: Reversing the Apple Sandbox.” arXiv preprint arXiv:1608.04303, 2016. Reverse-engineering study of Apple’s compiled sandbox profiles and their evolution.

**Public link**
[https://arxiv.org/abs/1608.04303](https://arxiv.org/abs/1608.04303)

**Version / platform window**
Focuses primarily on iOS profiles up through iOS 9.x, with attention to multiple binary profile formats (separated profiles, bundled profiles) across those releases; macOS is referenced mainly where formats or behaviour overlap.

**Primary axes / authority tags**
`binary profile format (iOS)` · `profile bundle layout and headers` · `SBPL decompilation tooling` · `built-in policy corpus and evolution` · `operation/filter usage statistics` · `large-scale profile comparison`

**Reliability and blind-spot notes**
Treat this as the canonical reference for how iOS sandbox profiles are stored and structured on disk across several generations, and for how to decompile them back into an SBPL-like form at scale. It carefully documents binary formats, header fields, section layouts, and the mechanics of reconstructing human-readable policies from compiled blobs. Its blind spots are deep macOS-specific evolution after the covered versions, and kernel-level evaluator internals (which rely more on BLAZAKIS2011); its view of the policy corpus is also time-bounded to the iOS releases it analyzes, so later operations, filters, and profile changes are necessarily absent.

**Usage guidance for builders**
Use SANDBLASTER2016 when you need to reason about compiled profiles as concrete artifacts: header structures, section boundaries, operation-node tables, regex/literal pools, and how SBPL constructs are encoded in those binaries. Reach for it when you are discussing PolicyGraph extraction, profile decompilation, or empirical observations about Apple’s stock profiles (which operations appear, how rules change across iOS versions, where constraints are tightened or relaxed). Treat its recovered corpus and methodology as the empirical backbone for any catalog or textbook claim that starts “in real Apple profiles we see…,” and pair it with BLAZAKIS2011 and APPLESANDBOXGUIDE when you need evaluator internals or language-level details beyond the iOS-centric formats and time window it covers.


### APPLESANDBOXGUIDE

**Citation**
fG!. “Apple’s Sandbox Guide v1.0.” reverse.put.as, 2011. Practitioner-focused guide to Apple’s sandbox profile language and stock policies.

**Public link**
[https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)

**Version / platform window**
Targets OS X 10.6/10.7 (Snow Leopard / Lion) era behaviour and SBPL, with examples and tooling usage grounded in those releases.

**Primary axes / authority tags**
`SBPL syntax and idioms` · `operation and filter taxonomy` · `default vs explicit rules` · `profile authoring and debugging` · `sandbox-exec / sandbox-simplify usage` · `stock profile patterns (10.6/10.7)`

**Reliability and blind-spot notes**
Treat this as the canonical language-and-idiom reference for Apple’s sandbox around 10.6/10.7: it systematically enumerates operations, filters, and modifiers, and explains how rules compose under default allow/deny semantics with practical examples. Its scope is intentionally userland-facing: it does not describe binary profile formats, kernel internals, or post-2011 features and operation families. Version-specific quirks, bugs, and missing later operations mean that some details are historically accurate but not representative of modern platforms; use it as a baseline vocabulary and mental model, not as an up-to-date catalogue of everything current systems support.

**Usage guidance for builders**
Use APPLESANDBOXGUIDE when you need a structured map of the SBPL surface: what the core operation families are (file, IPC, Mach, network, process, sysctl, system), how rules are written, and how filters and modifiers are intended to be combined. Reach for it when you are naming and grouping operations in the capabilities catalogue, designing didactic examples of profile fragments, or explaining default vs explicit rules in prose. Treat its worked examples with `sandbox-exec`, tracing, and `sandbox-simplify` as canonical small patterns for writing and debugging profiles in the “classic” era, and then layer other canonical sources on top when you need deeper internals or modern extensions to the language and policy set.

### WORMSLOOK2024

**Citation**
Osama Alhour. “A Worm’s Look Inside: Apple’s Sandboxing security measures on macOS & iOS.” nsantoine.dev, 2024. Practitioner-style technical writeup on modern sandboxing behaviour and process lifecycle.

**Public link**
[https://nsantoine.dev/SandboxPaper.pdf](https://nsantoine.dev/SandboxPaper.pdf)

**Version / platform window**
Focuses on contemporary macOS and iOS releases as of 2024, with particular attention to current container layouts, launch-time behaviour, and system daemons involved in sandboxing on those platforms.

**Primary axes / authority tags**
`containers and filesystem layout` · `entitlements and launch-time wiring` · `process startup lifecycle` · `sandboxd / containermanagerd / launchd roles` · `sandbox extensions and exceptions` · `macOS vs iOS differences`

**Reliability and blind-spot notes**
Treat this as a modern architectural snapshot of how Apple’s sandbox integrates with containers, entitlements, and system services rather than as a primary source on SBPL syntax or binary profile formats. It is strong on “who gets sandboxed, when, and with which container,” including concrete details of on-disk container structure and the roles of containermanagerd, sandboxd, launchd, and dyld in process startup. Its blind spots are deep kernel internals, historical evolution, and low-level profile encodings, which are covered more thoroughly in other canonical sources; some implementation details are inferred from observation and tooling rather than from direct reverse engineering.

**Usage guidance for builders**
Use WORMSLOOK2024 when you need to connect sandbox policy to the lived behaviour of apps on macOS and iOS: how containers are created and named, how bundle identifiers and UUIDs map to container directories, how entitlements and profiles are selected at launch, and where sandbox checks sit along the process startup and IPC paths. Reach for it when you are writing about lifecycle and wiring—install-time container creation, first launch, runtime interactions with the filesystem and services—especially when you need to bridge userland daemons and kernel enforcement in one narrative. Treat it as glue and a modern reference point for “what actually happens on a current system,” and pair it with other canon items for SBPL details, binary profile formats, and low-level evaluator behaviour.

---

### BLAZAKIS2011

**Citation**
Dionysus Blazakis. “The Apple Sandbox.” Black Hat DC, 2011. Reverse-engineering paper focused on Seatbelt’s internal architecture, compiler, and evaluator.

**Public link**
[https://www.ise.io/wp-content/uploads/2017/07/apple-sandbox.pdf](https://www.ise.io/wp-content/uploads/2017/07/apple-sandbox.pdf)

**Version / platform window**
Primarily OS X 10.6.x (Snow Leopard), with partial applicability to nearby 10.5/10.7 systems using the same basic Seatbelt design.

**Primary axes / authority tags**
`seatbelt kernel internals` · `libsandbox.dylib and Scheme compiler` · `SBPL evaluation model` · `early binary profile layout` · `AppleMatch regex engine` · `TrustedBSD MAC hooks`


**Reliability and blind-spot notes**
Treat this as the architectural spine for the “classic” Seatbelt design: it gives a concrete, end-to-end account of how SBPL is compiled, how binary profiles are structured, and how the kernel evaluates policy via MAC hooks and a regex engine. Its limits are version drift and scope: it predates iOS-style bundled profiles, newer macOS policy formats, and later operation sets. Some implementation details are reconstructed from reverse engineering and may differ in minor ways from current kernels, but the overall dataflow and control-flow picture is the reference model for this project.

**Usage guidance for builders**
Use BLAZAKIS2011 when you need to understand how the public interfaces (sandbox_init, sandbox-exec), libsandbox’s TinyScheme-based SBPL compiler, and Sandbox.kext’s MAC hooks fit into a single pipeline, and how human-readable rules become compact decision structures applied on syscalls. Reach for it whenever the task is “explain how a sandbox decision is actually made,” “relate a profile construct to kernel behaviour,” or “orient a PolicyGraph/binary-profile discussion in concrete machinery.” When modern sources disagree on details for newer formats or features, default to this paper’s architectural model and then layer later documents on top for version-specific differences.

---

### STATEOFSANDBOX2019

**Citation**
Maximilian Blochberger, Jakob Rieck, Christian Burkert, Tobias Mueller, and Hannes Federrath. “State of the Sandbox: Investigating macOS Application Security.” Proceedings of the 2019 ACM Workshop on Privacy in the Electronic Society (WPES), 2019. Empirical security study of macOS App Sandbox usage and weaknesses.

**Public link**
[https://svs.informatik.uni-hamburg.de/publications/2019/2019-11-Blochberger-State-of-the-Sandbox.pdf](https://svs.informatik.uni-hamburg.de/publications/2019/2019-11-Blochberger-State-of-the-Sandbox.pdf)

**Version / platform window**
Focuses on macOS around 2018–2019, with measurements and case studies drawn from then-current macOS releases, Mac App Store (MAS) apps, and third-party macOS software obtained from MacUpdate.

**Primary axes / authority tags**
`ecosystem adoption and coverage` · `entitlement usage patterns` · `privilege separation in real apps` · `sandbox-bypass vulnerability case study` · `MAS vs third-party comparison` · `empirical measurement methodology`

**Reliability and blind-spot notes**
Treat this as the canonical empirical snapshot of how the macOS sandbox is actually used in the wild: it combines static and dynamic analysis of over ten thousand apps to quantify sandbox adoption, entitlement use, and common privilege patterns. It also documents a concrete sandbox-bypass vulnerability discovered in the course of the study. Its blind spots are depth of internals and temporal drift: it assumes the App Sandbox model rather than re-deriving it, and its measurements describe a particular moment in the ecosystem; later macOS versions, store policies, and developer practices may differ. Use its quantitative findings and vulnerability analysis as evidence about practice, not as a current census.

**Usage guidance for builders**
Use STATEOFSANDBOX2019 when you need to talk about how widely and how well the sandbox is used, rather than how it is supposed to work: MAS vs third-party adoption rates, typical entitlement patterns, and the real-world state of privilege separation in macOS apps. Reach for it when motivating why capability catalogues and probe suites matter in practice, or when you want grounded examples of sandbox misuse and bypass (including the documented bug) to connect abstract capability talk to concrete risk. Treat it as the ecosystem and measurement lens in the canon—complementing the architectural and language-focused sources—when you are writing about “what developers and distributors actually do with the sandbox” and the gaps between the model and deployed reality.
