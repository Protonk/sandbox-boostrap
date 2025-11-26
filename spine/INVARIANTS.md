# Invariants

The following points are project-wide invariants: fixed assumptions about Seatbelt’s architecture, terminology, and modeling that other texts and tools in this project rely on. When you reason, explain, or write code for this project, do not contradict them; if external knowledge differs, follow these invariants and at most note the discrepancy.

* Seatbelt is implemented as a TrustedBSD MAC policy inside `Sandbox.kext` that mediates sensitive operations via internal policy graphs.

* Seatbelt mediates kernel operations by consulting compiled policy graphs keyed by operation identifiers, not by interpreting SBPL at runtime.

* SBPL is the primary sandbox policy language; it is a Scheme-like DSL compiled by a TinyScheme-derived interpreter in `libsandbox`.

* SBPL policies are expressed in terms of operations, filters, and metafilters, and these map directly onto structures in the compiled policy graph.

* Compiled profiles are binary policy graphs consisting of a header, an operation pointer table, a node graph, and shared literal/regex tables, with format variants across OS versions.

* Each operation class (for example, `file-read*`, `mach-lookup`, `network-outbound`) has a numeric ID and an entrypoint into the compiled graph; decisions are taken by traversing that graph for the operation.

* Sandbox decisions conceptually consist of an allow/deny verdict plus optional action modifiers, derived from the path taken through the policy graph for a given operation and context.

* The effective sandbox for a process is a stack of policies (platform profiles, app/custom profiles, optional auxiliary policies) plus sandbox extensions, evaluated with a fixed precedence where stronger denies dominate allows.

* Sandbox extensions act as a third dimension that grants narrowly scoped additional rights without changing the underlying profiles, and they are attached to process labels as opaque tokens consumed by filters.

* Every sandboxed process has a Seatbelt label in the kernel that encodes its active profiles and sandbox extensions; enforcement decisions are made against this label, not per-thread ad hoc state.

* The App Sandbox model provides each sandboxed app with a dedicated container directory, which defines the default filesystem view for that app.

* Access to files outside the container is widened primarily via sandbox extensions (for example, when the user picks a file in an open/save panel), not by permanently broadening the base profile.

* TCC, hardened runtime, and SIP are separate but adjacent security layers: they are not part of Seatbelt profiles but their decisions intersect with Seatbelt’s, and can veto operations even when Seatbelt would allow them.

* The high-level Seatbelt architecture—SBPL policies compiled into graph-based binary profiles enforced by `Sandbox.kext` against process labels—has remained stable from macOS 10.x through at least macOS 13–14.

* The existence and centrality of containers, entitlements, TCC, hardened runtime, and SIP as major components of Apple’s security stack are treated as stable facts for this project.

* High-churn surfaces include the exact SBPL contents of system profiles, the entitlement catalogue, detailed TCC service taxonomy and defaults, container layout minutiae, and fine-grained hardened-runtime/SIP rules; these are explicitly not treated as invariants.

* Any claim about high-churn surfaces must be versioned (by OS / build) and preferably backed by probes and logs; such claims remain empirical observations, not structural assumptions.

* `SUBSTRATE_2025-frozen` is the normative description of Seatbelt and its environment for this project; where external sources disagree, the substrate wins unless it is intentionally revised.

* The canon consists of exactly seven sandbox-related sources, which are treated as the primary external evidence for Seatbelt architecture and behavior in this substrate version.

* New information beyond the canon is incorporated via explicitly versioned deltas (for example, updated State documents or new substrate versions) rather than by silently rewriting canonical claims.

* `Concepts.md` defines the authoritative vocabulary and distinctions for this project; all code, documentation, and analysis should use these terms consistently.

* Each core concept (for example, SBPL Profile, PolicyGraph, Operation, Filter, Metafilter, Policy Stack Evaluation Order, Sandbox Extension) must be interpretable both at the SBPL text level and at the compiled/binary or trace level.

* Conceptual claims in substrate documents should be anchored in empirical artifacts (profiles, binaries, traces, probes) or canonical sources; ungrounded speculation is out of scope for the substrate.

* XNUSandbox’s role is strictly to decode and explain sandbox-related artifacts (SBPL, compiled profiles, labels) and to present a stable conceptual IR; it is not an enforcement engine, syscall interceptor, or TCC/hardened-runtime implementation.

* XNUSandbox targets the modern graph-based profile formats used on current macOS, but its internal IR is concept-driven in a way that should tolerate reasonable changes in binary layout.

* Tools and tests in this project should reason about sandbox behavior using the small concept set (operations, filters, metafilters, decisions, policy graphs, labels, containers, extensions, entitlements) rather than introducing unrelated ad-hoc notions.

* Capability catalog entries must be expressible in terms of underlying Seatbelt constructs (operations, filters, profiles, extensions, containers, entitlements, adjacent controls), not purely in terms of user-visible feature labels.

* When explaining or debugging a real-world decision, the correct mental model is a combination of stacked policies, process label, sandbox extensions, and adjacent controls, not a single flat SBPL rule list.

* macOS and iOS share a common container-centric, entitlement-driven sandbox model; platform differences are treated as variations in defaults and coverage on top of that shared structure.

* For the synthetic textbook, worked examples (such as TextEdit’s sandbox on a specific macOS release) are binding demonstrations of how the concepts map to real code and behavior; disagreements are resolved in favor of those examples plus the substrate.
