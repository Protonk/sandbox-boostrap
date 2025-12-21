>SUBSTRATE_2025-frozen
# Seatbelt / Sandbox Orientation

This document gives you a compact mental model of Apple’s sandbox. It is aimed at readers who are comfortable with macOS internals and willing to read C / reverse-engineered code, not a beginner’s primer.

You can assume the following reference sections exist and are available:
* In `Appendix.md`:
 * “Sandbox DSL Cheatsheet” – SBPL syntax, filters, metafilters, action modifiers.
 * “Binary Profile Formats and Policy Graphs” – headers, node layouts, regex tables, graph structure.
 * “Operations and Filters Reference” – operation families, filter categories, metadata mapping.
 * “Policy Stacking and Platform Sandbox” – platform vs per-process policy and sandbox extensions.
* In `Environment.md`: “Sandbox Environment” – containers and filesystem view, structural invariants vs churn, and adjacent controls (TCC, hardened runtime, SIP).
* In `Concepts.md`: Clear definitions and explanations for all important terms.

Use this orientation as your conceptual scaffold and the appendices above for precise vocabulary and layouts.

---

## 1. Purpose and Scope

This orientation explains:

* What Seatbelt is, at the level of “moving parts” (operations, filters, policy graphs, label state).
* How policy moves from SBPL text to kernel decisions.
* How to interpret what the tooling in this repo prints or parses.

It is deliberately light on:

* Concrete SBPL profiles and per-OS quirks (those live in the Appendix).
* Adjacent systems like TCC, hardened runtime, and SIP (those live in Environment).

---

## 2. Core Concepts

A comprehensive concept list is available at `book/substrate/Concepts.md`.

1. **Operation**

   A named class of kernel action such as `file-read*`, `mach-lookup`, or `network-outbound`. In the compiled format, each operation has a numeric ID, and the policy graph has an entrypoint per operation.

   * In SBPL: the symbol in `(allow file-read* …)`.
   * In binary: the index into an operation pointer table that yields a node offset.

2. **Filter**

   A predicate on the operation’s arguments or process/OS state: path, vnode type, UID, entitlement, signing identifier, sandbox extensions, and so on.

   * In SBPL: `(path "/bin/ls")`, `(subpath "/Applications/TextEdit.app")`, `(vnode-type REGULAR-FILE)`, `(global-name "com.apple.cfprefsd.daemon")`.
   * In binary: a filter key code plus an argument (often an index into literal/regex tables or a small enum).

   See “Sandbox DSL Cheatsheet” and “Operations and Filters Reference”.

3. **Metafilter / condition structure**

   Logical composition of filters using `require-any`, `require-all`, `require-not`. In SBPL these appear explicitly; in the binary format this appears as graph shape, not as explicit tags.

   * `require-any` ≈ OR of branches.
   * `require-all` ≈ AND of conditions.
   * `require-not` ≈ negation of a subgraph.

   See “Sandbox DSL Cheatsheet” and “Binary Profile Formats and Policy Graphs”.

4. **Decision**

   A verdict (usually allow/deny) plus optional action modifiers (e.g., logging/reporting flags). Implemented as terminal nodes and flags in the compiled profile.

5. **PolicyGraph**

   The compiled representation of a profile:

   * A header with counts/offsets.
   * An operation pointer table (operation ID → node offset).
   * A node array (filter and decision nodes).
   * Shared literal and regex tables.

   The local tooling’s internal IR is a slightly higher-level reconstruction of this.

6. **Profile Layer and Stack**

   Seatbelt evaluates a stack of profiles:

   * Platform profile(s) – OS-supplied policies for daemons, helpers, and system roles.
   * App/custom profile – App Sandbox profile or a profile created via sandbox(7).
   * Auxiliary profiles – occasional extra policies used for narrow roles.
   * Sandbox extensions – tokens that add scoped permissions on top of existing profiles.

   The **Policy Stack Evaluation Order** and the precedence rules (“platform denies dominate app allows”) are treated as structural invariants.

7. **Compiled Profile Source**

   Where a compiled profile came from:

   * Platform bundles and internal configuration.
   * App Sandbox templates parameterized by entitlements and metadata.
   * Custom SBPL and named profiles via sandbox(7).
   * Harness/test profiles created by tools.

   The analysis tooling does not care about the exact provenance once it has a compiled blob, but the rest of the documentation does.

At enforcement time there is no Scheme interpreter. The kernel walks a compiled graph for each relevant operation; our code must decode that graph and relate it back to the vocabulary above.

---

## 3. Policy Lifecycle: From SBPL to Kernel Decisions

You should think of Seatbelt policy as moving through four broad stages:

1. **SBPL source or template**

   * Human-readable SBPL, either:
     * App Sandbox template or other Apple-supplied internal SBPL.
     * SBPL files or strings passed to sandbox(7) APIs.
   * May contain `(param "…")` placeholders and use `string-append` and similar forms to build paths and names.

2. **Parameterized SBPL instance**

   * At launch time, the system gathers entitlements and metadata (bundle ID, container root, etc.).
   * These are fed into the SBPL template as a parameter dictionary.
   * The result is a concrete SBPL profile for this process or role: all `(param "…")` forms resolved, no remaining placeholders.

3. **Compiled profile (PolicyGraph)**

   * `libsandbox` (via TinyScheme) compiles SBPL into a binary policy:
     * Header, operation pointer table, node array, literal and regex tables.
   * The tooling here works with compiled blobs (from `.sb` files, and historically from kernelcaches), not directly with SBPL.
   * Action modifiers (e.g., `(with report)`) become flags on decision nodes and influence logging/reporting behavior.

4. **Installed policy and runtime evaluation**

   * The compiled profile is handed to `Sandbox.kext` via sandbox-specific syscalls or IPC.
   * The kernel stores the profile, attaches references to process credentials (labels), and uses it to evaluate MACF hooks for file/IPC/process/network operations.
   * Decisions are combined across platform/app/auxiliary profiles and sandbox extensions according to fixed precedence rules.

The detailed mechanics and references live in the appendix’s “Lifecycle pipeline” section; this Orientation only needs you to keep the four stages distinct.

---

## 4. Profiles, Processes, and “Who Is Sandboxed?”

Seatbelt policy is attached to *process credentials*, not to files or users in the abstract. You should keep separate:

1. **Platform policies**

   * Loaded at boot or as needed.
   * Apply to system daemons, helpers, and some apps based on launch configuration.
   * Often invisible to developers but critical for understanding real-world behavior.

2. **App Sandbox policies**

   * Triggered by the `com.apple.security.app-sandbox` entitlement.
   * Applied automatically by early `libSystem` initializers for App Sandbox apps.
   * Parameterized heavily by entitlements (network, file, device capabilities) and metadata (bundle ID, container root).

3. **Custom sandbox(7) policies**

   * Applied explicitly by code calling `sandbox_init_*`.
   * Can be based on named profiles, SBPL files, or SBPL strings.
   * Coexist with platform policies just like App Sandbox profiles do.

4. **Sandbox extensions**

   * Dynamic tokens that grant scoped extra capabilities (e.g., access to user-selected files).
   * Stored alongside profile references in the credential label.
   * Checked by extension filters inside the policy graph.

At the moment of evaluation, the kernel has a set of compiled profiles and extensions attached to the process label; those are what we can parse and display.

---

## 5. How to Reason About a Sandboxed Operation

When you see a denied (or allowed) operation in practice, you should think in terms of a stack and a graph, not a single flat rule list.

For a given operation (say, `file-read*` on `/Users/alice/Documents/foo.txt`), the effective decision is the intersection of:

* Platform profile decisions.
* Process profile decisions (if any).
* Dynamic sandbox extensions.
* Other MAC policies and SIP/TCC behavior (see “Sandbox Environment”).

“Policy Stacking and Platform Sandbox” explains this in detail. When reasoning about a behavior:

1. Identify the operation as Seatbelt sees it.

   * Which operation ID is in play (`file-read*`, `mach-lookup`, etc.)?
   * What are the relevant arguments (path, vnode type, target PID, bootstrap name)?

2. Walk the relevant policy graphs.

   * For the platform layer: what filters and decisions are attached to that operation?
   * For the process layer: what extra allows/denies exist?
   * Where do sandbox extensions plug in (if any)?

3. Combine the results with precedence rules.

   * Platform denies generally dominate app allows.
   * Extensions add scoped allows without rewriting platform/app profiles.
   * TCC and SIP may apply additional “no” decisions outside Seatbelt.

The internal representations used here (and the Appendix/Environment docs) are set up so that tools and tests can do this reasoning mechanically.

---

## 6. Working Discipline for Code and Documentation

To keep code maintainable and the surrounding documentation useful, adopt the following discipline:

1. **Keep the conceptual model small and explicit.**

   * New code should fit into the existing concept vocabulary (Operation, Filter, PolicyGraph, Profile Layer, etc.).
   * If you find yourself inventing new terms, consider whether they are aliases for existing concepts.

2. **Separate SBPL, compiled format, and analysis.**

   * SBPL parsing/pretty-printing, binary parsing, and higher-level analysis should not be tangled.
   * Avoid letting low-level format quirks leak into high-level reasoning code.

3. **Be explicit about version and format assumptions.**

   * If a parser or analysis assumes macOS 14’s header layout, say so in comments and tests.
   * When possible, write code that can tolerate missing or changed fields gracefully.

4. **Use the reference sections instead of ad-hoc explanations.**

   * For SBPL syntax → “Sandbox DSL Cheatsheet”.
   * For headers, node layouts, regex tables → “Binary Profile Formats and Policy Graphs”.
   * For operation/filter vocab and families → “Operations and Filters Reference”.
   * For runtime stacking and Seatbelt layers → “Policy Stacking and Platform Sandbox”.
   * For containers, invariants vs churn, and adjacent controls → “Sandbox Environment”.

5. **Treat empirical details as provisional.**

   * Operation counts, specific filter IDs, and exact profile contents are high-churn.
   * Structural invariants (graph shape, operation pointer tables, policy stacking) are stable; prefer to reason and test against those.
