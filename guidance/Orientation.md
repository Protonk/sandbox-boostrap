# Seatbelt / XNUSandbox Orientation

This document gives you a compact mental model of Apple’s Seatbelt sandbox and how it shows up in the XNUSandbox codebase. It is aimed at an advanced code agent that will read C / reverse-engineered code, not a beginner’s primer.

You can assume the following reference sections exist and are available:

* “Sandbox DSL Cheatsheet” – SBPL syntax, filters, metafilters, action modifiers.
* “Binary Profile Formats and Policy Graphs” – headers, node layouts, regex tables, graph structure.
* “Operations and Filters Reference” – operation families, filter categories, metadata mapping.
* “Policy Stacking and Platform Sandbox” – platform vs per-process policy, extensions, SIP/TCC context.

Use this orientation as your conceptual scaffold and the appendix for precise vocabulary and layouts.

---

## 1. Purpose and Scope

Your task in this repo is to make sense of XNUSandbox: a reverse-engineering toolkit that takes Apple’s compiled sandbox policies and turns them back into something close to SBPL.

To do that effectively you need to be able to:

* Recognize **what kind of object** you are looking at in code:

  * SBPL text, intermediary Scheme, compiled profile header, node array, operation table, regex table, etc.
* Map low-level constructs to **stable Seatbelt concepts**:

  * Operation IDs ↔ operation names.
  * Filter codes/arguments ↔ SBPL filters.
  * Node structures ↔ `require-any/all/not` and allow/deny decisions.
* Keep track of **which era and layer** of Seatbelt you are dealing with:

  * Older decision-tree formats vs later graph-based formats.
  * Platform profile vs per-process (App Sandbox or custom) profile.

The orientation stays at that conceptual level. When you need concrete SBPL spells, field layouts, or operation/filter inventories, the appendix sections are the place to look.

---

## 2. Core Seatbelt Model

Seatbelt is implemented as a TrustedBSD MAC policy inside XNU. Conceptually:

* Every process has a set of **MAC labels** on its credentials.
* Seatbelt uses one label to store zero or more **sandbox policies**:

  * A global **platform** policy applied to (almost) everything.
  * Optional **per-process** policy if the process is App Sandbox-enabled or calls `sandbox_init*`.
* Each sandbox policy is a **compiled profile**:

  * A graph or decision tree of nodes representing filter tests and terminal decisions.
  * Shared tables for literal strings and regexes.
* The kernel’s MAC hooks consult these compiled policies before allowing sensitive operations.

Four terms are worth fixing in your vocabulary:

1. **Operation**
   A named class of action such as `file-read*`, `network-outbound`, `mach-lookup`, `sysctl`. In compiled form, each operation has a numeric ID and an entrypoint into a rule graph.
   See “Operations and Filters Reference” for families and examples.

2. **Filter**
   A predicate on the operation’s arguments or process/OS state: path predicates, vnode type, Mach service names, socket addresses, entitlements, signing identifier, SIP state, extensions, and so on.
   See “Sandbox DSL Cheatsheet” and “Operations and Filters Reference”.

3. **Metafilter / condition structure**
   Logical composition of filters using `require-any`, `require-all`, `require-not`, plus rule-level combinations of multiple filters. In the binary format this appears as graph shape, not as explicit tags.
   See “Sandbox DSL Cheatsheet” and “Binary Profile Formats and Policy Graphs”.

4. **Decision**
   A verdict (usually allow/deny) plus optional action modifiers (log/report, user consent). Implemented as terminal nodes and flags in the compiled profile.

At enforcement time there is no Scheme interpreter. The kernel walks a **pre-compiled decision structure** for `(operation, arguments)` and produces a decision. XNUSandbox’s job is to walk the same structure and reconstruct a human-readable policy.

---

## 3. Policy Lifecycle: From SBPL to Kernel Decisions

Seatbelt policy goes through four conceptual stages. XNUSandbox mostly touches Stage 3 but is easier to understand if you keep all four in mind.

### 3.1 Stage 1: SBPL (Sandbox Profile Language)

Profiles are written in a Scheme-ish DSL:

```scheme
(version 1)
(deny default)

(allow file-read* (subpath "/System"))
(deny  file-read* (literal "/System/secret"))
```

Key points:

* Profiles are almost always **default-deny**: `(deny default)` followed by specific allows.
* Each rule is `(allow|deny [modifiers] OPERATION FILTER...)`.
* Filters and metafilters are expressed in a compact S-expression form.

You do not need to memorize every filter; the “Sandbox DSL Cheatsheet” is your SBPL reference. Treat SBPL as the high-level form you want XNUSandbox to emit.

### 3.2 Stage 2: libsandbox / TinyScheme compilation

`libsandbox.dylib` parses SBPL, expands macros, and lowers policies into an internal representation:

* Assigns numeric IDs to **operations** and **filter keys**.
* Lowers `require-any/all/not` and other structure into explicit decision graphs.
* Compiles regexes into AppleMatch NFAs and stores them in a separate table.
* Produces a **binary profile**: header + operation tables + node array + literal/regex tables.

This is described in detail in “Binary Profile Formats and Policy Graphs”. XNUSandbox usually works with these compiled blobs (from kernelcaches or files), not directly with SBPL.

### 3.3 Stage 3: Kernel install

When a process is sandboxed:

* User space passes the compiled profile to the kernel via sandbox-specific MAC syscalls.
* `Sandbox.kext` stores the policy blob and associated metadata in a sandbox label on the process’s credentials.
* For per-process policies, child processes inherit or derive a policy; for the platform policy, the label is effectively global.

From XNUSandbox’s perspective, what matters is that compiled profiles exist as distinct blobs (or as a bundle of profiles) with stable layouts it can parse.

### 3.4 Stage 4: Runtime evaluation

When a sandboxed process attempts a sensitive operation:

1. The relevant MAC hook in XNU runs.
2. Seatbelt identifies the **operation ID** and extracts relevant **arguments** (path, vnode type, Mach name, IP/port, entitlements, etc.).
3. It evaluates the platform policy:

   * Walks the operation’s rule graph (following filter tests and edges) until reaching a terminal decision.
4. If allowed, and if a per-process policy exists, it evaluates that policy similarly.
5. If all relevant policies allow, the syscall proceeds; otherwise it fails (typically with `EPERM`).

XNUSandbox mirrors the “walk the rule graph” part, but instead of enforcing decisions, it reconstructs SBPL-like rules.

“Binary Profile Formats and Policy Graphs” gives the concrete node layouts; “Policy Stacking and Platform Sandbox” describes how platform and per-process checks combine.

---

## 4. What XNUSandbox Is and Is Not

XNUSandbox is a **user-space decoder**, not an enforcement engine.

Typical responsibilities:

* Read compiled sandbox profiles from:

  * Standalone binary profile files.
  * Kernelcache/OS images where profiles are embedded or bundled.
* Parse:

  * Headers (magic, counts, offsets).
  * Operation pointer tables.
  * Node arrays (decision graphs).
  * Literal and regex tables.
* Reconstruct:

  * Operation names from IDs.
  * Filters from key/value codes and literal/regex indices.
  * Metafilters from graph patterns.
  * Human-readable SBPL or Scheme-like representations of rules.

Things it does not do:

* It does not hook MACF or enforce policies in the kernel.
* It does not model the full **stacked** policy (platform + process + extensions) on a live system; it decodes one profile at a time.
* It does not itself generate platform or TCC decisions; it only shows how profiles are written to do so.

When you see code that evaluates nodes, that evaluation is in service of **printing** or **analyzing** policy, not controlling the system.

---

## 5. Mapping Code Constructs to Seatbelt Concepts

When you open XNUSandbox, your first goal is to orient each major construct in terms of Seatbelt’s model.

### 5.1 Headers and top-level structures

Look for structs that correspond to profile headers:

* Magic/format ID.
* Version fields.
* Counts for:

  * Number of operations.
  * Number of nodes.
  * Number of regexes / literals.
* Offsets to:

  * Operation pointer table.
  * Node array (“operation node actions”).
  * Regex pointers.
  * Literal/regex blob.
  * Per-profile descriptors in bundled formats.

These map directly to the sections described in “Binary Profile Formats and Policy Graphs”.

### 5.2 Operation tables

Find the arrays that map operation IDs to entrypoints:

* In early formats: `op_table[op_id]` giving 16-bit offsets into a handler list.
* In later formats: “Operation Node Pointers” arrays indexed by operation ID.

Tie these to operation names using the mapping described in “Operations and Filters Reference”:

* If you see large enums or string arrays like `file-read*`, `mach-lookup`, `network-outbound`, they belong here.
* Once this mapping is clear, you can reason per-operation rather than per-offset.

### 5.3 Node representations

Identify the node struct or structs:

* Early decision-tree style:

  * Opcode byte: terminal vs non-terminal.
  * For terminals: result code (allow/deny) and flags.
  * For non-terminals: filter type, filter argument, match/unmatch offsets.
* Later graph-style:

  * Node kind / opcode (maybe more nuanced).
  * Filter key ID.
  * Filter value index or encoded argument.
  * One or more successor node indices.
  * Decision/flag fields.

Map these fields onto concepts from:

* “Sandbox DSL Cheatsheet” (filters, metafilters, action modifiers).
* “Operations and Filters Reference” (filter categories and values).

### 5.4 Filters and metafilters

Look for code that:

* Switches on a **filter key** or type.
* Interprets **filter arguments** as:

  * Indices into literal or regex tables.
  * Enums (vnode type, socket type, system attribute).
  * String indices (Mach names, entitlements).
* Traverses node edges differently depending on match vs unmatch.

This code is implementing the logical structure underlying SBPL’s `require-any/all/not`. The patterns that post-processing expects are documented in “Binary Profile Formats and Policy Graphs”; filter vocabulary is in “Operations and Filters Reference” and “Sandbox DSL Cheatsheet”.

### 5.5 Regex and literal handling

Locate:

* The regex pointer table and literal/regex blob.
* Code that:

  * Unpacks regex NFAs.
  * Optionally reconstructs textual regexes.

You do not need to understand AppleMatch in full; it is enough to know that:

* Regexes are stored as NFAs.
* Filters reference them by index.
* XNUSandbox may expose them as `regex #"...pattern..."` in output or as a structured description.

Refer to “Binary Profile Formats and Policy Graphs” for the flow; use “Sandbox DSL Cheatsheet” for how those regexes appear in SBPL.

---

## 6. Version and Layer Context

Seatbelt’s core model is stable, but the formats and policy layers have evolved. You should keep two axes in mind: **format version** and **policy layer**.

### 6.1 Format versions

You will encounter at least two families of formats:

* Early decision-tree format:

  * Simpler header and handler list layout.
  * Explicit opcode for terminal vs non-terminal nodes.
* Later graph-based formats:

  * Operation Node Pointers + consolidated node array.
  * Bundled profiles with shared tables.

XNUSandbox may have separate parsing paths (e.g., `decode_v1` vs `decode_v2`) or format probes. The details are in “Binary Profile Formats and Policy Graphs”. When you modify or extend the tool:

* Always be aware of which format a given function expects.
* Do not assume numeric IDs or header fields are universal across eras.

### 6.2 Policy layer and stacking

Any individual compiled profile belongs to one **layer** of the policy stack:

* Platform profile (global).
* App Sandbox template or similar shared profile.
* Custom per-daemon profile.

The combined runtime behavior is the intersection of:

* Platform profile decisions.
* Process profile decisions (if any).
* Dynamic sandbox extensions.
* Other MAC policies and SIP/TCC behavior.

“Policy Stacking and Platform Sandbox” explains this in detail. When reasoning about behavior or designing probes, never assume a single profile is the whole story.

---

## 7. How an Agent Should Work in This Repo

When you act on this repo as a code agent, follow this workflow:

1. **Classify the artifact.**
   For any file or function, decide whether it deals with:

   * SBPL / Scheme-like text.
   * Compiled binary profile (header, section offsets).
   * Node graph (operation node actions).
   * Regex/literal tables.
   * Operation/filter metadata (mappings to names).
   * Syscall / management code (`set_profile`, `check_sandbox`, etc.).

2. **Anchor on the model, not on raw bytes.**
   For any low-level construct, ask:

   * “Which operation(s) is this about?”
   * “Which filters is it testing?”
   * “How are these filters combined?”
   * “What decision(s) do these nodes lead to?”
     Use the appendix sections to translate between bytes and concepts.

3. **Use the appendix as your reference table.**

   * For SBPL spelling and idioms → “Sandbox DSL Cheatsheet”.
   * For header layouts and node formats → “Binary Profile Formats and Policy Graphs”.
   * For operation/filter vocab and families → “Operations and Filters Reference”.
   * For runtime stacking and context → “Policy Stacking and Platform Sandbox”.

4. **Preserve the separation of concerns.**
   When extending XNUSandbox or adding tests:

   * Keep parsing, graph construction, and SBPL pretty-printing logically distinct.
   * Avoid baking format-specific quirks into higher-level logic where possible.
   * Make explicit which OS/format/version assumptions a given piece of code relies on.

5. **Treat empirical details as version-specific.**
   If you rely on specific operation counts, filter IDs, or header magic values, treat them as tied to concrete OS versions and formats, not as eternal invariants. Document those assumptions in comments and tests.

If you maintain this discipline—model first, format-specific details second—XNUSandbox’s “Just a handful of utilities that have helped me examine the design of the XNU Sandbox.kext and friends.” will read more like an implementation of a known abstract machine than like an opaque reversing artifact.
