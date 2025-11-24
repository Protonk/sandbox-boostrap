# AGENTS.md — Seatbelt Knowledge Substrate

This file is a **conceptual router and use guide** for the local Seatbelt/XNUSandbox knowledge pack:

- `Orientation.md`
- `Concepts.md`
- `Appendix.md`
- `Canon.md`
- `ERRATA.md`

It is written for three broad classes of agents:

- Human investigators
- Code agents (e.g., Codex in repo mode, analysis tools)
- Chat agents (5.1 Thinking-style interpreters)

All of you should treat these documents as the **foundational universe** of information for Seatbelt in this context. External sources exist, but they are mediated via `Canon.md` and consulted explicitly, not implicitly.

---

## 1. Purpose and Scope

This substrate is not a full sandbox textbook. It is a **curated interface** to Seatbelt as used in the XNUSandbox project:

- It defines a **shared vocabulary** (operations, filters, profiles, stacks).
- It fixes a **model** of how SBPL and compiled profiles work.
- It encodes **assumptions and caveats** that agents must not silently override.
- It names the **external canon** that may be used later, and how.

If you are an agent acting in or around the XNUSandbox ecosystem, your first responsibility is to **align your mental model** to these documents before you propose changes, generate probes, or interpret profiles.

---

## 2. Document Map: What Each File Is For

### 2.1 `Orientation.md` — Quick Start and Mental Model

**Role**

- The “landing pad” for new agents.
- Describes what Seatbelt is, in this repo’s model:
  - TrustedBSD MAC policy module in XNU.
  - SBPL in userland, compiled to binary profiles.
  - Kernel-level decision graph evaluation per operation.
- Explains what XNUSandbox is supposed to do and what it is not:
  - Decode, analyse, and pretty-print policies.
  - Not enforce them, not emulate full macOS.

**Use this file when**

- You need to answer: “What problem is this project solving?”
- You are unsure how operations, filters, and decisions fit together.
- You are about to add new code that interprets or serializes profiles.

**Good tasks anchored on Orientation**

- Derive the **high-level architecture** of Seatbelt+XNUSandbox.
- Outline the **data-flow** from SBPL text → compiled graph → kernel decision → XNUSandbox decoder.
- Decide whether a new feature belongs in parsing, graph interpretation, or pretty-printing.

**Key invariant**

> Orientation defines the **top-level model**. If other documents or observations appear to contradict it, treat that as “drift to be explained” (see `ERRATA.md` / `Canon.md`), not as permission to silently change the model.

---

### 2.2 `Concepts.md` — Glossary and Abstract Schema

**Role**

- The **vocabulary and schema** for the Seatbelt world-view.
- Defines the main concepts used across code and documents:
  - SBPL profile, operation, filter, metafilter, decision.
  - Policy stack, platform vs process profiles.
  - Profile format variants (tree vs graph), literal/regex tables.
  - Operation/filter vocabulary maps.

**Use this file when**

- You are naming a new type, function, or module.
- You see a term in code or output and are unsure what it means.
- You are designing data structures for profiles, operations, or filters.

**Good tasks anchored on Concepts**

- Map C/Rust structs to conceptual entities:
  - “This struct is a profile header; this one is a node; this one is a vocabulary entry.”
- Align JSON/YAML schemas (e.g., capability catalog) with the concepts:
  - “This field is a decision; this one is a filter key; this one is a literal index.”
- Ensure new diagnostics or logs use **canonical terminology**.

**Key invariant**

> Concepts is the **source of naming truth**. Code and output should prefer these terms and definitions. If you must invent a new term, explain it in relation to `Concepts.md`.

---

### 2.3 `Appendix.md` — DSL Cheatsheet and Binary Reference

**Role**

- The **reference deck**:
  - SBPL/DSL syntax and patterns (“Sandbox DSL Cheatsheet”).
  - Binary profile formats and decision graphs.
  - Operations and filters reference (vocabulary mapping).
  - Policy stacking, platform sandbox, and extensions.

Think of this as the “standards doc” for how to parse and render things.

**Use this file when**

- You need to:
  - Parse or print SBPL rules.
  - Decode or encode binary profile headers, node arrays, and tables.
  - Understand what a given operation or filter key *means*.
  - Reason about how multiple policies stack (platform + per-process + extensions).

**Good tasks anchored on Appendix**

- Implement or modify the **binary parser** or **graph builder**.
- Implement or refine **SBPL pretty-printing** for decoded graphs.
- Cross-check operation and filter semantics for the capabilities catalog.
- Design probe programs that exercise specific SBPL patterns (e.g., `require-any`, `with report`, specific path filters).

**Key invariants**

- Parsing and binary layout details come from the Appendix; do not guess.
- Separation of concerns:
  - Appendix supports clear separation between:
    - Byte-level formats
    - Graph-level semantics
    - Textual SBPL surface.

Agents should preserve this three-layer structure.

---

### 2.4 `Canon.md` — External Sources and How to Use Them

**Role**

- A **registry of external, time-stamped sources**:
  - `BLAZAKIS2011`, `ROWESANDBOXING`, `APPLESANDBOXGUIDE`, `SANDBLASTER2016`, `STATEOFSANDBOX2019`, `HACKTRICKSSANDBOX`, `WORMSLOOK2024`, etc.
- For each, it encodes:
  - Scope (structure vs behaviour vs ecosystem vs exploitation).
  - Why it matters in this project.
  - Typical queries you should send to it.

**Use this file when**

- You are allowed to bring in non-local knowledge and need to:
  - Check structural claims (formats, hooks, SBPL semantics).
  - Investigate drift and modern behaviour.
  - Generate probe ideas based on historical bypasses or real-world app behaviour.

**Good tasks anchored on Canon**

- Choose **which external document to re-read** in detail for a specific question.
  - “I want binary format details” → `BLAZAKIS2011` or `SANDBLASTER2016`.
  - “I want real-world entitlement usage” → `STATEOFSANDBOX2019`.
  - “I want modern drift probes” → `WORMSLOOK2024`.
- Frame Deep Research / exegesis prompts that:
  - Take a canon source as anchor.
  - Carefully mesh it with the local model.

**Important boundary**

> When working under a “local-only” epistemic stance, `Canon.md` is *descriptive*, not executable: you may discuss what it says about the sources as text, but you must not import new facts from those sources unless explicitly permitted.

---

### 2.5 `ERRATA.md` — Drift, Pitfalls, and Corrections

**Role**

- A running log of **places where hands-on macOS behaviour** diverges from Orientation/Appendix framing:
  - API availability (`sandbox_apply`, `sandbox-exec` usage).
  - Actual locations of profiles / formats on modern systems.
  - Subtle differences in how extensions, parameters, or regex engines behave.

**Use this file when**

- You find a discrepancy between:
  - The conceptual model (Orientation/Concepts/Appendix), and
  - Actual behaviour observed on a specific macOS version.
- You plan to modify code that depends on version-sensitive details.

**Good tasks anchored on Errata**

- Confirm whether an odd behaviour is already known:
  - “Is this `EPERM` from `sandbox_apply` expected?”
- Annotate code paths with “this relies on a known divergence; see ERRATA entry X”.
- Decide whether to:
  - Update Orientation/Appendix, or
  - Treat a divergence as version-specific behaviour that should be documented but not folded into the general model.

**Key invariant**

> Errata does not replace the model; it **pins** deviations and nuances to specific contexts (OS versions, APIs, tools). Treat it as a list of “known sharp edges”.

---

## 3. Agent Roles and Contracts

This section defines **typical roles** and how they should traverse the documents.

### 3.1 Human Investigator

**Role**

- Understand Seatbelt and XNUSandbox deeply.
- Design experiments, read code, and make decisions about architecture.

**Traversal pattern (suggested)**

1. Read `Orientation.md` straight through.
2. Skim `Concepts.md` once; then keep it open as a glossary.
3. Use `Appendix.md` as a reference when:
   - Reading or writing binary decoding code.
   - Reading SBPL text or designing example profiles.
4. When subtle questions arise:
   - Check `ERRATA.md` for known divergences.
   - Consult `Canon.md` to pick external sources for deeper study (if allowed).

**Contract**

- Do not silently overwrite the conceptual model with “Random blog post X”.
- When you discover new behaviour, record it as **proposed errata** and/or annotate the canon usage, not as a quiet change in what words mean.

---

### 3.2 Code Agent — Decoder / Parser

**Role**

- Implement and maintain code that:
  - Parses binary profiles into structured graphs.
  - Maps node-level structures to operations/filters/decisions.
  - Pretty-prints or exports them.

**Primary documents**

- `Appendix.md` (formats, graphs, vocab).
- `Concepts.md` (schema and naming).
- `Orientation.md` (overall architecture and scope).

**Key behaviours**

- Keep **parsing**, **graph interpretation**, and **pretty-printing** clearly separated in the codebase, mirroring the conceptual layers in Appendix/Concepts.
- Use canonical names from `Concepts.md` for types and functions where possible.
- Use the operations/filters mapping defined in the Appendix to name things; do not invent new semantics for existing IDs.

**When stuck**

- If a layout detail is unclear → re-read the relevant “Binary Profile Formats and Policy Graphs” section in `Appendix.md`.
- If semantics of an operation/filter are unclear:
  - First, check the operations/filters reference in `Appendix.md`.
  - Only then, if explicitly allowed, look up the relevant canon source (e.g., Apple Sandbox Guide) via `Canon.md`.

---

### 3.3 Code Agent — Capability Catalog / Probe Generator

**Role**

- Maintain a structured capability catalog.
- Generate probes that test specific operations/filters/stacking behaviour.

**Primary documents**

- `Concepts.md` (for capability categories and schema alignment).
- `Appendix.md` (for SBPL/DSL shapes and operation/filter semantics).
- `Canon.md` (for identifying interesting operations and drift areas).
- `ERRATA.md` (for known discrepancies on modern OS versions).

**Key behaviours**

- Align catalog entries and probe names to the **operations and filters** in Appendix/Concepts.
- Use DSL patterns from `Appendix.md` (e.g., `require-any`, `subpath`, `container-subpath`, `with report`) as templates for probes.
- Use `Canon.md` to pick high-value areas for probing (e.g., from `WORMSLOOK2024`, `HACKTRICKSSANDBOX`), but only when external consultation is permitted.

**When subtle behaviour appears**

- Record interpretations as:
  - Updates to the capability catalog, referencing the relevant concept/operation/filter.
  - Candidate entries for `ERRATA.md` if they reflect OS-specific divergences.

---

### 3.4 Chat Agent — Local Exegesis (5.1 Thinking-style)

**Role**

- Read and interpret the local documents.
- Answer questions about Seatbelt and XNUSandbox **using only this substrate**, unless explicitly granted access to external canon.

**Primary documents**

- `Orientation.md` for overall story.
- `Concepts.md` for terminology.
- `Appendix.md` for concrete details and examples.
- `ERRATA.md` and `Canon.md` only when the user explicitly asks about drift or external sources.

**Epistemic stance (default)**

- Treat these documents as the **only ground truth**.
- If something is not in them, say so explicitly.
- When asked to speculate or “use intuition”, clearly mark any inference and keep it local.

**When external knowledge is allowed**

- Use `Canon.md` as the **only entry point**:
  - Choose appropriate external sources.
  - Make it clear which canon source supports which statement.
- Do not blend external knowledge back into these documents silently; treat external facts as layered on top of the local model.

---

## 4. Traversal Recipes

This section gives **concrete routes** through the substrate for common situations.

### 4.1 “I just landed in this repo; what is going on?”

1. Read `Orientation.md`.
2. Skim `Concepts.md` to learn the vocabulary.
3. Scan `Appendix.md` to see that:
   - There is a DSL cheat sheet.
   - There is a binary format/graph section.
   - There is an operations/filters reference.
4. Remember that:
   - `Canon.md` exists to guide external reading.
   - `ERRATA.md` exists to explain divergences you may see later.

### 4.2 “I need to decode a compiled profile.”

1. From `Concepts.md`, confirm:
   - What a compiled profile is.
   - What nodes, operations, filters, and decisions are.
2. From `Appendix.md`, read the relevant:
   - Binary format description.
   - Graph navigation description.
   - Operation/filter vocab mapping.
3. Implement / inspect code that:
   - Reads header → operation tables → nodes → literal/regex tables.
   - Builds an internal decision graph.
   - Pretty-prints to SBPL-like text using DSL patterns from the cheatsheet.

### 4.3 “I suspect a behaviour drift on macOS N.”

1. Re-check Orientation/Concepts/Appendix to ensure:
   - You understand the model you are comparing against.
2. Check `ERRATA.md`:
   - See if the behaviour is already logged.
3. If external consultation is allowed:
   - Use `Canon.md` to pick appropriate sources (e.g., `WORMSLOOK2024` for modern drift, `STATEOFSANDBOX2019` for ecosystem behaviour).
4. Record your findings:
   - As a new or updated entry in `ERRATA.md` and/or catalog.
   - Without silently rewriting `Concepts.md` or `Orientation.md` unless the underlying model is genuinely wrong.

---

## 5. Invariants and Boundaries for All Agents

- **Shared vocabulary**  
  Use terms from `Concepts.md`. Avoid inventing synonyms for core entities (operation, filter, profile, policy stack, decision).

- **Layered knowledge**  
  - Orientation → Concepts → Appendix form the core conceptual/binary layer.
  - Canon adds external perspectives.
  - Errata pins OS-specific deviations.

- **No silent drift**  
  When you learn something new that conflicts with the current model:
  - Do not retroactively change what words mean.
  - Instead, propose updates in:
    - `ERRATA.md` (for version-specific quirks), and/or
    - A future revision of Orientation/Appendix/Concepts, with clear justification.

- **Separation of concerns in code and text**
  - Binary parsing ≠ graph semantics ≠ SBPL pretty-printing.
  - External research ≠ local model.
  - Capability catalog ≠ raw decoding.

If all agents respect this routing and these boundaries, the documents in this pack remain a **stable, shared substrate** that humans, code, and chat systems can all rely on when reasoning about the macOS Seatbelt sandbox.
