# AGENTS.md — Seatbelt Knowledge Substrate

This file is a **conceptual router and use guide** for this directory, written for three broad classes of agents, machine or not:

- Code Agents: Primarily interested in writing code to test and expand understanding of the sandbox and validate foundations.
- Chapter Authors: Primarily interested in presenting generated understanding to readers of all documentation but especially the work product in `book/`
- Readers: Interested in retreival, understanding, and interrogation. 

All but the last should treat these documents as the **foundational universe** of information for Seatbelt in this context. External sources exist, but they are mediated via `Canon.md` and consulted explicitly, not implicitly.

---

## 1. Purpose and Scope

This substrate is not a full sandbox textbook. It is a **curated interface** to Seatbelt as used in the mac OS sandbox project:

- It defines a **shared vocabulary** (operations, filters, profiles, stacks).
- It fixes a **model** of how SBPL and compiled profiles work.
- It encodes **assumptions and caveats** that agents must not silently override.
- It names the **external canon** that may be used later, and how.

If you are a Code Agent or a Chapter Author, your first responsibility is to **align your mental model** to these documents before you propose changes, generate probes, or interpret profiles.

---

## 2. Document Map: What Each File Is For

### 2.1 `Orientation.md` — Quick Start and Mental Model

**Role**

- The “landing pad” for new agents.
- Describes what Seatbelt is, in this repo’s model:
  - TrustedBSD MAC policy module in XNU.
  - SBPL in userland, compiled to binary profiles.
  - Kernel-level decision graph evaluation per operation.
- Explains what mac OS sandbox is supposed to do and what it is not:
  - Decode, analyse, and pretty-print policies.
  - Not enforce them, not emulate full macOS.

**Use this file when**

- You need to answer: “What problem is this project solving?”
- You are unsure how operations, filters, and decisions fit together.
- You are about to add new code that interprets or serializes profiles.

**Good tasks anchored on Orientation**

- Derive the **high-level architecture** of Seatbelt+mac OS sandbox.
- Outline the **data-flow** from SBPL text → compiled graph → kernel decision → mac OS sandbox decoder.
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

### 2.6 `sources/`: Directory of information on canon sources

A directory of subdirectories with the short name of a source, e.g. `sources/BLAZAKIS2011/`. Each of these contain one or more markdown documents written by a chat agent pointed at the source. The original sources ***are not checked in to the repo***--these interpretations are what form our universe of information, not the pdfs.

### 2.7 `reports/`: Reports from research agents

Contains one or more `.md` files with reports from research runs.

## 3. Agent Roles

This section suggests **typical roles** for working with the knowledge substrate. Real workflows may blend roles, but you should adopt one primary stance per task.

### 3.1 Chapter Author

- Uses this substrate as the primary source of truth when drafting or revising explanatory text (especially in `book/`).
- Focuses on coherence, traceability, and explicit scope: what is established, what is tentative, and what is out of scope.
- Flags gaps, tensions, or contradictions as issues or marginalia instead of silently “fixing” the underlying model.

### 3.2 Code Agent

- Treats this substrate as the specification for experiments, probes, and tooling that touch the sandbox.
- Uses the shared vocabulary and model here when naming operations, filters, behaviours, and test cases.
- Proposes changes only after reconciling discrepancies between observed behaviour and the documented model, feeding back minimal notes when new edge cases are discovered.

---

## 4. Invariants and Boundaries for All Agents

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
