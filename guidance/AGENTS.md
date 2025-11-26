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

> Orientation defines the **top-level model**. Detail and caveats are found in other files.

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

> Concepts is the **source of naming truth**. Code and output should prefer these terms and definitions.

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

- You are mediating a conflict between claims in sources and you need to:
  - Check structural claims (formats, hooks, SBPL semantics).
  - Investigate drift and modern behaviour.
  - Understand where knowledge may be limited

**Good tasks anchored on Canon**

- Choose **which source to re-read** in detail for a specific question.
  - “I want binary format details” → `BLAZAKIS2011` or `SANDBLASTER2016`.
  - “I want real-world entitlement usage” → `STATEOFSANDBOX2019`.
  - “I want modern drift probes” → `WORMSLOOK2024`.

---

### 2.5 `State2025.md` — Contemporary macOS Seatbelt Snapshot

**Role**

- Summarizes what the macOS sandbox ecosystem actually looks like circa 2024–2025 (who is sandboxed, how containers/extensions are wired up, how secinit/containermanagerd/TCC fit together).
- Separates **stable invariants** from **high-churn surfaces** to guide probe design and threat modeling.
- Bridges older canon to modern behavior so authors can cite “current state” without re-deriving it each time.

**Use this file when**

- You need to answer “What does Seatbelt do on current macOS releases?” for code, probes, or narrative text.
- You are choosing which parts of the stack to measure (containers, entitlement usage, extension issuance, TCC interactions).
- You are summarizing drift or continuity between historical documentation and present-day macOS.

**Good tasks anchored on State2025**

- Plan probes or experiments that validate modern behavior (secinit decisions, containermanagerd container setup, sandbox extensions).
- Align code/tests with today’s defaults and deployment patterns (App Store vs third-party, sandboxed vs unsandboxed).
- Write short “state of the world” paragraphs for chapters or reports without re-reading every source.

**Key invariant**

> Treat `State2025.md` as the best-effort **snapshot** of current behavior.

---

### 2.6 `sources/`: Directory of information on canon sources

A directory of close-reading summaries of sources by SHORTNAME, e.g. `APPLESANDBOXGUIDE.md`. Original sources ***are not checked in to the repo***--these interpretations form our universe of information, not the pdfs.

---

## 3. Invariants and Boundaries for All Agents

- **Shared vocabulary**  
  Use terms from `Concepts.md`. Avoid inventing synonyms for core entities (operation, filter, profile, policy stack, decision).

- **Layered knowledge**  
  - Orientation → Concepts → Appendix form the core conceptual/binary layer.

- **Separation of concerns in code and text**
  - Binary parsing ≠ graph semantics ≠ SBPL pretty-printing.

If all agents respect this routing and these boundaries, the documents in this pack remain a **stable, shared substrate** that humans, code, and chat systems can all rely on when reasoning about the macOS Seatbelt sandbox.
