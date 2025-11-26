# Spine README

This directory contains the “spine” documents for the sandbox textbook substrate. They are short, durable summaries meant to be included at the top of prompts so that chat models share the same map of the corpus and the same invariants when they answer questions or generate new text.

The spine is intentionally compact: it should be safe to prepend to many prompts (for you or for agents) without overwhelming the model.

---

## Files

* `INDEX.md`
  High-level map of the substrate: what’s in it, where it lives, and how the pieces relate. Think “table of contents + rough topology,” not a catalog of every file.

* `INVARIANTS.md`
  Cross-document facts and constraints that should be treated as stable unless explicitly overridden. This is the “do not contradict these unless you have extremely strong evidence” layer.

* `GROUNDING.md`
  How to treat the substrate as ground truth: what “grounded” means here, how to prefer empirical evidence over speculation, and how to resolve conflicts between sources.

If additional spine documents appear later, they should be similarly short and play a clearly defined role (e.g., a state-of-the-world snapshot for a specific year).

---

## How to use the spine to prime a model

In most workflows, spine docs are not something the model is asked to edit. They are part of the context you hand to the model so that downstream tasks are consistently framed.

A simple pattern:

1. Prepend the spine (or the relevant parts of it) to the system message or “background” section of your prompt.
2. Follow with any task-specific instructions.
3. Only then include the local files or excerpts you want the model to work with.

In pseudocode:

```text
SYSTEM:
  [contents of INDEX.md]
  [contents of INVARIANTS.md]
  [contents of GROUNDING.md]

  [task-specific instructions here]

USER:
  [local excerpts / question / code / etc.]
```

You can selectively drop `INDEX.md` or `GROUNDING.md` for very small tasks, but `INVARIANTS.md` is usually worth including whenever you care about conceptual consistency across runs or agents.

---

## Example 1: Using only invariants

Use this pattern when:

* The task is small and conceptual (definitions, short explanations, minor rewrites).
* You want answers aligned with the project’s fixed vocabulary and mental model.
* You do not need the model to roam the substrate or reference specific files.

For example, to ask for a short explanation of a concept that must respect your core definitions:

```text
SYSTEM:
  [contents of INVARIANTS.md]

  You are helping to write a synthetic textbook on the macOS sandbox.
  Follow the definitions and constraints in the invariants text above.
  If you are unsure, prefer not to speculate.

USER:
  Write a concise definition of “sandbox profile” consistent with the invariants.
  Keep it to 3–4 sentences and do not reference specific papers or tools by name.
```

Here:

* `INVARIANTS.md` supplies the canonical meaning of “sandbox profile,” operations, filters, etc.
* The model does not need to know where those concepts appear in the substrate; it just needs to not drift.

This is a good default for “small, local” textbook tasks: polishing a paragraph, tightening a definition, or checking a short explanation for consistency.

---

## Example 2: Priming a model to mine the substrate

Use the full spine when:

* The question is hard or synthetic (e.g., “compare behavior across macOS releases”).
* The answer should be grounded in specific substrate files.
* You want the model to use `INDEX.md` as a map and `GROUNDING.md` as rules of engagement.

Example prompt template for a “Thinking” / analysis model:

```text
SYSTEM:
  [contents of INDEX.md]
  [contents of INVARIANTS.md]
  [contents of GROUNDING.md]

  You are reading a frozen documentation substrate about the macOS sandbox.
  Use INDEX.md to locate relevant files.
  Treat INVARIANTS.md as constraints that should not be casually violated.
  Follow GROUNDING.md when deciding what counts as evidence and how to handle conflicts.

  Your job:
  1. Identify which substrate files are most relevant.
  2. Synthesize an answer that is explicitly grounded in them.
  3. If sources disagree, describe the disagreement and reason about it without inventing new facts.

USER:
  Using the substrate, explain how macOS app sandbox initialization differs from iOS:
  - Who decides that a process should be sandboxed?
  - How containers are created and associated with processes.
  - How entitlements interact with profiles in each platform.
  Focus on behavior around macOS 14 / iOS 17 as described in the substrate.
```

In this pattern:

* `INDEX.md` lets the model propose “I should look at X, Y, Z” instead of hallucinating new documents.
* `INVARIANTS.md` prevents it from “explaining” the sandbox in ways that contradict your fixed conceptual scaffold.
* `GROUNDING.md` discourages it from speculating beyond what the substrate supports and gives it a conflict-resolution policy.

This template is a good starting point for Deep-Research-style runs over just the local substrate, or for a “reader” agent whose job is to produce reports that you or other agents will later mine for textbook prose.

---

## Example 3: Splitting work across disconnected agents

The spine is also the shared “handoff” context between agents that never see each other’s conversations. A common pattern is:

* A **planner** or “Thinking” agent that reasons over the spine and the index, and emits a plan or intermediate artifact.
* A **coder** or “Codex” agent that only sees concrete file paths and instructions and is tasked with edits or extractions.

Example: planner → coder workflow

1. Planner prompt:

   ```text
   SYSTEM:
     [contents of INDEX.md]
     [contents of INVARIANTS.md]
     [contents of GROUNDING.md]

     You are designing a small refactor task for a code-editing agent that
     will not see this spine. Your job is to:
     - Use INDEX.md to identify which files describe sandbox profiles and operations.
     - Use INVARIANTS.md to decide what must remain true after edits.
     - Use GROUNDING.md to avoid asking for changes that contradict the substrate.

     Output:
     - A short natural-language plan.
     - A precise list of file paths and edits for a code agent to apply.

   USER:
     We want a single, clearer example SBPL profile that matches our invariants
     about operations and filters. Identify the best existing example in the substrate
     and propose edits that make it more didactic without changing semantics.
   ```

2. Coder (Codex) prompt, which uses only the planner’s output (no spine):

   ```text
   SYSTEM:
     You are a code-editing assistant. Apply the following plan exactly.
     Do not alter files beyond what is described.

   USER:
     [planner’s plan here: file paths + concrete edit instructions]
   ```

The spine never reaches the coder agent directly, but it shapes the plan the planner produces. This is the main pattern for mixed chat/Codex workflows: treat the spine as the stable “constitution” for planner/reader agents, and have them pass only specific, low-level instructions to editing agents.

---

## When and how to extend the spine

You should almost never need to edit these files, with the exception of `INVARIANTS.md`. Edit `INVARIANTS.md` only when you have new, well-supported cross-document facts or need to correct a real error.

