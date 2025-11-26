# AGENTS

This file tells you how to use `substrate/`. It exists to route you to the right substrate text for a given question, not to tell you how to write the textbook or how to build tools.

`substrate/` is the stable textual base for a synthetic textbook on the macOS “Seatbelt” sandbox, circa 2025. Treat it as:

* The place where we say what we believe is true about Seatbelt and its surrounding ecosystem.
* The reference layer that other tools, deep-research reports, and probes are allowed to disagree with, but never silently override.

Treat the contents of `substrate/` as frozen. You consult it; you do not update it or extend it.

---

## 1. What this directory is (and is not)

* It is a snapshot of the project’s understanding of the macOS sandbox around 2025:

  * Concepts and how they hang together.
  * The structural environment assumed by most examples and probes.
  * A specific view of the ecosystem (“who is sandboxed, how, and why”).
  * A small amount of detailed supporting material and a curated canon.

* It is not:

  * A public appendix for the eventual textbook reader.
  * A place you cite from or link into in user-facing text by default.
  * A living glossary or wiki.

You work elsewhere in the repo. This directory is the internal reference you read first when you need to know “what did we previously decide about X?”

---

## 2. Router: which file to consult for which question

Use this section as your primary decision tree.

### High-level framing and mental model → `Orientation.md`

Go here when your question is:

* “What is the overall story we’re telling about Seatbelt?”
* “How do profiles, entitlements, containers, and the surrounding mechanisms fit together conceptually?”
* “What kinds of misconceptions are we trying to manage or avoid at the story level?”

Use it to set your own mental model before you draft chapters, examples, or research prompts.

---

### Definitions, distinctions, and vocabulary → `Concepts.md`

Go here when your question is:

* “What does this project mean by ‘operation’, ‘filter’, ‘entitlement’, ‘policy graph’, etc.?”
* “How are similar terms distinguished (e.g., profile vs policy vs capability)?”
* “What evidence, sources, or behaviors constrain this concept?”

In practice:

* Terms from `Concepts.md` should mean exactly what is written there. 
* Treat concepts as hypotheses about behavior that someone has already argued for, not as labels you are free to redefine on the fly.

---

### Structural environment and invariants → `Environment.md`

Go here when your question is:

* “What OS versions, hardware, and surrounding security mechanisms is the substrate assuming?”
* “How are containers laid out, roughly?”
* “How does Seatbelt sit next to things like TCC, hardened runtime, SIP, and code signing at the mechanism level?”

Use it to:

* Keep your own work anchored in the same assumed world & notice when you are deliberately stepping outside that world (older macOS, iOS, hypothetical designs) and need to say so in your own artifacts.

---

### Real-world usage and ecosystem snapshot → `State.md`

Go here when your question is:

* “Around 2025, who is actually sandboxed on macOS and how?”
* “How does Seatbelt fit into the broader security posture in practice, not just on paper?”
* “What adoption patterns, threat models, and failure modes were we assuming when we froze this edition?”

Use it to:

* Ground case studies, risk discussions, and “why this matters” sections in how the system was actually used at the time.
* Detect when your later evidence is describing a different world (new OS versions, changed ecosystem, new classes of apps).

---

### Detailed tables, cheatsheets, and mini-essays → `Appendix.md`

Go here when your question is:

* “Is there a quick list or cheatsheet for operations, filters, or common profile constructs?”
* “Is there a short technical note on this specific mechanism or edge case?”
* “Is there a small, focused explanation that was too heavy to live in the main scaffold?”

Use it when you need concrete detail to sharpen your understanding. You typically translate what you learn here into fresh, reader-appropriate material elsewhere rather than copying directly.

---

### Where the substrate’s claims come from → `Canon.md`

Go here when your question is:

* “Which external sources underwrite these claims about Seatbelt?”
* “Which documents are considered primary for architecture, SBPL, binary profiles, containers, or empirical usage?”
* “If I had to read only a few external things to understand the substrate, what are they?”

Use it to choose what to read next or to understand why the substrate leans the way it does on disputed points. You add new sources to your own artifacts; you do not extend the canon list here.

---

## 3. How to “use” the substrate without extending it

Given the freeze and the fact that this layer is not meant to be surfaced directly to readers:

* Use the substrate to calibrate yourself, not to decorate your output.

  * Read what it says about a concept or mechanism.
  * Internalize the stance and evidence.
  * Then write your chapter, design your experiment, or sketch your example in a way that is self-contained.

* When your work diverges from the substrate:

  * Acknowledge the earlier stance in your own artifact in whatever way your prompt or harness expects.
  * Treat the substrate as the baseline you are updating from, not something you rewrite or reconcile.

* When you need new structure (new concepts, new environment distinctions, new “state” snapshots):

  * Define them and justify them where you are working.
  * Do not attempt to retrofit them into `substrate/`. The substrate remains the “first edition”; you are now working on later commentary and extensions.

---