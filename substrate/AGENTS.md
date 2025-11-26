# AGENTS

`substrate/` is the stable textual base for a synthetic textbook on the macOS “Seatbelt” sandbox, circa 2025. It is
* The place where we say what we believe is true about Seatbelt and its surrounding ecosystem.
* The reference layer that other tools, deep-research reports, and probes are allowed to disagree with, but never silently override.

## 1. What this directory is not

The substrate is meant to support, not decorate the work of the output. Write your chapter, design your experiment, or sketch your example such that if `substrate/` were not packaged with the textbook there would be no information loss. It is not:
* A public appendix for the eventual textbook reader. All important detail you glean from the substrate must eventually pass to the textbook. Do not cite from or link to the substrate in any place in `book/`.
* A living document. Content marked "`>SUBSTRATE_2025-frozen`" is frozen. You should not update it unless explicitly directed to work in the `substrate/` directory.

---

## 2. Router: which file to consult for which question

Use this section as your primary decision tree.

### High-level framing and mental model → `Orientation.md`

Go here when your question is:

* “What is the overall story we’re telling about Seatbelt?”
* “How do profiles, entitlements, containers, and the surrounding mechanisms fit together conceptually?”
* “What kinds of misconceptions are we trying to manage or avoid at the story level?”

Use it to set your own mental model of the sandbox.

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

### Per-source exegesis and evidence → `exegesis/`

Go here when your question is:

* “How does the substrate interpret this particular canonical source (BLAZAKIS2011, APPLESANDBOXGUIDE, STATEOFSANDBOX2019, etc.)?”
* “What concrete landmarks, symbols, or behaviours does a given paper or guide provide?”
* “Which parts of a source are treated as architectural ground truth vs speculative or time-limited observations?”

Use it to:

* Follow how external texts are read into the substrate’s worldview and which passages support specific claims.
* Anchor new probes or examples in the same landmarks when you want to stay aligned with the canon without rereading full papers every time.

---
