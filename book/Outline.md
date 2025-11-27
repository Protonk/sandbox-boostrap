**Chapter 1 — Introduction**

This chapter explains what the macOS sandbox is for, why it matters, and what this book is trying to do about it.

* **1.1 Why sandboxes exist** — Briefly situates the sandbox in macOS’s security story: isolation, least privilege, and damage containment.
* **1.2 Why the macOS sandbox feels opaque** — Describes why the sandbox is hard to see directly (hidden profiles, entitlements, containers) and how that shapes what users and developers experience.
* **1.3 What this book assumes about you** — States the expected background (Unix, macOS, some security) and what you do not need to know in advance.
* **1.4 How to read this book** — Suggests ways to navigate: following the TextEdit walkthrough, dipping into reference chapters, or using it as a lab manual.
The chapter closes by setting expectations: we will treat the sandbox as both a formal system and a piece of fallible, evolving software.

---

**Chapter 2 — Methods: How We Learned What We Claim**

This chapter explains how sandbox ideas in the book were treated as empirical claims and checked against running systems.

* **2.1 From informal ideas to testable claims** — Shows how high-level notions (“file read operation”, “platform profile”) are turned into precise questions about observable behaviour.
* **2.2 Probes, experiments, and boundary objects** — Describes the basic experimental pattern: small programs or profiles that exercise a single idea and record concrete outcomes.
* **2.3 What worked cleanly and what did not** — Classifies results into confirmed behaviours, refinements, dead ends, and areas where the system remains ambiguous.
* **2.4 Evidence levels and how to read them** — Introduces simple markers for later chapters (empirically anchored, literature-based, model-only) and what confidence each should convey.
The chapter ends by inviting the reader to treat later claims as hypotheses they can rerun, not as immutable facts.

---

**Chapter 3 — TextEdit.app: A Worked Sandbox Example**

This chapter uses the built-in TextEdit.app as a concrete case study of how a real macOS app is sandboxed.

* **3.1 What TextEdit is allowed to do** — Surveys its visible capabilities (opening documents, accessing recent files, using iCloud) as a starting point for sandbox expectations.
* **3.2 Profiles, containers, and entitlements in practice** — Walks through the main components that constrain TextEdit: its app sandbox profile, its container directories, and its entitlements.
* **3.3 Tracing real operations through the sandbox** — Follows concrete actions (opening a file, auto-saving, accessing fonts) through sandbox decisions to connect behaviour with rules.
* **3.4 What TextEdit shows us about the broader system** — Extracts general lessons from the example: typical patterns, surprising limitations, and where system-wide policy leaks through.
The chapter closes by summarizing TextEdit as a template for reading other apps’ sandboxes and for grounding the more abstract chapters that follow.

---

**Chapter 4 — Seatbelt Orientation and Policy Lifecycle**

This chapter describes how sandbox policy flows from source definitions into the kernel and back out as allow/deny decisions.

* **4.1 Where sandbox policy lives in macOS** — Locates the main components: the kernel extension, user-space helpers, on-disk profiles, and per-process state.
* **4.2 From profile text to compiled policy** — Outlines the pipeline that turns human-readable policy into internal data structures suitable for fast decision-making.
* **4.3 How profiles are installed, stacked, and applied** — Explains how different profiles (platform, app, service) combine and how they get attached to specific processes.
* **4.4 How a single sandbox decision is made** — Follows a typical system call through the evaluator, showing how operations, filters, and actions produce a final result.
The chapter ends by presenting this lifecycle as the backbone that later chapters will keep returning to, regardless of which part of the sandbox they examine.

---

**Chapter 5 — Vocabulary and the SBPL / DSL Surface**

This chapter introduces the working language used to describe and author sandbox policy on macOS.

* **5.1 Profiles, operations, and actions** — Defines the core building blocks: profiles as units of policy, operations as named kinds of behaviour, and actions as what the sandbox does in response.
* **5.2 Filters, arguments, and conditions** — Explains how operations are refined by predicates on things like paths, network endpoints, and Mach resources.
* **5.3 Metafilters and policy structure** — Describes constructs that combine conditions (any/all/not) and how they shape the logical structure of rules.
* **5.4 Stacks, containers, and extensions as policy context** — Introduces the idea that profiles run in layers and are influenced by containers and ad hoc sandbox extensions.
The chapter concludes by positioning this vocabulary and DSL as the shared language for the rest of the book, and as the minimum needed to read and reason about real policies.

---

**Chapter 6 — A Small App in a Big Sandbox**

This chapter introduces a tiny, purpose-built app and uses it to show how the same code behaves under different sandbox configurations.

* **6.1 Why build our own example app** — Explains why a controlled, open example complements TextEdit: we can choose its behaviours, profiles, and entitlements, and use them as a repeatable lab for the rest of the book.
* **6.2 The app’s behaviours and what they exercise** — Describes the app’s concrete actions (filesystem, network, IPC, TCC-adjacent) and connects each one to the operations and filters introduced in earlier chapters.
* **6.3 One app, many sandboxes** — Walks through running the app as unsandboxed, as a minimally sandboxed App Sandbox app, with additional entitlements, and under custom sandbox(7) profiles, showing how each incarnation changes what it can do.
* **6.4 Reading profiles, labels, and capability catalogs from the example** — Uses the app’s profiles and traces to illustrate compiled policy graphs, profile layers, sandbox extensions, and how they roll up into capability catalog entries.
The chapter closes by positioning this small app as a standing testbed that other chapters can reuse when they dig deeper into binary formats, system profiles, and ecosystem-wide capability mapping.

---

**Chapter 7 — Binary Profiles and Policy Graphs in Depth**

This chapter opens the compiled side of Seatbelt: how SBPL turns into binary profiles, how those profiles are laid out, and how PolicyGraphs actually drive decisions.

* **7.1 From SBPL templates to compiled blobs** — Recaps the compilation pipeline with enough detail to locate versioning, parameterization, and profile provenance in real `.sb` files.
* **7.2 Headers, sections, and vocabulary maps** — Describes the structure of binary profiles: headers, operation pointer tables, node arrays, literal/regex tables, and how operation/filter vocabulary maps tie them back to human-readable names.
* **7.3 PolicyGraphs: nodes, edges, and decision paths** — Explains the node-level representation of filters, metafilters, and decisions; shows how per-operation entrypoints and control flow correspond to SBPL structure and observable allow/deny results.
* **7.4 Tools and patterns for decoding profiles** — Sketches practical approaches for inspecting and validating profiles (decoders, invariants, sanity checks) and ties them to the capability catalog and earlier example apps.
  The chapter closes by treating the binary format and PolicyGraphs as the “implementation ground truth” that underlies all higher-level descriptions of sandbox behaviour.

---

**Chapter 8 — The Sandbox in the Wild: Ecosystem and Threats**

This chapter steps back from individual profiles and apps to look at how Seatbelt is actually used across macOS, and what that means for security practice.

* **8.1 Who is sandboxed, and how** — Surveys macOS 13–14: Mac App Store apps, Apple’s own services and helpers, traditional desktop apps, and how often Seatbelt is actually in play versus other controls.
* **8.2 The modern pipeline: signing, containers, and consent** — Reconstructs the sign→secinit→container→Seatbelt→TCC→SIP path for typical processes and shows where sandbox policy sits among those layers.
* **8.3 Failure modes, bypasses, and design tensions** — Uses historical bugs and structural gaps to illustrate how partial sandbox deployment, over-broad entitlements, or misconfigured profiles can create security weaknesses.
* **8.4 Capability catalogs as a way to reason about risk** — Shows how capability catalogs can be used to compare apps and profiles, identify surprising powers, and support audits or hardening work.
  The chapter ends by framing Seatbelt as one moving part in a larger macOS security ecosystem, and by suggesting how readers can use the book’s tools and concepts to evaluate real systems they care about.

---

**Conclusion — Reading the Sandbox Forward and Backward**

This concluding chapter gathers the threads of the book into a bundle of what we can now say about the macOS sandbox, and it walks the reader through the core references that underlie those threads.

* **C.1 What the book has actually pinned down** — Recaps, the pieces that now hang together: SBPL and operations, compiled profiles and policy graphs, containers and extensions, profile layers and capability catalogs, and where they fit into the wider sign→secinit→Seatbelt→TCC→SIP pipeline.
* **C.2 The architectural canon: how policy is wired in** — Tours the references that focus on architecture and implementation details, showing how each one illuminates a different part of the policy lifecycle and how they map onto the book’s chapters on orientation, vocabulary, and binary profiles.
* **C.3 The operational and offensive canon: how it behaves under pressure** — Walks through references that treat the sandbox as something to be poked, bypassed, or operationalised, relating their case studies and techniques to the methods and experiments developed earlier in the book.
* **C.4 The ecosystem and evolution canon: how the sandbox sits in the real world** — Uses the more survey- and measurement-oriented references to frame the mixed deployment of Seatbelt across macOS, the role of containers and adjacent layers, and the ways the system has shifted over time.
* **C.5 Reading the canon with new eyes** — Offers concrete suggestions for revisiting each reference using the book’s concepts and tools: what to trace, what to try to re-derive, and how to turn their examples into new probes, profiles, and capability catalog entries of your own.

---

**API — Using the Book as a Lab**

This chapter explains how to treat the textbook and its companion repository as an addressable environment rather than a static document, so that both human readers and automated tools can navigate sections, concepts, artifacts, and capability catalogs through a small, explicit API.

* **API.1 Why this book has an API at all** — Describes the motivation for exposing the structure of the text and examples: to let explanations, experiments, and profiles be connected and revisited in a repeatable way.
* **API.2 Resource types and IDs** — Introduces the small set of resource types (`section`, `concept`, `artifact`, `catalog_entry`) and their naming schemes, and shows how they correspond to chapters, concepts, example app incarnations, and capability catalogs.
* **API.3 Indexes and maps in the repository** — Outlines the role of the `api/` index files (for sections, concepts, artifacts, and catalogs), how to read them, and how they link the narrative chapters to concrete files and decoded profiles.
* **API.4 Common jobs and workflows for agents** — Shows how to use the API surfaces to do a few recurring jobs: answering “why did this happen?”, finding where a concept is defined and demonstrated, replaying an example, and comparing two apps or profiles via their capability catalogs.

---

**Addendum — Lab Companion**

This addendum collects the concrete scaffolding behind the book’s examples: where to find experiments, how capability catalogs are structured, and small reference tables the chapters lean on.

1. **A.1 Experiment and Probe Index**

* A.1.1 Chapter-to-artifact map
  * For each chapter section that relies on a concrete probe, app incarnation, or profile, list:
  * the artifact’s short name,
  * its role (what concept or behaviour it demonstrates),
  * and its rough location in the accompanying repository.
* A.1.2 Boundary object summary
  * A compact table of the main “boundary objects” used in the book (probes, profiles, catalogs), with columns for: concept focus (e.g., PolicyGraph, profile layers, containers), expected outcome, and cross-references to figures or examples in the text.

2. **A.2 Capability Catalog Schema and Examples**

* A.2.1 Schema overview
  * A concise description of the catalog structure: how entries record operations, filters, entitlements, profile layers, sandbox extensions, and provenance.
* A.2.2 Minimal schema reference
  * A small, implementation-shaped schema (in prose or pseudo-structured form) that defines the required fields and their meanings, aligned with the terminology used in the main chapters.
* A.2.3 Worked entries
  * One or two fully spelled-out catalog entries (e.g., the example app in two sandbox incarnations) that are more detailed than the abbreviated forms shown in the chapters.
  * Brief annotations showing how to read each field and how it connects back to operations, filters, PolicyGraphs, and containers.

3. **A.3 Reference Tables and Glosses**

* A.3.1 Operations and filters used in the book
  * A small table of the operations and filters that recur most often in examples, with very short descriptions and pointers to where they first appear in the text.
* A.3.2 Profile-layer roles and examples
  * A table that links profile-layer roles (platform, app, helper, auxiliary) to representative examples from the chapters and to their typical place in the policy stack.
* A.3.3 Compact glossary for recurring terms
  * A brief glossary for terms that the book assumes once introduced (e.g., sandbox extension, Compiled Profile Source, Policy Stack Evaluation Order, capability catalog), giving the reader a quick lookup without re-entering earlier chapters.