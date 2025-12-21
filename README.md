# Zero-knowledge guide to the macOS sandbox

SANDBOX_LORE is a host-specific, local-only universe for understanding the macOS Seatbelt sandbox around 2024–2025. It fixes a single “world” (one Sonoma-era Mac) and builds a layered explanation of how sandbox profiles, compiled graphs, and runtime behavior fit together.

The project is designed to:
- Fix a workable model of Seatbelt internals and the App Sandbox on this host.
- Capture a stable vocabulary and concept graph tied to real artifacts.
- Provide runnable, inspectable labs and experiments that can be regenerated locally.

## SANDBOX_LORE

At a high level, SANDBOX_LORE is a host-specific description of Seatbelt for a single macOS Sonoma machine, built in layers:

- A **substrate** defining the world and the vocabulary the project is allowed to use. From this substrate we generate a fixed list of concepts.
- A **concept inventory** and validation harness sit between theory and artifacts, tracking which evidence backs what ideas
- **CARTON** – an intermediate representation between artifacts, concepts, and code which distributes machine-readable artifacts and tooling **into** vocabularies, op-tables, tag layouts, system-profile digests, and selected runtime/lifecycle manifests. 

This allows us to build a **machine-readible resource** which is both regenerable from the repo and a host baseline and not dependent on any expertise of any particular agent, human or otherwise.

## Host Baseline & Evidence Model

The project deliberately fixes a narrow but detailed world:

- **Host baseline**
  - macOS Sonoma 14.4.1 (23E224), Apple Silicon.
  - SIP enabled.
  - Seatbelt as a TrustedBSD MACF module with SBPL-compiled, graph-based profiles.

- **Evidence priorities**
  - Static artifacts on this host—compiled profiles, dyld cache slices, decoded PolicyGraphs, vocab tables, and mapping JSONs—are the primary external reality.
  - The substrate docs under `book/substrate/` are assumed correct for this host unless the repo explicitly revises them.
  - Runtime behavior, entitlements, extensions, and kernel-dispatch work are in progress and must carry explicit status: `ok`, `partial`, `brittle`, or `blocked`, never silently upgraded to fact.

- **Two views of policy**
  - SBPL and compiled profiles are treated as two views of the same policy; concepts are phrased so they make sense in both the language and the binary graph.
  - Operation and Filter vocabularies live in versioned mapping files and must not be invented ad hoc or assumed stable across OS versions without an explicit mapping.

For a compact narrative of these assumptions and the surrounding ecosystem (TCC, hardened runtime, SIP), see:

- `book/substrate/Orientation.md` – architecture and policy lifecycle.
- `book/substrate/Concepts.md` – core Seatbelt concepts and definitions.

## Repository Layout

Detailed navigation and norms live in layered `AGENTS.md` files in each subtree.

- `book/`  
  Textbook, labs, and tooling:
  - Chapters and profiles that tell the sandbox story in human-readable form.
  - Examples and experiments that serve as runnable labs and probes.
  - API tooling for working with compiled profiles, runtime checks, and CARTON-backed mappings.
  - A graph layer (`book/graph/`) that holds the concept inventory, validation harness, and stable host-specific mappings that feed into CARTON.

- `dumps/`  
  Reverse-engineering artifacts for this macOS build. Some subtrees contain local-only host data. See `dumps/AGENTS.md` before running tools or adding files here.

- `AGENTS.md`  
  Project-wide guardrails for agents: host baseline, evidence priorities, and modeling constraints.

- `book/substrate/`  
  Orientation, Concepts, Appendix, Environment, and State; frozen theory of Seatbelt and its environment for this host.

- `guidance/`  
  Compressed context bundles for agents.

- `status/`  
  Meta-level assessments and audits

- `troubles/`  
  Records of crashes, decoding problems, runtime failures, and other issues that need follow-up.

