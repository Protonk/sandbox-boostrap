# Zero-knowledge guide to the macOS sandbox

SANDBOX_LORE is a host-specific, local-only universe for understanding the macOS Seatbelt sandbox around 2024–2025. It fixes a single “world” (one Sonoma-era Mac) and builds a layered explanation of how sandbox profiles, graphs, and runtime behavior fit together.

The project is designed for both humans and agents:

- Fix a workable model of Seatbelt internals and the App Sandbox.
- Capture a stable vocabulary and concept graph tied to real artifacts.
- Provide runnable, inspectable labs and experiments.

## What this repo actually does

The repo treats as primary:

- **Substrate texts** – Orientation, Concepts, Appendix, Environment, and State under `substrate/`, which define the project’s vocabulary and world.
- **Static artifacts** – Compiled profiles, dyld cache extracts, decoded graphs, vocab tables, and mapping JSONs tied to a single host baseline.
- **Experiments and examples** – SBPL profiles, runtime probes, and analysis scripts that test and refine concepts.

From these, we build:

- A **concept inventory**: a small, explicit set of Seatbelt concepts with witnesses and validation status.
- A **graph/mapping layer**: machine-readable IR (operations, filters, op-tables, tag layouts, system-profile digests, runtime expectations) for this host.
- A **textbook-like “book”**: examples and chapters that walk through the sandbox using only the fixed substrate and mappings.

Whenever static structure, runtime experiments, and canonical sources disagree, that disagreement is treated as an open modeling or tooling bug—not something to smooth over.


## Repository layout (top level)

High-level map of the root and `book/`:

- `AGENTS.md`  
  Project-wide guardrails for agents: host baseline, evidence priorities, and modeling constraints.

- `substrate/`  
  Orientation, Concepts, Appendix, Environment, and State; frozen at `SUBSTRATE_2025-frozen`. This is the normative theory of Seatbelt and its environment for this host.

- `book/` – the “textbook + labs”
  - `AGENTS.md` – navigation and norms for the `book/` tree.
  - `Outline.md` – high-level textbook outline.
  - `chapters/` – per-chapter text and plans (e.g., TextEdit case study).
  - `profiles/` – SBPL/profile sources used in the book.
  - `examples/` – runnable labs and probes (each subdirectory is a self-contained example).
  - `experiments/` – cross-cutting experiments that validate and refine concepts on modern macOS.
  - `graph/` – shared graph IR and mappings:
    - `graph/concepts/` – concept inventory, conceptual docs, and validation tooling (`validation/`).
    - `graph/mappings/` – stable mapping artifacts (vocab tables, op-table alignment, anchor maps, tag layouts, system-profile digests, runtime traces).
  - `tests/` – pytest harness and guardrails for mappings, experiments, and examples.

- `dumps/`  
  Reverse-engineering artifacts for the current macOS build. `Sandbox-private/` is git-ignored host data. See `dumps/AGENTS.md` before touching anything here.

- `status/`  
  Meta-level assessments and audits (for example, experiment audits under `status/experiments/`) that describe how well experiments and mappings meet project expectations.

- `troubles/`  
  Records of crashes, decoding problems, or validation issues that need follow-up.


## Scope and invariants

The project deliberately fixes a narrow but detailed world:

- **Host baseline**
  - macOS Sonoma 14.4.1 on Apple Silicon.
  - SIP enabled.
  - Modern Seatbelt architecture (TrustedBSD MACF module, SBPL-compiled profiles, graph-based evaluation).

- **Evidence priorities**
  - Static artifacts on this host—compiled profiles, dyld cache entries, decoded PolicyGraphs, mapping JSONs—are the primary external reality.
  - The substrate docs are assumed correct for this host unless the repo explicitly revises them.
  - Runtime behavior, entitlements, and kernel dispatch work are in progress and must be treated as `ok` / `partial` / `brittle` / `blocked`, not silently upgraded to fact.

- **Mapping discipline**
  - Operation and Filter vocabularies, op-table structure, and tag layouts (where known) are captured under `book/graph/mappings/` and treated as canonical for this host.
  - SBPL and compiled profiles are two views of the same policy; whenever possible, concepts are phrased so they make sense both in SBPL and in compiled graphs.

- **Modeling obligations**
  - Every substantive claim about sandbox behavior should be traceable to:
    - A specific experiment under `book/experiments/`,
    - A mapping dataset under `book/graph/mappings/`,
    - A validation artifact under `book/graph/concepts/validation/out/`,
    - Or a canonical source recognized by the substrate.
  - When artifacts and theory disagree, the correct response is to record the discrepancy and bound it, not to adjust the story until it fits.

This repo is not a general-purpose macOS security manual. It is a tightly scoped, regenerable atlas of Seatbelt and its surroundings for one Sonoma host, designed to be a solid foundation for both human readers and agents.
