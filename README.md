# Zero-knowledge guide to the macOS sandbox

SANDBOX_LORE is a host-specific, local-only universe for understanding the macOS Seatbelt sandbox around 2024–2025. It fixes a single “world” (one Sonoma-era Mac) and builds a layered explanation of how sandbox profiles, compiled graphs, and runtime behavior fit together.

The project is designed for both humans and agents:

- Fix a workable model of Seatbelt internals and the App Sandbox on this host.
- Capture a stable vocabulary and concept graph tied to real artifacts.
- Provide runnable, inspectable labs and experiments that can be regenerated locally.


## 1. What SANDBOX_LORE Is

At a high level, SANDBOX_LORE is a frozen atlas of Seatbelt for a single macOS Sonoma machine:

- The **substrate** (Orientation, Concepts, Appendix, Environment, State) defines the world and the vocabulary the project is allowed to use.
- A **concept inventory** and validation harness sit between theory and artifacts, tracking which ideas are backed by strong evidence and which remain partial or speculative.
- A **graph/mapping layer** publishes machine-readable IR for this host: operation/filter vocabularies, op-tables, tag layouts, system-profile digests, and selected runtime/lifecycle manifests.
- A **textbook-like book** (chapters + examples) walks through Seatbelt using only this fixed world and these mappings.

Everything here is meant to be regenerable from two inputs: this repo and the fixed host baseline. Whenever static structure, runtime experiments, and canonical sources disagree, that disagreement is treated as an open modeling or tooling bug, not something to smooth over.


## 2. Host Baseline & Evidence Model

The project deliberately fixes a narrow but detailed world:

- **Host baseline**
  - macOS Sonoma 14.4.1 (23E224), Apple Silicon.
  - SIP enabled.
  - Seatbelt as a TrustedBSD MACF module with SBPL-compiled, graph-based profiles.

- **Evidence priorities**
  - Static artifacts on this host—compiled profiles, dyld cache slices, decoded PolicyGraphs, vocab tables, and mapping JSONs—are the primary external reality.
  - The substrate docs under `substrate/` are assumed correct for this host unless the repo explicitly revises them.
  - Runtime behavior, entitlements, extensions, and kernel-dispatch work are in progress and must carry explicit status: `ok`, `partial`, `brittle`, or `blocked`, never silently upgraded to fact.

- **Two views of policy**
  - SBPL and compiled profiles are treated as two views of the same policy; concepts are phrased so they make sense in both the language and the binary graph.
  - Operation and Filter vocabularies live in versioned mapping files and must not be invented ad hoc or assumed stable across OS versions without an explicit mapping.

For a compact narrative of these assumptions and the surrounding ecosystem (TCC, hardened runtime, SIP), see:

- `Preamble.md` – short, agent-friendly summary of the substrate and invariants.
- `substrate/Orientation.md` – architecture and policy lifecycle.
- `substrate/Concepts.md` – core Seatbelt concepts and definitions.


## 3. Repository Layout

This section sketches the main pieces of the repo; detailed navigation and norms live in layered `AGENTS.md` files in each subtree.

- `AGENTS.md`  
  Project-wide guardrails for agents: host baseline, evidence priorities, and modeling constraints.

- `Preamble.md`  
  Compressed context bundle for humans and agents, summarizing the substrate and evidence model.

- `substrate/`  
  Orientation, Concepts, Appendix, Environment, and State; frozen theory of Seatbelt and its environment for this host.

- `book/`  
  Textbook, labs, and tooling:
  - Chapters and profiles that tell the sandbox story in human-readable form.
  - Examples and experiments that serve as runnable labs and probes.
  - API tooling (e.g., decoder, SBPL compiler, op-table helpers, golden-runner harness) for working with compiled profiles and runtime checks.
  - A graph layer (`book/graph/`) that holds the concept inventory, validation harness, Swift generator, and stable host-specific mappings (vocab tables, op-table alignment, tag layouts, anchor maps, system-profile digests, runtime expectations, lifecycle manifests).
  - A unified test harness (`make -C book test`) that runs Python unit checks and builds the Swift graph tools to enforce compile-time contracts.

- `dumps/`  
  Reverse-engineering artifacts for this macOS build. Some subtrees (e.g., `Sandbox-private/`) contain local-only host data. See `dumps/AGENTS.md` before running tools or adding files here.

- `status/`  
  Meta-level assessments and audits (for example, experiment and mapping status reports) that describe how well the current experiments and mappings meet project expectations.

- `troubles/`  
  Records of crashes, decoding problems, runtime failures, and other issues that need follow-up rather than being hidden or papered over.

When in doubt about how to extend or use any part of the tree, consult the nearest `AGENTS.md` file; those layered guides are the authoritative “map” for both humans and agents. 

## Testing

Use the single entrypoint to exercise both Python tests and Swift build checks:

```
source .venv/bin/activate
make -C book test
```

The Python harness mirrors the pytest suite without invoking pytest; the Swift step builds `book/graph` to surface compile-time contract issues. There is no alternative test runner.
