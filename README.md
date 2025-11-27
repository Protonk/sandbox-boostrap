# Synthetic textbook for Apple’s macOS Seatbelt sandbox.

This repo is not a traditional software project. It is a curated, local-only universe for understanding the macOS sandbox circa 2025, with an emphasis on:

- Fixing a workable model of Seatbelt internals and the App Sandbox.
- Capturing a stable vocabulary and concept graph.
- Providing runnable, inspectable labs that exercise real mechanisms.
- Giving you and your agents a consistent substrate to reason against.

Nothing here enforces policy.

---

## What this does

The repo treats as primary:

- Select sources, summarized and cross referenced into a "substrate" of material for human and machine agents.
- Empirical behavior from examples, profile ingestion, and real profiles.

Concepts we form from the substrate are tested against empirical behavior. This validated concept inventory standing on the substrate is a stable, inspectable base layer for reasoning about the sandbox. 

Using this layer we build an example-driven synthetic textbook for human and machine agents covering the sandbox on macOS. 

---

## Repository layout (top level)

High-level map of the root and `book/`:

- `book/` – the cathedral of shit
  - `Outline.md` – high-level textbook outline.
  - `chapters/` – per-chapter text and examples (e.g., TextEdit case study).
  - `profiles/` – SBPL/profile snippets used in the book.
  - `examples/` – runnable labs:
    - `apple-scheme/` – libsandbox compile demo.
    - `containers-and-redirects/` – container/symlink probes.
    - `entitlements-evolution/` – entitlement/signing metadata probe.
    - `extensions-dynamic/` – sandbox extension API pattern (libsandbox).
    - `extract_sbs/` – compile system `.sb` profiles to blobs.
    - `libsandcall/` – compile/apply SBPL via libsandbox.
    - `mach-services/` – Mach service register/lookup probes.
    - `metafilter-tests/` – `require-any/all/not` microprofiles.
    - `network-filters/` – network operation/filter probes.
    - `platform-policy-checks/` – sysctl/SIP/platform policy checks.
    - `re2dot/`, `resnarf/` – regex extraction/visualization tools.
    - `sb/`, `sbdis/`, `sbsnarf/` – SBPL→blob examples and legacy disassembly.
    - `sbpl-params/` – SBPL parameterization demos.
  - `concepts/` – concept inventory and validation:
    - `CONCEPT_INVENTORY.md` – concept clusters, validation plan, process stages.
    - `Handoff.md` – current state of validation work, outputs, blockers, and next steps for agents.
    - `validation/` – ingestion code, task maps, and captured JSON/JSONL evidence under `validation/out/`.
- `spine/`  
  Preamble prompts for machine agents building the textbook or concept inventory.

- `substrate/`  
  Orientation, concepts, appendix, canon, and per-source exegesis. Frozen at `SUBSTRATE_2025-frozen`. 

- `troubles/`  
  Records of crashes or validation troubles

## Scope

The main object of concern is modern macOS (Ventura/Sonoma and neighbors), not just historical Snow Leopard, though this is where accurate, comprehensive sourcing is richest. Older materials (Apple Sandbox Guide, Blazakis, SandBlaster, etc.) appear as explicitly mediated sources, not as invisible authorities.

The most recent source consulted is from 2024 and the textbook is not intended at this time to be a living document. 
