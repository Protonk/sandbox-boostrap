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

- `book/` – The Cathedral of Shit
  - `AGENTS.md` – navigation map for the `book/` tree.
  - `Outline.md` – high-level textbook outline.
  - `chapters/` – per-chapter text and plans (e.g., TextEdit case study).
  - `profiles/` – SBPL/profile sources used in the book.
  - `examples/` – runnable labs and probes (each subdirectory is a unit example).
  - `graph/` – Swift-based contracts and JSON artifacts:
    - `graph/Package.swift`, `graph/Sources/` – BookGraph types and generator CLI.
    - `graph/concepts/` – concept inventory, validation docs, and generated concept JSON.
    - `graph/regions/` – stub `text_regions.json` for chapter bindings.
- `substrate/` – Orientation, Concepts, Appendix, Environment, State; frozen at `SUBSTRATE_2025-frozen`.
- `troubles/` – records of crashes or validation troubles.

## Scope

The main object of concern is modern macOS (Ventura/Sonoma and neighbors), not just historical Snow Leopard, though this is where accurate, comprehensive sourcing is richest. Older materials (Apple Sandbox Guide, Blazakis, SandBlaster, etc.) appear as explicitly mediated sources, not as invisible authorities.

The most recent source consulted is from 2024 and the textbook is not intended at this time to be a living document. 
