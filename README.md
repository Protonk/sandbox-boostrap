# Synthetic textbook for Apple’s macOS Seatbelt/XNUSandbox.
>For concrete instructions, conventions, or workflows, see `AGENTS.md` at the root.

This repo is not a traditional software project. It is a curated, local-only universe for understanding the macOS sandbox circa 2025, with an emphasis on:

- Fixing a workable model of Seatbelt internals and the App Sandbox.
- Capturing a stable vocabulary and concept graph.
- Providing runnable, inspectable labs that exercise real mechanisms.
- Giving you and your agents a consistent substrate to reason against.

Nothing here enforces policy.

---

## Scope and stance

The time slice is “modern macOS” (Ventura/Sonoma and neighbors), not just historical Snow Leopard. Older materials (Apple Sandbox Guide, Blazakis, SandBlaster, etc.) appear as explicitly mediated sources, not as invisible authorities.

The repo treats as primary:

- Apple’s own documentation, as filtered through the guidance layer.
- Empirical behavior from examples, profile ingestion, and real profiles.

External texts are pulled into `substrate/sources/` with exegesis files and are meant to act as time-stamped anchors. The intent is to keep claims traceable and to make drifts in macOS behavior visible over time rather than silently overwriting them.

This exists to give you a stable, inspectable base layer for sandbox reasoning you can come back to after gaps.

---

## Repository layout (top level)

High-level map of the root:

- `substrate/`  
  Orientation, concepts, appendix, canon, and per-source exegesis.

- `concepts/`  
  Concept inventory and cross-cutting code (e.g., profile ingestion) that multiple artifacts rely on.

- `book/`  
  A cathedral of shit

- `AGENTS.md`  
  Root-level routing and role guidance for you and for any machine agents acting in this repo (with additional AGENTS files in key subdirectories).
