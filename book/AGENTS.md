# Agents in `book/`

This is the textbook workspace. Use it with the substrate vocabulary (`substrate/`) and the fixed host baseline recorded in `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`. Everything here should stay grounded in the mappings and concepts defined for this host.

## Router

- `Outline.md` – top-level textbook outline.
- `chapters/` – per-chapter drafts and plans; check chapter-local notes before editing.
- `graph/` – shared graph IR and concept inventory.
  - See `book/graph/AGENTS.md` for norms on mappings and validation code.
- `experiments/` – host-specific experiments and their reports/notes/artifacts.
  - See `book/experiments/AGENTS.md` for how experiments are structured.
- `examples/` – runnable SBPL/demo bundles and extraction helpers used by chapters and experiments.
- `profiles/` – SBPL/profile sources shared across the book.
- `api/` – shared tooling (decoder, SBPL/blob wrapper, Ghidra helpers); see `book/api/AGENTS.md`.
- `tests/` – guardrails for book artifacts and experiment outputs (`pytest book/tests`).

When in doubt, start with the AGENTS/README in the relevant subdirectory.

## Expectations

- Stay within the host baseline and substrate vocabulary; don’t import generic macOS lore.
- Use the stable mappings under `book/graph/mappings/` (vocab, op-table, tag layouts, system digests, runtime) as the backbone for explanations and code.
- Experiments publish stable outputs into `book/graph/mappings/` only when they are reusable and versioned; scratch lives in `book/experiments/*/out`.
- Keep `Report.md`/`Notes.md` up to date when touching experiments; keep chapter text aligned with the current mappings and concept inventory.
