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
- `tests/` – guardrails for book artifacts and experiment outputs (run via `make -C book test`).

When in doubt, start with the AGENTS/README in the relevant subdirectory.

## Expectations

- Stay within the host baseline and substrate vocabulary; don’t import generic macOS lore.
- Use the stable mappings under `book/graph/mappings/` (vocab, op-table, tag layouts, system digests, runtime) as the backbone for explanations and code, and treat CARTON as the frozen, API-backed web built from those mappings.
- Experiments publish stable outputs into `book/graph/mappings/` only when they are reusable and versioned; scratch lives in `book/experiments/*/out`.
- Keep `Report.md`/`Notes.md` up to date when touching experiments; keep chapter text aligned with the current mappings and concept inventory.
- For validations, prefer the driver: `python -m book.graph.concepts.validation --list|--all|--tag <tag>`. For vocab on this host, run `--tag vocab` (or `--id vocab:sonoma-14.4.1`) and consume `book/graph/mappings/vocab/*.json`. For field2 work, run `--experiment field2` to refresh/verify `book/experiments/field2-filters` outputs before promotion. For a quick pre-promotion sweep, run `--tag smoke` (vocab + field2 + runtime-checks).
- Prefer `tag:golden` jobs when you need canonical IR; use `--describe <job_id>` if you’re unsure what a job does or which inputs/outputs it covers.

Routing cheat-sheet:
- Runtime behavior: `python -m book.graph.concepts.validation --tag smoke` → consume `book/graph/mappings/runtime/runtime_signatures.json`.
- Vocab: `python -m book.graph.concepts.validation --tag vocab` (or smoke) → consume `book/graph/mappings/vocab/{ops,filters}.json`.
- System profiles: `python -m book.graph.concepts.validation --tag system-profiles` → consume `book/graph/mappings/system_profiles/digests.json`.
- CARTON (frozen IR/mapping set): use `book/graph/carton/CARTON.json` for stable Sonoma 14.4.1 IR/mappings; do not mutate listed files—add new experiments/IR/mappings separately. Prefer `book/api/carton/carton_query.py` (backed by the CARTON coverage mapping) for lookups; see `book/graph/carton/API.md` + `USAGE_examples.md`.
