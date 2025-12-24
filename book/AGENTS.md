# Agents in `book/`

This is the textbook workspace. Use it with the substrate vocabulary (`book/substrate/`) and the fixed host baseline recorded in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`. Everything here should stay grounded in the mappings and concepts defined for this host.

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
- `tools/` – host-local helper binaries/app bundles used by experiments (e.g., `tools/entitlement/EntitlementJail.app` for running probes under an App Sandbox parent).
- `tests/` – guardrails for book artifacts and experiment outputs (run via `make -C book test`).
- Platform/system sandbox profiles (e.g., `airlock.sb`) are included only as static decoder inputs via `book/graph/concepts/validation/golden_corpus/`; see the golden-corpus Report for the static-only stance.

When in doubt, start with the AGENTS/README in the relevant subdirectory.

## Expectations

- Stay within the host baseline and substrate vocabulary; don’t import generic macOS lore.
- Use the stable mappings under `book/graph/mappings/` (vocab, op-table, tag layouts, system digests, runtime) as the backbone for explanations and code, and treat CARTON as the frozen, API-backed web built from those mappings.
- Use `book/graph/mappings/vocab/ops_coverage.json` to distinguish operations with runtime evidence from vocab-only coverage. Today `file-read*`, `file-write*`, and `mach-lookup` have both structural and runtime backing (runtime-checks + runtime-adversarial); when relying on other ops, design new probes or treat claims as tentative until runtime evidence exists.
- Experiments publish stable outputs into `book/graph/mappings/` only when they are reusable and versioned; scratch lives in `book/experiments/*/out`.
- Keep `Report.md`/`Notes.md` up to date when touching experiments; keep chapter text aligned with the current mappings and concept inventory.
- For validations, prefer the driver: `python -m book.graph.concepts.validation --list|--all|--tag <tag>`. For vocab on this host, run `--tag vocab` (or `--id vocab:sonoma-14.4.1`) and consume `book/graph/mappings/vocab/*.json`. For field2 work, run `--experiment field2` to refresh/verify `book/experiments/field2-filters` outputs before promotion. For a quick pre-promotion sweep, run `--tag smoke` (vocab + field2 + runtime-checks).
- Prefer `tag:golden` jobs when you need canonical IR; use `--describe <job_id>` if you’re unsure what a job does or which inputs/outputs it covers.
- For sandbox concept questions (operations ↔ profiles ↔ runtime signatures), CARTON is the default IR: use `book/api/carton/carton_query.py` instead of re-parsing validation outputs. Be ready to handle `UnknownOperationError` for ops outside the vocab and `CartonDataError` for manifest/hash/mapping issues.
- CARTON routing (preferred patterns): start with discovery (`list_operations`, `list_profiles`, `list_filters`). Then map intent to helper:
  - “What do we know about op X?” → `operation_story(op_name)` / `profiles_and_signatures_for_operation(op_name)`.
  - “What does profile P exercise?” → `profile_story(profile_id)` (filters block is conservative today).
  - “What do we know about filter F?” → `filter_story(filter_name)` (usage_status marks current knowledge).
  - Errors: `UnknownOperationError` = typo/unknown op; `CartonDataError` = manifest/hash/mapping drift.

Routing cheat-sheet:
- Runtime behavior: `python -m book.graph.concepts.validation --tag smoke` → consume `book/graph/mappings/runtime/runtime_signatures.json`.
- Vocab: `python -m book.graph.concepts.validation --tag vocab` (or smoke) → consume `book/graph/mappings/vocab/{ops,filters}.json`.
- System profiles: `python -m book.graph.concepts.validation --tag system-profiles` → consume `book/graph/mappings/system_profiles/digests.json`.
- CARTON (frozen IR/mapping set): use `book/api/carton/CARTON.json` for stable Sonoma 14.4.1 IR/mappings; do not mutate listed files—add new experiments/IR/mappings separately. Prefer `book/api/carton/carton_query.py` (backed by the CARTON coverage and index mappings) for lookups; see `book/api/carton/README.md`, `AGENTS.md`, and `API.md`.

## Validation tiers

Treat every claim as belonging to a tier: **bedrock** (name it as bedrock and cite its mapping path; check `book/graph/concepts/BEDROCK_SURFACES.json` for the current set), **mapped-but-partial** (carry words like “partial”, “brittle”, or “under exploration” in prose/comments), or **substrate-only** (say there is no host witness yet and that the claim is substrate theory). If you make a claim that sounds global (“the sandbox does X”), also state which tier it is in; do not silently upgrade partial/brittle or substrate-only statements to bedrock.
