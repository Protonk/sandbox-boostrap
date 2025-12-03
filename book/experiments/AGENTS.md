# Agents in `book/experiments/`

These instructions apply to all subdirectories of `book/experiments/`.

## Router: what lives here

Each subdirectory under `book/experiments/` is a host-specific experiment. They fall roughly into these families:

- **Static structure & vocab**
  - `node-layout` – profile format, node region, literal/regex pools, stride/tag structure.
  - `op-table-operation` – op-table “bucket” behavior vs operations/filters.
  - `op-table-vocab-alignment` – bucket ↔ Operation Vocabulary alignment.
  - `vocab-from-cache` – Operation/Filter vocab harvested from the dyld cache.
  - `tag-layout-decode` – tag ↔ node-layout mapping for literal/regex-bearing nodes.
  - `system-profile-digest` – digests for curated system profiles.
  - `anchor-filter-map` – anchors ↔ Filter IDs using `field2` and vocab.
  - `field2-filters` – `field2` behavior across filters, tags, and profiles.
  - `probe-op-structure` – richer SBPL probes to surface `field2` and tag patterns.

- **Runtime & semantic alignment**
  - `runtime-checks` – bucket-level runtime behavior vs decoder expectations.
  - `sbpl-graph-runtime` – SBPL ↔ graph ↔ runtime “golden” triples.

- **Entitlements, kernel, and symbol work**
  - `entitlement-diff` – entitlement-driven profile/filter/runtime differences.
  - `kernel-symbols` – kernel symbol/string inventories for sandbox-related work.
  - `symbol-search` – searches for the PolicyGraph dispatcher and related kernel helpers.

New experiments should follow the same pattern: a dedicated directory with its own `Report.md`, `Notes.md`, and local `out/` for artifacts, plugged into the shared mapping layer under `book/graph/mappings/` once results are stable.

Shared tooling tip:
- For quick blob snapshots (section sizes, op-table entries, stride/tag stats, literals), use `book/api/inspect_profile` (CLI or Python) instead of duplicating parsers.

## What makes a good experiment here

A good experiment is:

- **Focused** – answers a single clear question in substrate vocabulary (Operation, Filter, PolicyGraph, Profile Layer, etc.) for this specific host baseline.
- **Evidence-backed** – every nontrivial claim points to concrete artifacts: SBPL, compiled blobs, decoded graphs, vocab/mapping JSONs, or runtime logs.
- **Static-first, status-aware** – leans on static mappings and formats as backbone, and marks semantic/lifecycle results with their status (`ok`, `partial`, `brittle`, `blocked`).
- **Reproducible** – can be rerun (or at least re-read) by another agent using only the repo, the fixed host baseline, and the instructions in `Report.md`.

Experiments should remain small and host-grounded: they refine or consume existing mappings and formats rather than introducing new global abstractions without evidence.

## Documentation model

Each experiment uses the same documentation scaffold:

- **`Report.md` (canonical narrative)**
  - Primary document for humans and agents.
  - Should cover:
    - `## Purpose` – why this experiment exists, in terms of substrate concepts.
    - `## Baseline & scope` – host, inputs, dependencies, and what is explicitly in/out of scope.
    - `## Deliverables / expected outcomes` – concrete artifacts (files, mappings, guardrails).
    - `## Plan & execution log` – what has been done and what remains, at a coarse granularity.
    - `## Evidence & artifacts` – where the JSONs, blobs, digests, vocab files, and logs live.
    - `## Blockers / risks` – current obstacles and fragile assumptions.
    - `## Next steps` – the most important questions or tasks to pursue next.
    - Optional `## Appendix` – tables or historical notes that support the main text.
  - Keep this file in sync with the actual state of `out/` and any shared artifacts the experiment influences.

- **`Notes.md` (running notes)**
  - Use as a running log of commands, observations, and dead ends.
  - Prefer short, factual entries tied to specific files or scripts.
  - When something in `Notes.md` becomes a stable conclusion, reflect it back into `Report.md`.

- **`out/` (local artifacts)**
  - Store machine-readable outputs here (inventories, digests, audits, runtime logs, intermediate mapping JSONs).
  - Name files so that other experiments can consume them (`field2_inventory.json`, `op_table_map.json`, `tag_histogram.json`, etc.).
  - When an artifact becomes stable and reused across experiments, promote it into `book/graph/mappings/…` with clear metadata; keep `out/` as the local scratch/provenance.

- **Common subtrees**
  - `sb/` / `sb/build/` – SBPL source and compiled profiles for probes.
  - Local scripts (`analyze.py`, `run_probes.py`, `harvest_*.py`, etc.) – keep them small, experiment-scoped, and described in `Report.md` / `Notes.md`.


## Things to avoid

When working under `book/experiments/`, agents should avoid:

- **Silent failures**
  - Do not discard or hide harness failures, apply gates, decoder errors, or mismatches between expected and observed behavior.
  - Always record such failures explicitly in `Report.md` or `Notes.md`, with enough context to recognize and revisit them.

- **Timestamps/dates in `Notes.md`**
  - When appending new notes, avoid including explicit timestamps or dates in `Notes.md`.
