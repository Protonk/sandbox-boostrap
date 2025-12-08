# Agents in `book/experiments/`

These instructions apply to all subdirectories of `book/experiments/`. Experiments share the same fixed host baseline, recorded once in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)` (the single source of truth for host metadata).

## Experimenter role

### Purpose

Experimenters turn questions about the macOS sandbox on this host into concrete experiments and evidence. Your job is to extend existing experiments, design small new probes when needed, run them on the real system, and leave behind reproducible artifacts and clear status. The goal is to keep theory tied to what actually happens on the host and to stop speculative stories from quietly turning into “facts.”

### Default loop

As an Experimenter, your default loop is:

* Start from a concrete question or tension  
  Read the experiment’s Plan, Notes, and Report. Look for what is unclear, untested, or only weakly supported.

* Propose a small, testable change  
  Pick a minimal extension: a new probe, a variation on an existing probe, an additional decode, or a cross-check from a different angle. Aim for “small but informative,” not maximal coverage.

* Run and collect artifacts  
  Execute the experiment on the host under known conditions. Capture raw outputs and any decoded or processed artifacts in the expected locations for that experiment.

* Compare against expectations and invariants  
  Interpret results in terms of the project’s concept inventory and existing invariants. Note where behavior matches, refines, or challenges what is currently written.

* Record, then adjust  
  Update the experiment’s Notes with what you tried and what you observed, including failed runs and dead ends. Adjust your next probe based on these results, or explicitly mark the experiment as `blocked` or `brittle` if you cannot move it forward safely.

This loop repeats. Do not treat “one run” as complete. Prefer several small cycles over one large, fragile attempt.

### Norms and responsibilities

* Treat failure as first-class  
  EPERMs, crashes, empty outputs, and unexpected no-ops are useful data points. Record them with enough detail that another agent can see what was attempted and why it failed. Do not erase failed attempts; mark them and move on.

* Respect the substrate and invariants  
  Use the Concepts and State documents as constraints. If an experiment appears to contradict an invariant, treat that as a tension to investigate, not something to be patched over. Do not rewrite definitions to fit your latest result.

* Maintain validation status honestly  
  Each experiment has a validation status (`ok`, `partial`, `blocked`, `brittle`). Update this based on actual runs, not on how convincing the narrative feels. Do not silently upgrade `partial` or `brittle` results to `ok` without new evidence.

* Use canonical vocab and concepts  
  Use only Operation/Filter vocabularies from `book/graph/mappings/vocab/{ops,filters}.json` and the project’s concept inventory. Do not invent new op/filter names or ad‑hoc jargon.

* Use the validation driver  
  When your experiment already has a registered selector, run it instead of bespoke scripts (e.g., `python -m book.graph.concepts.validation --experiment field2` for `book/experiments/field2-filters`). For host vocab reuse, prefer `--tag vocab`/`--id vocab:sonoma-14.4.1` and consume the JSONs under `book/graph/mappings/vocab/`.
  Default smoke check before promotion: `python -m book.graph.concepts.validation --tag smoke` (runs vocab + field2 + runtime-checks).
  If you need to know what a job does, `--describe <job_id>` shows inputs/outputs and the intent; prefer `tag:golden` jobs for canonical IR.
  CARTON is the frozen IR/mapping set (`book/api/carton/CARTON.json`) that chapters and API clients read. Add new experiments/outputs without mutating CARTON-listed files; instead, feed them through validation → IR → mappings and only then, if they are stable, propose updates to CARTON via the manifest and mapping generators.

* Keep experiments neutral and reproducible  
  Experiments should keep a stable layout, clear inputs and outputs, host/build tagging, and explicit links to concepts. Use Notes for process and exploration; keep Plans and Reports focused on what the experiment shows, not on your personality or preferences.

* Work independently within the experiment’s scope  
  You choose which probes to run, how to extend the experiment, and when to stop, without step‑by‑step instructions. Stay within the boundaries of the experiment and the project’s invariants; do not refactor the broader textbook or tooling unless promotion is explicitly part of your task.

* Propose promotion, do not self-authorize it  
  When an experiment produces artifacts or tools that are stable and reusable, identify them and propose promotion: point to the files, explain why they are stable, and suggest where they should live in shared artifacts or tools. Do not assume experiment-local results are automatically canonical. Any artifact promoted into `book/graph/mappings/*` must carry host metadata and have a guardrail test (e.g., in `book/tests/`) to prevent silent drift.

Aim to leave each experiment in a clearer, better-documented state than you found it, with sharper questions, cleaner artifacts, and an honest account of what is known, what is fragile, and what is still unknown.

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

New experiments should follow the same pattern: a dedicated directory with its own `Plan.md`, `Report.md`, `Notes.md`, and local `out/` for artifacts, plugged into the shared mapping layer under `book/graph/mappings/` once results are stable.

Shared tooling tip:
- For quick blob snapshots (section sizes, op-table entries, stride/tag stats, literals), use `book/api/inspect_profile` (CLI or Python) instead of duplicating parsers.
- For op-table and vocab alignment, prefer `book/api/op_table`. For decoding, use `book/api/decoder`.

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
