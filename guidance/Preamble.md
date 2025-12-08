SANDBOX_LORE is a host-specific, local-only universe for the macOS Seatbelt sandbox on a single baseline associated with the `world_id` `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. The substrate under substrate/ defines the world and vocabulary you are allowed to use; validated mappings, CARTON, and experiments/validation IR extend that world with host-specific facts that you may treat as true at their recorded status. Your job as an embedded agent is to stay inside that world and treat compiled profiles, Operation/Filter vocabularies, PolicyGraphs, node tags, and repository mappings as primary evidence, not decoration.

This document is a compact context bundle, not a router or API manual. It is meant to give you immediate traction on three things: (1) what this project believes about Seatbelt on this host, (2) how that belief is encoded in IR and mappings, and (3) how experiments, validation, and tools hang off that IR. When you need detailed workflow or path-level instructions, defer to the layered `AGENTS.md` files and module READMEs; when you need high-level bearings and invariants, start here and in the substrate.


# World and evidence model

The project deliberately fixes a narrow but detailed world:

- A host baseline captured in `book/world/*` and identified by the the unique `world_id` carried into mappings and CARTON.
- Static artifacts: compiled profiles, trimmed dyld slices, decoded PolicyGraphs, vocab tables, and mapping JSONs under `book/graph/mappings/`—are the primary external reality. Explanations should lean on them, not on generic macOS lore.
- The substrate (`Orientation`, `Concepts`, `Appendix`, `Environment`, `State`, `Canon`) is the project’s normative theory for this host. The concept inventory and validation harness turn that theory into explicit concepts, evidence types, and checks against real artifacts.

Static structure is the backbone. Profile formats, op-table shape, tag layouts where known, and Operation/Filter vocabularies have been decoded for this host, wired into `book/graph/mappings/*`, and guarded by tests and validation status. These give you a stable view of “what the sandbox looks like” in binary form. By contrast, semantic and lifecycle claims (runtime allow/deny behavior, entitlement-driven differences, extensions, kernel dispatch) are still being nailed down; validation and experiments mark them with `status: ok/partial/brittle/blocked`. When you rely on those areas, carry the status into your reasoning instead of silently upgrading provisional evidence to fact.


# Substrate, concepts, and IR

The substrate documents define the concept set and language this project is allowed to use: SBPL profiles and parameterization, operations, filters and metafilters, decisions, policy nodes and PolicyGraphs, profile layers, compiled profile sources, containers, entitlements, extensions, and the broader environment (TCC, hardened runtime, SIP, real-world application of Seatbelt). `book/graph/concepts/CONCEPT_INVENTORY.md` and the generated JSON in `book/graph/concepts/` mirror this inventory in a machine-readable way. The Swift generator in `book/graph/` reads substrate text and validation metadata and emits `concepts.json`, `concept_map.json`, `concept_text_map.json`, and a lightweight validation report.

You should use this vocabulary when naming things in code and prose. In particular:

- **Operation** and **Filter** are versioned, host-bound vocabularies, instantiated for this world in `book/graph/mappings/vocab/{ops.json,filters.json}`. These files implement the Operation Vocabulary Map and Filter Vocabulary Map; do not invent new names or IDs.
- **PolicyGraph** is the compiled graph for a profile, with **policy nodes** tagged and laid out according to `tag_layouts/tag_layouts.json` and decoded via shared tools.
- **Profile layer** and **Compiled Profile Source** describe where a profile comes from and which role it plays in the stack (platform/system profiles such as `sys:airlock` and `sys:bsd`, app/App Sandbox templates, golden experimental profiles).

The mapping layer under `book/graph/mappings/` is the shared IR that ties these concepts to concrete data for this host:

- `vocab/` — Operation/Filter vocabulary (plus attestations) harvested from dyld/`libsandbox`.
- `op_table/` — Operation Pointer Table mappings: bucket maps, structural signatures, and vocab alignment.
- `tag_layouts/` — per-tag node layouts (record size, edge fields, literal/regex payload fields).
- `anchors/` — anchor ↔ field2 ↔ Filter mappings for literal strings (paths, Mach names, etc.).
- `system_profiles/` — digests, static checks, and attestations for curated system profiles.
- `runtime/` — expectations, normalized traces, lifecycle traces, golden runtime profiles, and `runtime_signatures.json`.
- `dyld-libs/` — dyld manifest for the slices used by vocab/encoder work, with its own checker.
- `carton/` — CARTON-derived overlays (coverage and indices) built from the frozen CARTON surface.

Every mapping JSON is host-bound, carries metadata (including `world_id`, inputs, `source_jobs`, and `status`), and is intended to be regenerated from experiments and validation IR, not hand-edited.


# Experiments, validation, and promotion

Experiments under `book/experiments/` are small, host-specific probes that tie questions about this world to observable behavior. They fall into three broad families:

- Static structure and vocab (node layout, op-table behavior and alignment, vocab-from-cache, tag layouts, system profile digests, anchor/field2 work).
- Runtime behavior and semantic alignment (runtime-checks, runtime-adversarial, sbpl-graph-runtime).
- Entitlements, kernel, and symbol work (entitlement-driven profile differences, kernel symbols, symbol-search, libsandbox encoder).

Experiment subdirectories share a scaffold (`Plan.md`, `Report.md`, `Notes.md`, `out/` for artifacts). They publish raw and normalized IR under their own `out/` trees; promotion into shared mappings happens only after validation.

The validation harness in `book/graph/concepts/validation/` is the bridge between experiment outputs and mappings. It:

- Registers jobs and tags (for example `vocab:*`, `op-table:*`, `experiment:<name>`, `runtime:*`, `graph:*`) and runs them via a single driver (`python -m book.graph.concepts.validation`).
- Normalizes experiment outputs into `validation/out/` (static-format, semantic, vocab, lifecycle IR) and records status in `validation_status.json` using a common schema (`ok[-changed/-unchanged]`, `partial`, `brittle`, `blocked`, `skipped`).
- Documents the current cut: static-format and vocab are `ok`, runtime and lifecycle coverage are partial and explicitly bounded.

Mapping generators under `book/graph/mappings/*/generate_*.py` are the only supported path from validation IR to shared mappings. They are expected to:

- Run the relevant validation jobs (often via a shared promotion helper in `book/graph/mappings/run_promotion.py`).
- Require that those jobs be `status: ok` before proceeding.
- Read only normalized IR under `validation/out/`, not raw experiment scratch.
- Emit host-bound mapping JSON with metadata and status fields.

This pipeline (experiments → validation IR → mapping generators → `book/graph/mappings/*`) is the backbone that keeps theory, experiments, and IR aligned.


# CARTON and shared tooling

CARTON is the frozen IR/mapping layer that the textbook and API clients read. Its manifest, `book/api/carton/CARTON.json`, lists the CARTON-facing JSON files (vocab, runtime signatures, system profile digests, coverage and index overlays) and their SHA-256 hashes, tied to the world baseline. The only supported way to change what CARTON knows is:

1. Extend experiments and validation so that new IR exists under `validation/out/`.
2. Regenerate mappings via the generators and promotion helper under `book/graph/mappings/`.
3. Refresh the manifest with `book/api/carton/create_manifest.py`.

Callers do not reach these files directly; they go through the Python API in `book.api.carton.carton_query`, which:

- Loads the manifest, verifies file paths and hashes, and enforces basic schema.
- Exposes concept-shaped helpers such as `list_operations`, `list_profiles`, `list_filters`, `ops_with_low_coverage`, `operation_story`, `profile_story`, `filter_story`, and `runtime_signature_info`.
- Separates “unknown concept” (`UnknownOperationError`) from “CARTON is out of sync” (`CartonDataError`).

Agents should treat CARTON as the default surface for questions like “what do we know about operation X?” or “which runtime signatures touch profile Y?” and fall back to mappings or validation IR only when they are extending the IR itself.

Below CARTON, the API layer in `book/api/` provides reusable tools for this baseline:

- `decoder/` — decode compiled blobs into dicts using vocab and tag-layout mappings.
- `sbpl_compile/` — wrap private `libsandbox` compile entry points.
- `inspect_profile/` — produce structural summaries of compiled blobs.
- `op_table/` — parse SBPL, compute op-table entries and signatures, and align them to vocab.
- `SBPL-wrapper/` and `file_probe/` — drive runtime probes; `EPERM` apply gates on this host are treated as `blocked` outcomes, not “profile does not exist.”
- `runtime_golden/` and `golden_runner/` — manage golden runtime profiles, expected matrices, and normalized runtime results.
- `ghidra/` — support kernel and op-table symbol work in a controlled workspace.

These tools assume the mappings and world baseline are correct for this host; their job is to make it easy to move between SBPL, compiled profiles, decoded graphs, runtime probes, and CARTON without re-implementing infrastructure.


# Invariants and open areas

Across all of this, a handful of project-wide invariants and cautions shape how you should reason:

- The world is a single, frozen host baseline; all architectural and behavioral claims are about this world unless explicitly labeled otherwise.
- Static-format and vocab/mapping clusters (profile layout, op-table structure, tag layouts where known, Operation/Filter vocabularies, dyld manifest) are treated as structurally reliable on this host and form the default backbone for explanations.
- Semantic and lifecycle clusters (runtime allow/deny behavior, entitlement-driven differences, profile-layer semantics, extensions, kernel dispatch) are in progress. Many claims in these areas are supported only for a subset of operations (notably `file-read*`, `file-write*`, and `mach-lookup`) and may be `partial` or `brittle`. Use `book/graph/mappings/runtime/` and vocab coverage files to see where runtime backing exists.
- Operation and Filter vocabularies are defined by `book/graph/mappings/vocab/{ops.json,filters.json}` and their attestations; do not invent new names or assume cross-version stability without an explicit mapping.
- Platform profile blobs such as `airlock` and `bsd` are real policies even when apply gates prevent applying them on this host; those failures are part of the environment, not evidence that the profiles are fictional.
- Entitlements, containers, and sandbox extensions are inputs that select and parameterize policy stacks and labels; they should be explained in terms of their impact on compiled profiles, labels, and PolicyGraphs, not as free-floating permissions.
- Kernel reverse engineering is explicitly unfinished. Candidate dispatcher sites exist, but none has been blessed as “the” PolicyGraph evaluator; treat them as hypotheses.
- When runtime harnesses, decoded structure, and canonical texts disagree, treat that as an open modeling or tooling bug. Record and bound the discrepancy instead of averaging stories.
- The goal of the runtime work is a small set of “golden” scenarios where structure, entitlements, and runtime behavior are all well understood and reproducible; explanations should be phrased so they could, in principle, be checked against such examples.
- All code and prose should be regenerable from the repo plus the fixed host baseline. If you rely on knowledge that cannot be regenerated (for example, opaque model weights), do not present it as authoritative.
- When the simplest honest answer is “we don’t know yet” or “current evidence is inconsistent,” say that explicitly and, where possible, point to the experiments, validation IR, or mappings that bound that ignorance.


# Minimal routing

For deeper detail:

- For human overview and repository layout, read `README.md` and the root `AGENTS.md`.
- For textbook structure and graph IR, see `book/Outline.md`, `book/AGENTS.md`, and `book/graph/README.md`.
- For experiments and their roles, see `book/experiments/AGENTS.md` and `book/experiments/Experiments.md`.
- For API surfaces and CARTON, see `book/api/README.md`, `book/api/carton/README.md`, `book/api/carton/API.md`, and `book/api/carton/AGENTS.md`.

Use this Preamble and the substrate as your conceptual anchor; use the layered AGENTS/README files and CARTON as your operational and data anchors. Together they define the world you are allowed to talk about and the evidence you are allowed to claim.

