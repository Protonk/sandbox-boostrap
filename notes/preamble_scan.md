# Preamble rewrite prep

## Guidance landmarks
- `guidance/Preamble.md` — under review; current agent-facing guidance.
- Overlapping guidance: root `AGENTS.md`, root `README.md`, `book/AGENTS.md`, `book/graph/AGENTS.md`, `book/experiments/AGENTS.md`, `book/api/AGENTS.md` + `book/api/carton/AGENTS.md`, `guidance/AGENTS.md` (cordons off thread prompts), `book/experiments/Experiments.md`, `book/tests/README.md`, `book/world/README.md`.
- Current Preamble gist: frames SANDBOX_LORE as a static-first, Sonoma-bound atlas where vocab/layout mappings are solid, runtime behavior is fragile, and kernel/entitlement/lifecycle work is provisional. Emphasizes using substrate vocabulary, treating validation statuses as meaning, leaning on decoders/op-table/tag-layout mappings, and acknowledging apply gates and incomplete runtime coverage.

## Repo structure inventory (agent-facing)

### Substrate + concept inventory
- Paths: `substrate/*.md`, `book/graph/concepts/{CONCEPT_INVENTORY.md,concepts.json,...}`, `book/graph/README.md`.
- Purpose: normative theory + generated concept set for this host; Swift generator ties substrate to concept JSON and validation strategies.
- Entry points: `cd book/graph && swift run` emits concept JSON, strategies, validation report.
- Invariants/metadata: concept names/relations come from CONCEPT_INVENTORY; generated JSON is source for validation/code; keep host binding via world_id.

### Mapping / IR backbone
- Paths: `book/graph/mappings/{vocab,op_table,anchors,tag_layouts,system_profiles,runtime,dyld-libs,carton}/`, manifest `book/api/carton/CARTON.json`, baseline `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json` (world_id `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).
- Purpose: stable host-specific IR (op/filter vocab, op-table alignment, tag layouts, anchor→field2/filter maps, system profile digests/attestations/static checks, runtime expectations/traces/lifecycle, dyld slice manifest, CARTON coverage/indices).
- Entry points: `book/graph/mappings/run_promotion.py` (runs validation + generators), per-cluster generators (`runtime/generate_runtime_signatures.py`, `runtime/generate_lifecycle.py`, `system_profiles/generate_static_checks.py`, `system_profiles/generate_attestations.py`, `vocab/generate_attestations.py`, `carton/generate_*` scripts), CARTON manifest builder `book/api/carton/create_manifest.py`.
- Invariants/status: every mapping JSON carries metadata (world_id, inputs/source_jobs, status like ok/partial/brittle/blocked, hashes, host/build); manifest hashes guard CARTON files; dyld-libs manifest checked by `book/tests/test_dyld_libs_manifest.py`; vocab coverage file (`vocab/ops_coverage.json`) distinguishes runtime-backed ops.

### Validation + experiments pipeline
- Paths: validation harness `book/graph/concepts/validation/` (registry/driver, fixtures, strategies, status schema, `out/` IR), experiments under `book/experiments/*` with Plan/Report/Notes/out, experiments router `book/experiments/Experiments.md`.
- Purpose: bridge from theory to artifacts; experiments generate raw/normalized IR, validation driver normalizes and records status; promotion reads normalized IR only.
- Entry points: `python -m book.graph.concepts.validation --list|--all|--tag <tag>|--describe <job>`; smoke tag runs vocab+field2+runtime-checks; experiment-specific jobs registered in registry. Experiment outputs live in `out/`; promotion pulls from `book/graph/concepts/validation/out/...`.
- Invariants/status: `validation/out/index.json` + `validation_status.json` track status per job (schema enforced by `--tag meta`); `README.md` marks current state (static ok, runtime/lifecycle partial); experiments have host-bound IDs and expected scaffolding; statuses ok/partial/brittle/blocked are semantic.

### APIs and tooling
- Paths: `book/api/{decoder,sbpl_compile,inspect_profile,op_table,regex_tools,SBPL-wrapper,file_probe,runtime_golden,golden_runner,ghidra,carton}/`, `book/api/README.md`, `book/api/carton/API.md`.
- Purpose: reusable helpers for decoding/compiling profiles, op-table parsing, runtime harnesses, golden runner, Ghidra scaffold, and CARTON query surface.
- Entry points: Python CLIs (`python -m book.api.op_table.cli ...`, `python -m book.api.inspect_profile.cli ...`, `python -m book.api.runtime_golden.generate`, `python -m book.api.golden_runner.cli ...`), SBPL-wrapper build/run per README, Ghidra CLI, CARTON API (`from book.api.carton import carton_query`; helpers like `operation_story`, `profile_story`, `filter_story`, `runtime_signature_info`, `ops_with_low_coverage`).
- Invariants/status: Tools assume vocab/tag-layout mappings; CARTON queries go through manifest hashes and raise `UnknownOperationError` vs `CartonDataError`; runtime_golden/golden_runner support runtime-checks “golden” set; SBPL-wrapper treats apply EPERM as blocked.

### Examples, profiles, chapters, world
- Paths: `book/examples/` (16 runnable demos; lessons + run scripts), `book/profiles/` (golden-triple, textedit, shared SBPL), `book/chapters/` + `book/Outline.md`, `book/world/` (baseline manifests).
- Purpose: human-facing labs and SBPL/profile sources for examples and chapters; curated golden profiles; host baseline data and dyld manifest template.
- Entry points: example scripts (e.g., `book/examples/sb/run-demo.sh`, `extract_sbs/run-demo.sh`), profile README in subfolders; world README/template for new baselines.
- Invariants/status: profiles marked provisional/golden via schema; world-baseline.json treated immutable once set; examples rely on libsandbox/sandbox-exec availability.

### Tests / guardrails
- Paths: `book/tests/*` (smoke/imports, example runners, validation fixture decoder checks, experiment artifact shape checks, op_table CLI sanity, dyld manifest check), `pytest.ini`.
- Purpose: ensure mappings/artifacts exist and schemas stay aligned; runnable via single entrypoint.
- Entry point: `make -C book test` (activates Python harness + Swift build); uses repo-local runners not direct pytest by default.
- Invariants/status: tests assume experiment outputs present (node-layout, op-table, etc.), fixture decodes consistent (op_table length == op_count), dyld manifest hashes match trimmed slices.

### Other landmarks
- `dumps/` and `troubles/` exist but are gated by their `AGENTS.md`; dumps contain private artifacts that must not be copied into tracked dirs.

## Preamble drift analysis
- Keep/strengthen: single-host baseline and “static artifacts first”; vocab/format mappings as backbone; statuses (`ok/partial/brittle/blocked`) are meaningful; apply gates and runtime uncertainty should be acknowledged when present; avoid inventing op/filter names.
- Update/rename: highlight CARTON as frozen manifest-backed IR with coverage/indices + manifest hashing; point to layered AGENTS/README routers instead of Preamble as sole map; note validation driver (`python -m book.graph.concepts.validation`) and promotion pipeline (`run_promotion.py` + generators) as canonical path from experiments → mappings → CARTON; runtime story now includes normalized expectations/traces and runtime_signatures mapping with golden set (file-read*/file-write*/mach-lookup aligned except known /tmp redirect quirk); world baseline lives in `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json` and stamps mappings.
- Remove/retire: avoid treating thread prompt files under `guidance/` as operative repo guidance; retire any implication that agents should hand-edit mapping JSONs (pipeline now explicit and manifest-guarded); drop reliance on Preamble as master router now that layered AGENTS/README and CARTON API exist.

## Outline for future Preamble rewrite
- Scope & baseline: single Sonoma host, world_id, SIP on; status semantics.
- Where to read first: root README + layered AGENTS (book/, graph/, experiments/, api/), substrate docs.
- Canonical IR backbone: `book/graph/mappings/*` (vocab, op_table, tag_layouts, anchors, system_profiles, runtime, dyld-libs) + metadata/status expectations.
- Concept inventory & validation: substrate → `book/graph/concepts`, Swift generator, validation driver/registry, validation out/ index/status.
- CARTON: manifest (`CARTON.json`), API usage patterns, hash enforcement, coverage/indices.
- Experiments → promotion flow: experiment scaffolding, validation jobs/tags (smoke/golden), normalized IR, promotion script and mapping generators; note statuses must be carried through.
- Tools/API layer: decoder/op_table/inspect_profile/sbpl_compile, SBPL-wrapper + file_probe, runtime_golden/golden_runner, Ghidra scaffold; encourage reuse over reimplementation.
- Examples/profiles/chapters: where runnable probes and golden profiles live; link to world baseline and profile schemas.
- Tests/guardrails: single `make -C book test` entrypoint; what invariants tests enforce (artifact presence, schema, manifest hashes).
- Unknowns/tensions: explicit slot to mark open questions or blocked areas (e.g., incomplete runtime coverage, unresolved kernel dispatcher) with references to experiments/validation bounding current knowledge.
