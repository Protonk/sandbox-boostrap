# Test Coverage Inventory

## Scope and Entry Points
Kernel: Single entrypoint `make -C book test` runs the Python sanity harness (`book/tests/run_all.py`) plus the Swift graph build; tests are lightweight guardrails rather than full semantic coverage.
- `book/ci.py` fingerprints `book/tests`, `book/api`, `book/graph/concepts/validation`, `book/examples`, and `book/experiments`, runs the harness, then calls `graph/swift_build.py` (stamping results under `book/out/ci-stamps/`).
- `book/tests/README.md` sets expectations: fast/deterministic, `@pytest.mark.system` for host-tied cases, repo-relative paths only.
- `book/tests/run_all.py` imports all `book/tests/test_*.py` plus any `book/api/**/test_*.py` (today only `book/api/golden_runner/test_golden_runner.py`) with limited fixtures (`tmp_path`, `monkeypatch`).
- Validation jobs currently registered in `book/graph/concepts/validation/out/validation_status.json` are `ok-unchanged` for `vocab:sonoma-14.4.1`, `experiment:field2`, `experiment:runtime-checks`, and `experiment:system-profile-digest`.

## Coverage Inventory
Kernel: Coverage centers on structural/contract checks for bedrock mappings and CARTON, with targeted runtime probes for a small set of operations; most tests assert shape, provenance, and world pinning rather than broad behavioral semantics.

### Mapping and Vocab Guardrails
Kernel: Bedrock/static IR is checked for presence, shape, world pinning, and downgrade propagation.
- `book/tests/test_bedrock_registry.py` keeps `book/graph/concepts/BEDROCK_SURFACES.json` aligned with `CONCEPT_INVENTORY.md` and ensures AGENTS files point at the registry.
- `book/tests/test_mappings_guardrail.py` and `test_system_profiles_mapping.py` pin system profile digests (`status: ok`, world_id), canonical profile set, tag layout/world propagation, anchor map presence, field2 IR (`book/graph/concepts/validation/out/experiments/field2/field2_ir.json`), and op-table metadata/counts.
- `book/tests/test_vocab_harvest.py` and `test_dyld_libs_manifest.py` confirm vocab tables match dyld-harvested names and that the dyld manifest checker passes for `libsandbox`.
- `book/tests/test_anchor_filter_alignment.py`, `test_anchor_outputs.py`, and `test_anchor_scan.py` tie mapped anchors to observed `anchor_hits.json` field2 values and literal-pool offsets in `probe-op-structure` outputs.
- Decoder/structural checks (`test_decoder_headers.py`, `test_decoder_validation.py`, `test_validation.py`, `test_tag_layout_hash.py`, `test_golden_corpus.py`, `test_golden_decodes.py`) cover header parsing, fixture decoding, tag layout hashing, golden-corpus manifest alignment, and golden decode content.

### CARTON and API Surfaces
Kernel: CARTON hashes, indices, and error paths are validated against the frozen manifest and world baseline.
- `book/tests/test_carton_manifest.py` regenerates `book/api/carton/CARTON.json` and asserts path set and hashes match expected mappings/validation outputs and baseline world_id.
- `book/tests/test_carton_api_discovery.py`, `test_carton_api_facade.py`, `test_carton_query.py`, `test_carton_indices.py`, `test_carton_coverage_mapping.py`, `test_carton_rebuild.py`, and `test_carton_scenario.py` exercise discovery helpers, story helpers, coverage/index generation, rebuild flows, and failure modes (`UnknownOperationError`, `CartonDataError`).
- Coverage metadata downgrades are propagated and asserted in `test_canonical_drift_scenario.py`, ensuring demotions in digests flow into tag layouts and CARTON overlays.
- `book/tests/test_concept_index_alignment.py` and `test_ops_coverage.py` assert concept/operation coverage alignment and runtime evidence flags (`file-read*`, `file-write*`, `mach-lookup` must have runtime evidence in `ops_coverage.json`).
- `book/tests/test_mappings_guardrail.py` also checks CARTON coverage metadata mirrors canonical profile status.

### Runtime and Behavioral Probes
Kernel: Targeted runtime suites cover golden profiles and adversarial cases; runtime evidence is strong for `file-read*`, `file-write*`, and `mach-lookup` but sparse elsewhere.
- `book/tests/test_runtime_golden.py`, `test_runtime_results_structure.py`, `test_runtime_results_outcomes.py`, `test_runtime_matrix_shape.py`, `test_runtime_results_metafilter.py`, and `test_runtime_results_system_profiles.py` assert normalized runtime results from `runtime-checks` (allow/deny patterns, schema, probe sets) and record `sys:airlock` EPERM apply gates as `deny`/`blocked`.
- `book/tests/test_runtime_adversarial.py` and `test_network_outbound_guardrail.py` check adversarial probes (metafilter variants, mach-local/global, network-outbound allow/deny) against `book/experiments/runtime-adversarial/out` expected matrices and runtime results.
- `book/tests/test_runtime_signatures_mapping.py` and `test_runtime_golden.py` verify `book/graph/mappings/runtime/runtime_signatures.json` content, probe summaries, and field2 summaries align with golden decodes and world metadata.
- `book/tests/test_vfs_canonicalization_outputs.py` and `test_vfs_canonicalization_structural.py` pin the observed `/tmp`→`/private/tmp` canonicalization pattern and note metadata probes deny across the board (harness limitation captured in expected outputs).
- `book/tests/test_golden_decodes.py` and `book/graph/mappings/runtime/golden_decodes.json` ensure decode-level literals and counts remain stable for the golden runtime set.

### Experiments, Examples, and Assets
Kernel: Shape checks ensure experiment outputs and example artifacts remain present and structurally coherent.
- `book/tests/test_experiments.py` covers node-layout, op-table-operation, and op-table-vocab-alignment outputs for key fields; `test_entitlement_diff_assets.py`, `test_kernel_string_refs.py`, and `test_examples.py` assert presence/shape of entitlements, kernel string refs, and example build artifacts (system-tagged where appropriate).
- `book/tests/test_op_table_api.py`, `test_sbpl_compile_api.py`, `test_regex_tools.py`, `test_sbpl_graph_runtime_assets.py`, `test_sbpl_wrapper_exists.py`, `test_book_api_ghidra_connector.py`, and `test_ghidra_scaffold.py` sanity check API entrypoints, CLI wrappers, and Ghidra scaffolding.
- `book/tests/test_golden_corpus.py` keeps the golden-corpus manifest/summary aligned with the Sonoma baseline and tag-layout hash.
- `book/tests/test_network_outbound_guardrail.py` and `test_runtime_adversarial.py` reuse experiment assets to enforce behavioral expectations for adversarial probes.

### Toolchain Build
Kernel: The Swift graph package is built as part of the CI harness; build success is the only enforced check today.
- `book/ci.py` runs `swift_build.py` after the Python harness and records stamps under `book/out/ci-stamps/`.
- No Swift-level unit tests are present; the build step catches compile-time drift only.

## Evidence Status and Classification
Kernel: Structural/vocab/mapping checks ride on `status: ok` artifacts and bedrock surfaces; runtime coverage is limited to a small subset of operations with `ops_coverage.json` marking the rest as structural-only.
- `book/graph/concepts/validation/out/validation_status.json` lists four jobs, all `ok-unchanged` (vocab, field2, runtime-checks, system-profile-digest) tied to `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Bedrock registry enforced via `book/tests/test_bedrock_registry.py`; canonical system profiles are `status: ok` in `book/graph/mappings/system_profiles/digests.json` and propagate to tag layouts and CARTON overlays.
- `book/graph/mappings/runtime/runtime_signatures.json` is `status: ok` but only includes probes for the golden set; `book/graph/mappings/vocab/ops_coverage.json` marks most operations as structural-only with runtime evidence restricted to `file-read*`, `file-write*`, and `mach-lookup`.
- System profiles with apply gates (e.g., `sys:airlock`) remain in scope; runtime tests treat EPERM as recorded `blocked`/`deny`, not absence.
- Many experiment-driven checks are shape/sanity tier; they do not upgrade semantic claims beyond the recorded experiment status (`partial`/`blocked` where applicable in Reports/Notes).

## Gaps and Next Focus
Kernel: Biggest gaps are breadth of runtime semantics, lifecycle/entitlement coverage, and lack of tests for narrative/prose drift or Swift logic; many experiments are only shape-checked.
- Runtime breadth: only a handful of operations have runtime evidence; no adversarial coverage for most of the 196 ops, and container/extension scenarios are largely untested beyond existing lifecycle traces.
- Lifecycle/entitlements: few automated checks for entitlement-driven profile selection/stacking or extension dynamics; lifecycle traces exist but lack guardrail tests.
- API/tooling depth: `book/api/` modules other than CARTON and sbpl/decoder wrappers have minimal direct tests; the Swift generator has build-only coverage.
- Experiments and chapters: narrative markdown (chapters/TextEdit) and several experiments (`bedrock-followups`, `sandbox-init-params`, `symbol-search`, etc.) lack dedicated assertions beyond presence/shape; Report/Notes consistency is untested.
- CI hygiene: harness depends on `pytest` availability and assumes local macOS facilities for system-tagged tests; missing guards for running under alternate environments or without the Sonoma baseline artifacts.
