# Test Coverage Inventory

 Tests in `book/` are designed as fast guardrails around the Sonoma world’s IR rather than as exhaustive semantic proofs: they strongly pin vocab and mapping structure to this host, give high-confidence runtime stories for a small golden slice of operations and profiles, and largely leave chapters, many experiments, and Swift graph logic to external review.

## Scope and Entry Points

 All automated checks flow through a single CI harness that mirrors pytest discovery without relying on pytest’s runner, and then compiles the Swift graph tools; this keeps “what passes CI” tightly coupled to the host-specific world and the mapping layer.

- Single entrypoint: `make -C book test` (default Make target) calls `book/ci.py`, which in turn runs the Python harness and the Swift build once, with coarse-grained stamps in `book/out/ci-stamps/`.
- Python side: `book/ci.py` fingerprints `book/tests`, `book/api`, `book/graph/concepts/validation`, `book/examples`, and `book/experiments`, then invokes `python -m book.tests.run_all` as a lightweight stand-in for pytest.
- Harness shape: `book/tests/run_all.py` discovers `book/tests/test_*.py` plus any `book/api/**/test_*.py` (today only `book/api/golden_runner/test_golden_runner.py`), supports a small fixture set (`tmp_path`, `monkeypatch`), and runs module-level `test_*` callables plus `unittest.TestCase` classes.
- Expectations: `book/tests/README.md` frames this as a sanity suite—fast, deterministic, with `@pytest.mark.system` on tests that shell out or depend on macOS libs, and with all asserted paths normalized to repo-relative form.
- Validation bridge: `book/graph/concepts/validation/out/validation_status.json` currently records four `ok-unchanged` jobs (`vocab:sonoma-14.4.1`, `experiment:field2`, `experiment:runtime-checks`, `experiment:system-profile-digest`), and several tests assume these jobs have run and produced their normalized IR.

## High-Level Coverage Picture

 Coverage clusters fall into four main bands: (1) structural bedrock for vocab, system profiles, tag layouts, and op-table, (2) CARTON manifest and query API contracts, (3) runtime semantics for a small “golden” operation/profile set plus a VFS canonicalization scenario, and (4) shape and presence checks for experiments, examples, and toolchain builds.

At a high level:
- Structural/mapping tests aim at the **bedrock** tier: they assert file presence, schema, world pinning, and cross-file consistency for the shared IR in `book/graph/mappings/*` and golden-corpus outputs.
- CARTON tests sit just above that, ensuring that the frozen IR (`CARTON.json` + indices) remains an accurate projection of the underlying mappings and validation IR for this world.
- Runtime tests live in the **mapped-but-partial** tier: they provide detailed allow/deny expectations for a small set of profiles and operations (notably `file-read*`, `file-write*`, and `mach-lookup`) and treat VFS canonicalization quirks as environment facts rather than decoder bugs.
- Experiments/examples/tests treat their JSON artifacts and SBPL assets as **shape-guarded** but not deeply interpreted; many assertions are “does this JSON look like we expect?” rather than “does this SBPL profile enforce every substrate claim?”.

The sections below expand each band and connect individual tests back to the concept inventory and mapping layers.

## Structural / Mapping Guardrails

 This cluster pins the static IR for the Sonoma world: Operation/Filter vocab tables, system profile digests, tag layouts, anchor/field2 mappings, and decoder behavior are treated as bedrock, and tests assert that they stay world-pinned, internally consistent, and in sync with golden-corpus and validation outputs.

In this band, tests mostly answer “are the mapping JSONs that everything else uses still present, well-formed, and aligned with the concept inventory and world baseline?” rather than “are all semantic claims complete?”. Key pieces:

- **Bedrock registry and concept inventory**
  - `book/tests/test_bedrock_registry.py` keeps `book/graph/concepts/BEDROCK_SURFACES.json` in lockstep with the bedrock navigation bullets in `CONCEPT_INVENTORY.md` and asserts that root and graph-level `AGENTS.md` files direct readers to that registry. This ties the human-facing concept story to the machine-readable surface list.

- **System profile digests, tag layouts, and world pinning**
  - `book/tests/test_mappings_guardrail.py` and `test_system_profiles_mapping.py` guard `book/graph/mappings/system_profiles/digests.json`: they require the canonical trio (`sys:airlock`, `sys:bsd`, `sys:sample`) to exist, enforce `metadata.status == "ok"`, and insist that mapping- and contract-level `world_id` values both match the Sonoma baseline in `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`.
  - The same tests ensure that tag layouts (`book/graph/mappings/tag_layouts/tag_layouts.json`) and CARTON coverage metadata reflect any future status demotions, so drift in canonical digests cannot silently remain “ok” in downstream IR.
  - `book/tests/test_tag_layout_hash.py` asserts that the tag-layout hash function is sensitive to tag-set changes but insensitive to metadata-only churn, keeping the “contract” tied to structure, not comments or notes.

- **Vocab and dyld alignment**
  - `book/tests/test_vocab_harvest.py` couples the validation vocab mapping in `book/graph/mappings/vocab/{ops.json,filters.json}` to dyld-harvested name lists from `book/experiments/vocab-from-cache/out`. It asserts identical name order, contiguous IDs, and an `ok` metadata status, effectively treating these vocab tables as the canonical Operation/Filter vocabulary for this world.
  - `book/tests/test_dyld_libs_manifest.py` shells out to `book/graph/mappings/dyld-libs/check_manifest.py` and fails if the dyld manifest and on-disk slices disagree, tying vocab derivation back to the captured dyld slice set.

- **Anchors, field2, and probe-structure links**
  - `book/tests/test_anchor_filter_alignment.py`, `test_anchor_outputs.py`, and `test_anchor_scan.py` connect the curated anchor ↔ filter mappings in `book/graph/mappings/anchors/anchor_filter_map.json` to the raw anchor hits produced by `book/experiments/probe-op-structure/out/anchor_hits.json` and to literal-pool offsets and node indices in compiled probe profiles. They require that mapped anchors have observed `field2` values and that those values are reflected in the mapping, upgrading those entries toward bedrock.
  - `book/tests/test_mappings_guardrail.py` also checks that the field2 experiment IR (`book/graph/concepts/validation/out/experiments/field2/field2_ir.json`) includes key system profiles such as `sys:bsd` and `sys:sample`, confirming that anchor/field2 work has coverage for the canonical trio.

- **Decoder structure and golden corpus**
  - `book/tests/test_decoder_headers.py`, `test_decoder_validation.py`, and `test_validation.py` sanity-check `book/api/profile_tools/decoder.py`: they decode fixtures and assert header shapes, section offsets, tag counts vs node counts, and CLI JSON dump/summary behavior. These tests treat decoder output as structurally reliable (bedrock) for the fixture set.
  - `book/tests/test_golden_corpus.py` ties the golden-corpus manifest and summary (`book/graph/concepts/validation/golden_corpus/*`) to the Sonoma `world_id` and to the tag-layout hash, ensuring that the curated corpus of compiled profiles stays synchronized with the tag-layout mapping.
  - `book/tests/test_golden_decodes.py` validates the `book/graph/mappings/runtime/golden_decodes.json` summaries (node/op counts and literal strings) for the golden runtime set, providing a stable decode view for those profiles.

Together, these tests say: if they pass, the project can treat vocab tables, canonical system digests, tag layouts, anchor mappings, and decoder output for golden fixtures as structurally trustworthy bedrock for this world.

## CARTON and API Surfaces

 The CARTON layer is tested as a frozen projection of the mapping and validation IR: the manifest, coverage and index overlays, and query helpers are all checked so that callers can rely on CARTON as the default read-only view of this world without re-reading raw JSONs.

- **Manifest and world pinning**
  - `book/tests/test_carton_manifest.py` regenerates `book/api/carton/CARTON.json` via `create_manifest.main()`, then asserts that the manifest’s file set is exactly the expected list (vocab, system digests, runtime signatures, CARTON overlays, and selected validation IR), that every path exists on disk, that SHA-256 hashes match the contents, and that no `generated_at` timestamp sneaks into the manifest.
  - The same test verifies that `world_id` in the manifest matches the Sonoma baseline world in `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`.

- **Coverage, indices, and downgrade propagation**
  - `book/tests/test_mappings_guardrail.py` ensures that `book/graph/mappings/carton/operation_coverage.json` and `book/graph/mappings/tag_layouts/tag_layouts.json` carry the same metadata status as system digests and that canonical profile statuses are present for the canonical trio.
  - `book/tests/test_concept_index_alignment.py` and `test_ops_coverage.py` assert alignment between concept indices, operation vocab, and coverage entries, and require that operations with strong runtime backing today—`file-read*`, `file-write*`, `mach-lookup`—have `runtime_evidence == True` in `ops_coverage.json`.
  - `book/tests/test_canonical_drift_scenario.py` simulates a fabricated hash drift for `sys:bsd` and exercises the system-profiles, tag-layouts, and CARTON overlay generators. It asserts that status demotions propagate all the way from digests into coverage and indices, and that unaffected profiles (e.g., `sys:airlock`) stay `ok`. This test explicitly encodes the downgrade story for canonical drift.

- **Query helpers and error paths**
  - `book/tests/test_carton_api_discovery.py`, `test_carton_api_facade.py`, `test_carton_query.py`, `test_carton_indices.py`, `test_carton_coverage_mapping.py`, `test_carton_rebuild.py`, and `test_carton_scenario.py` exercise the high-level CARTON helpers in `book/api/carton/carton_query.py`. They cover discovery calls (`list_operations`, `list_profiles`, `list_filters`), story helpers (`operation_story`, `profile_story`, `filter_story`, `profiles_and_signatures_for_operation`), and the “low coverage” and rebuild flows.
  - These tests also stress error cases: they expect `UnknownOperationError` for unknown operations, `CartonDataError` for missing or malformed mappings or hash mismatches, and confirm that profile-level stories expose conservative filter information when filter usage is not fully mapped.

When these tests pass, the project can treat CARTON as a faithful, world-pinned overlay on the mapping and validation IR, with clear failure modes if mappings drift or hashes diverge.

## Runtime and Behavioral Probes

 Runtime tests provide a dense, host-specific picture for a handful of “golden” profiles and operations, establishing that the static IR (vocab, tag layouts, system digests) agrees with observed kernel behavior for those cases; outside that slice, runtime coverage is explicitly partial.

- **Golden runtime scenarios**
  - `book/tests/test_runtime_golden.py`, `test_runtime_results_structure.py`, `test_runtime_results_outcomes.py`, `test_runtime_matrix_shape.py`, `test_runtime_results_metafilter.py`, and `test_runtime_results_system_profiles.py` all consume normalized runtime IR from `book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json` and from `book/experiments/runtime-checks/out`. They assert:
    - Presence of the golden profiles (`bucket4:v1_read`, `bucket5:v11_read_subpath`, `runtime:metafilter_any`, `runtime:strict_1`, `sys:bsd`, `sys:airlock`) in both expected matrices and runtime results.
    - Stable allow/deny patterns for file-read/write probes across different synthetic profiles (e.g., bucket 4 vs bucket 5).
    - System profile behaviors, including that `sys:bsd` denies all probes in the particular runtime-checks matrix, and that `sys:airlock` probes are recorded as EPERM/deny with a status that allows for `blocked` or `partial` (capturing apply gates rather than treating them as missing profiles).

- **Adversarial profiles and network/VFS behavior**
  - `book/tests/test_runtime_adversarial.py` and `test_network_outbound_guardrail.py` ingest artifacts from `book/experiments/runtime-adversarial/out` and assert that:
    - Expected matrices are world-pinned and profile sets match between expectations and runtime results.
    - Every mismatch in `mismatch_summary.json` is annotated in `impact_map.json`, making divergences explicit rather than silently ignoring them.
    - Carefully paired SBPL profiles for network-outbound allow/deny differ only in the `network-outbound` clause and produce expected allow/deny behavior at runtime.
  - `book/tests/test_vfs_canonicalization_outputs.py` and `test_vfs_canonicalization_structural.py` focus on the VFS canonicalization experiment (`book/experiments/vfs-canonicalization/out`), asserting:
    - Shape and presence for expected vs runtime JSON lists.
    - That a “tmp-only” profile denies all probes due to `/tmp`→`/private/tmp` canonicalization.
    - That “private-tmp-only” and “both-paths” profiles follow a predictable allow/deny pattern for file-read/write probes across `/tmp`, `/private/tmp`, and related paths, and that metadata probes deny across the board (recorded as a harness limitation).

- **Runtime mappings and signatures**
  - `book/tests/test_runtime_signatures_mapping.py` checks `book/graph/mappings/runtime/runtime_signatures.json`: it requires `metadata.status == "ok"`, absence of timestamps, correct `world_id`, presence of signatures for the golden profiles, and structured field2 summaries for key system profiles.
  - `book/tests/test_golden_decodes.py` links these signatures back to `golden_decodes.json` by requiring non-zero node/op counts and expected literal strings for `runtime:metafilter_any` and `runtime:strict_1`, tying runtime expectations to static decode details.

Collectively, these tests justify treating runtime behavior for `file-read*`, `file-write*`, `mach-lookup`, and the VFS canonicalization scenario as well-understood on this host (mapped-but-partial), while explicitly leaving most other operations and profiles in a structural-only tier.

## Experiments, Examples, and Assets

 Experiment and example tests are almost entirely structural: they ensure that curated SBPL profiles, experiment outputs, kernel symbol inventories, and example demos remain present and well-shaped so other tools and chapters can rely on them as inputs.

- **Experiment outputs**
  - `book/tests/test_experiments.py` inspects artifacts from `book/experiments/node-layout/out`, `op-table-operation/out`, and `op-table-vocab-alignment/out`, checking for expected keys (names, op entries, section lengths, alignment records) and verifying that node-layout decoder blocks contain node counts, tag counts, and op-table offsets. These tests treat those JSON files as stable IR for decoder/op-table work.
  - `book/tests/test_entitlement_diff_assets.py` and `test_kernel_string_refs.py` (not detailed here) similarly check the presence and basic structure of outputs in entitlement-diff and kernel-symbols experiments, ensuring that later consumers can assume those artifacts exist and are minimally sane.

- **Examples and SBPL/tooling scaffolds**
  - `book/tests/test_examples.py` walks `book/examples/` and runs selected demos (e.g., compile sample profiles, extract system profiles), then asserts that compiled blobs or expected outputs exist, marking system-dependent tests appropriately.
  - `book/tests/test_op_table_api.py`, `test_sbpl_compile_api.py`, `test_regex_tools.py`, `test_sbpl_graph_runtime_assets.py`, `test_sbpl_wrapper_exists.py`, `test_book_api_ghidra_connector.py`, and `test_ghidra_scaffold.py` provide smoke tests for API/tooling modules: they assert that CLIs can be imported and invoked on small inputs, that SBPL compile wrappers exist and function on sample profiles, and that Ghidra scaffolding can be imported and used to drive kernel analyses in a controlled way.
  - `book/tests/test_golden_corpus.py` doubles as both structural and example coverage, confirming that golden-corpus entries are present, world-pinned, and have decoded representations for static-only platform profiles.

These tests do not claim semantic completeness for the experiments or examples; instead they keep their artifacts stable enough that higher-level tools, chapters, and future experiments can rely on them as known-good building blocks.

## Toolchain Build (Swift)

 The Swift graph package is exercised only at the “builds successfully” level today; there are no Swift unit tests guarding behavior, so all semantic guarantees for graph IR still come from Python-side validation and mappings.

- `book/ci.py` calls `book/graph/swift_build.py` as a second step after the Python harness and records a `swift-build` stamp in `book/out/ci-stamps/`.
- The Swift package parses mapping JSONs and emits a lightweight validation report, but CI currently treats any successful build as sufficient; failures stop the build, but no additional assertions are made about Swift-side logic.
- There are no Swift tests under `book/graph` analogous to the Python tests in `book/tests/`, so Swift changes rely on mapping/json invariants and manual inspection rather than an automated test suite.

## Evidence Tiers and Status

 Test coverage lines up cleanly with the project’s evidence tiers: structural and vocab clusters are treated as bedrock, runtime/lifecycle work as mapped-but-partial, and much of the narrative/experiment layer as substrate-only or shape-guarded.

- **Bedrock cluster**
  - `book/graph/concepts/validation/out/validation_status.json` lists four jobs, all `ok-unchanged` for this world: vocab extraction (`vocab:sonoma-14.4.1`), field2 experiment normalization, runtime-checks normalization, and system-profile-digest IR. Many mapping tests (vocab, system digests, tag layouts, runtime signatures) implicitly assume these jobs have produced their outputs.
  - Bedrock surfaces in `book/graph/concepts/BEDROCK_SURFACES.json` are enforced via `test_bedrock_registry.py`; system digests in `book/graph/mappings/system_profiles/digests.json` and tag-layouts in `book/graph/mappings/tag_layouts/tag_layouts.json` are treated as `status: ok` and world-pinned unless an explicit drift scenario is staged.

- **Mapped-but-partial cluster**
  - Runtime mappings in `book/graph/mappings/runtime/runtime_signatures.json` have `metadata.status == "ok"` but intentionally cover only the golden profile set and the operations exercised by runtime-checks and runtime-adversarial. Tests confirm this slice is consistent and well-formed; they do not claim coverage for all 196 operations.
  - `book/graph/mappings/vocab/ops_coverage.json` encodes structural vs runtime evidence flags per operation. `test_ops_coverage.py` asserts that `file-read*`, `file-write*`, and `mach-lookup` have both `structural_evidence` and `runtime_evidence` set to `True`, while leaving most other ops as structural-only by design.
  - Experiments like runtime-adversarial and vfs-canonicalization record EPERM apply gates and VFS quirks explicitly; tests enforce that these are captured and annotated (`status: ok/partial/blocked` at the profile or probe level) rather than silently normalized away.

- **Substrate-only and shape-guarded areas**
  - System profiles that cannot be applied on this host (e.g., platform `airlock`) are still present in static mappings and golden-corpus decodes, and runtime tests treat their EPERM behavior as part of the environment rather than as missing profiles.
  - Many experiment Reports/Notes and chapter markdown files (including the TextEdit narrative) have no direct tests; their claims remain in the substrate or narrative tier, backed indirectly by the artifacts they reference rather than by automated assertions.
  - Shape tests over experiments (`test_experiments.py`, entitlement and kernel symbol checks) keep IR present and structurally coherent but do not upgrade the semantic content of those experiments to bedrock.

## Gaps and Next Focus

 The main gaps are breadth of runtime semantics, lifecycle/entitlement coverage, Swift-side behavior, and automated checks for narrative drift; closing them will require new experiments and validation jobs rather than just more shape tests.

- **Runtime breadth and operation coverage**
  - Today, strong runtime evidence is concentrated on `file-read*`, `file-write*`, `mach-lookup`, and a narrow VFS canonicalization scenario. Most operations in `ops_coverage.json` have `runtime_evidence == False`.
  - Next steps would be to extend `runtime-adversarial` and related experiments to additional operations (for example, `mach-lookup` variants, network filters beyond the current probes, and container-related operations), promote their normalized IR into `book/graph/mappings/runtime/`, and add guardrail tests that mirror the existing golden/runtime patterns.

- **Lifecycle, entitlements, and extensions**
  - Lifecycle traces and entitlement/extension scenarios are present in validation IR and some experiments, but there are few direct tests asserting their shape or semantic expectations.
  - New tests could: (1) assert schema and world pinning for `book/graph/mappings/runtime/lifecycle.json` and lifecycle traces; (2) tie specific entitlements/extension scenarios to expected labels or profile stacks; and (3) encode “golden” lifecycle behaviors in the same way runtime-checks does for operations.

- **API/tooling and Swift depth**
  - Many `book/api/` modules (decoder, op_table, inspect_profile, runtime_golden, file_probe, ghidra helpers) are covered by smoke tests but lack deeper behavioral assertions (for example, detailed checks on op-table alignment or decode/lifecycle joins).
  - The Swift graph package currently has build-only coverage. Introducing small Swift tests that re-encode key invariants (e.g., that runtime signatures reference valid vocab IDs and profiles present in digests) would mirror the Python-side guardrails and catch drift early.

- **Narrative and experiment consistency**
  - Chapters under `book/chapters/` and detailed profiles narratives (such as the TextEdit notes) rely on the underlying mappings and experiments but are not themselves checked for consistency (e.g., that example operation names still exist in vocab, or that cited profile IDs still appear in digests and CARTON).
  - Experiment `Report.md`/`Notes.md` files (for example, `bedrock-followups`, `sandbox-init-params`, `symbol-search`) are lightly or not at all tested; adding minimal checks that referenced artifacts exist and that cited mapping paths are still valid would reduce drift between prose and IR.

- **Harness and environment assumptions**
  - The CI harness assumes `pytest` is importable (for fixtures) and that the Sonoma world baseline and dyld slices are present on disk. Tests do not currently guard against running in an environment where those assumptions fail (for example, missing dyld manifest, partial world checkout).
  - Future work might add explicit “environment sanity” tests—checking for the presence and hash of `world-baseline.json`, dyld slices, and key mapping files before running more expensive tests—and surfacing clearer failure messages when the host state no longer matches the captured baseline.

These gaps are not failures of the current suite—they reflect an intentional focus on structural bedrock and a small, well-understood runtime slice. They mark the places where new experiments, validation jobs, and then tests would move more concepts from “substrate-only” or “mapped-but-partial” toward bedrock for this Sonoma world.
