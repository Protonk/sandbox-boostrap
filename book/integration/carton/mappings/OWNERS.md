# Mapping owners index

This index covers artifacts under `book/integration/carton/bundle/relationships/mappings/`. It lists the generator or source, primary inputs, and guardrail tests. Items included in the CARTON spec are also checked by `book/integration/tests/carton/test_carton_manifest.py` and `book/integration/tests/carton/test_carton_check.py`.

## dyld-libs

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/dyld-libs/{manifest.json,usr/**}` | manual extraction from dyld cache; validate with `book/integration/carton/mappings/dyld-libs/check_manifest.py` | host dyld shared cache (libsandbox slice) | `book/integration/tests/graph/test_dyld_libs_manifest.py` |

## vocab

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json,operation_names.json,filter_names.json}` | `book/integration/carton/mappings/vocab/generate_vocab_from_dyld.py` | `book/integration/carton/bundle/relationships/mappings/dyld-libs/usr/lib/libsandbox.1.dylib` | `book/integration/tests/graph/test_vocab_harvest.py` |
| `book/integration/carton/bundle/relationships/mappings/vocab/ops_coverage.json` | `book/integration/carton/mappings/vocab/generate_ops_coverage.py` | `book/integration/carton/bundle/relationships/mappings/vocab/ops.json`<br>`book/integration/carton/bundle/relationships/mappings/runtime/runtime_coverage.json` (if present)<br>`book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/expected_matrix.json`<br>`book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/expected_matrix.json`<br>`book/profiles/golden-triple/expected_matrix.json` | `book/integration/tests/graph/test_ops_coverage.py` |
| `book/integration/carton/bundle/relationships/mappings/vocab/attestations.json` | `book/integration/carton/mappings/vocab/generate_attestations.py` | `book/integration/carton/bundle/relationships/mappings/vocab/ops.json`<br>`book/integration/carton/bundle/relationships/mappings/vocab/filters.json`<br>`book/evidence/graph/concepts/validation/out/validation_status.json`<br>`book/evidence/graph/concepts/validation/out/metadata.json`<br>canonical profile blobs from `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json` | `book/integration/tests/graph/test_vocab_harvest.py` (validates ops/filters inputs) |

## op_table

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/op_table/{op_table_operation_summary.json,op_table_map.json,op_table_signatures.json,op_table_vocab_alignment.json,metadata.json}` | `book/integration/carton/mappings/op_table/generate_op_table_mappings.py` | `book/evidence/experiments/profile-pipeline/node-layout/out/summary.json`<br>`book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_map.json`<br>`book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_signatures.json`<br>`book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json`<br>`book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json}` | `book/integration/tests/graph/test_mappings_guardrail.py`<br>`book/integration/tests/contracts/test_op_table_api.py` |
| `book/integration/carton/bundle/relationships/mappings/op_table/op_table_catalog_v1.json` | `book/tools/sbpl/op_table_runner.py` (promoted experiment output) | `book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_catalog_v1.json` | `book/integration/tests/contracts/test_op_table_api.py` |

## anchors

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/anchors/anchor_field2_map.json` | `book/integration/carton/mappings/anchors/generate_anchor_field2_map.py` | `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json` (and optional `anchor_hits_delta.json`) | `book/integration/tests/graph/test_anchor_field2_alignment.py` |
| `book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json` | `book/integration/carton/mappings/anchors/generate_anchor_ctx_filter_map.py` | `book/integration/carton/bundle/relationships/mappings/anchors/anchor_field2_map.json`<br>`book/integration/carton/bundle/relationships/mappings/vocab/filters.json`<br>probe and system blobs referenced by `probe-op-structure` and `system_profiles` | `book/integration/tests/graph/test_anchor_filter_alignment.py` |
| `book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json` | `book/integration/carton/mappings/anchors/generate_anchor_filter_map.py` | `book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json` | `book/integration/tests/graph/test_anchor_filter_map_is_generated.py`<br>`book/integration/tests/graph/test_anchor_filter_alignment.py`<br>`book/integration/tests/graph/test_anchor_filter_map_cfprefsd_runtime_lift.py` |

## tag_layouts

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` | `book/integration/carton/mappings/tag_layouts/generate_tag_layouts.py` + `book/integration/carton/mappings/tag_layouts/annotate_metadata.py` | canonical blobs from `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json` | `book/integration/tests/graph/test_tag_layout_hash.py` |
| `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_u16_roles.json` | `book/integration/carton/mappings/tag_layouts/generate_tag_u16_roles.py` | `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`<br>`book/integration/carton/bundle/relationships/mappings/vocab/filters.json`<br>canonical blobs from `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json` | `book/integration/tests/graph/test_tag_roles_validation.py` |

## system_profiles

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json` | `book/integration/carton/mappings/system_profiles/generate_digests_from_ir.py` | `book/evidence/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json`<br>`book/integration/carton/bundle/relationships/mappings/system_profiles/static_checks.json` | `book/integration/tests/graph/test_system_profiles_mapping.py`<br>`book/integration/tests/graph/test_system_profile_metadata.py`<br>`book/integration/tests/graph/test_mappings_guardrail.py` |
| `book/integration/carton/bundle/relationships/mappings/system_profiles/static_checks.json` | `book/integration/carton/mappings/system_profiles/generate_static_checks.py` | canonical blobs from `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json`<br>`book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` | `book/integration/tests/graph/test_system_profile_metadata.py` |
| `book/integration/carton/bundle/relationships/mappings/system_profiles/{attestations.json,attestations/*.jsonl}` | `book/integration/carton/mappings/system_profiles/generate_attestations.py` | `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json`<br>`book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json`<br>`book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json`<br>`book/integration/carton/bundle/relationships/mappings/vocab/{ops.json,filters.json}`<br>`book/integration/carton/bundle/relationships/mappings/runtime/expectations.json` (optional)<br>`book/evidence/graph/concepts/validation/out/semantic/runtime_results.json` (optional) | `book/integration/tests/graph/test_system_profiles_mapping.py` |
| `book/integration/carton/bundle/relationships/mappings/system_profiles/header_contract.json` | `book/integration/carton/mappings/system_profiles/generate_header_contract.py` | canonical blobs from `book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json` | `book/integration/tests/contracts/test_header_contract.py` |

## runtime_cuts

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/runtime_cuts/{events_index.json,ops.json,scenarios.json,runtime_indexes.json,runtime_manifest.json,runtime_story.json,traces/*.jsonl}` | `book/integration/carton/mappings/runtime/promote_from_packets.py` (uses `book/api/runtime/analysis/mapping/build.py`) | `book/integration/carton/bundle/relationships/mappings/runtime/packet_set.json`<br>promotion packets referenced by that set under `book/evidence/experiments/runtime-final-final/**/promotion_packet.json` | `book/integration/tests/runtime/test_runtime_matrix_shape.py`<br>`book/integration/tests/runtime/test_runtime_mismatch_packets.py`<br>`book/integration/tests/runtime/test_runtime_contract.py` |

## runtime

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/runtime/{runtime_coverage.json,runtime_signatures.json,runtime_links.json,op_runtime_summary.json,runtime_callout_oracle.json,promotion_receipt.json}` | `book/integration/carton/mappings/runtime/promote_from_packets.py` (calls `generate_runtime_*` helpers) | `book/integration/carton/bundle/relationships/mappings/runtime/packet_set.json`<br>promotion packets under `book/evidence/experiments/runtime-final-final/**/promotion_packet.json`<br>`book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_story.json` | `book/integration/tests/runtime/test_runtime_contract_guardrails.py`<br>`book/integration/tests/runtime/test_runtime_links_mapping.py`<br>`book/integration/tests/runtime/test_runtime_op_summary.py`<br>`book/integration/tests/runtime/test_runtime_signatures_mapping.py` |
| `book/integration/carton/bundle/relationships/mappings/runtime/expectations.json` | `book/integration/carton/mappings/runtime/generate_expectations.py` | `book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_story.json`<br>`book/integration/carton/bundle/relationships/mappings/runtime/traces/*.jsonl`<br>`book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/impact_map.json`<br>`book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/run_manifest.json` | `book/integration/tests/runtime/test_runtime_expectations.py` |
| `book/integration/carton/bundle/relationships/mappings/runtime/{lifecycle.json,lifecycle_story.json,lifecycle_coverage.json,lifecycle_traces/*.jsonl}` | `book/integration/carton/mappings/runtime/generate_lifecycle.py` | `book/evidence/graph/concepts/validation/out/lifecycle/entitlements.json`<br>`book/evidence/graph/concepts/validation/out/lifecycle/extensions_dynamic.md`<br>`book/evidence/graph/concepts/validation/out/metadata.json` | `book/integration/tests/runtime/test_lifecycle_manifest.py`<br>`book/integration/tests/runtime/test_lifecycle_cross_checks.py` |
| `book/integration/carton/bundle/relationships/mappings/runtime/{golden_expectations.json,golden_decodes.json,decoded_blobs/*,traces/golden_traces.jsonl}` | `book/api/runtime/execution/workflow.py` (generate_golden_artifacts) | `book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/expected_matrix.json`<br>`book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/runtime_results.json` | `book/integration/tests/runtime/test_golden_decodes.py`<br>`book/integration/tests/runtime/test_runtime_golden.py` |
| `book/integration/carton/bundle/relationships/mappings/runtime/packet_set.json` | curated list used by promotion | promotion packets under `book/evidence/experiments/runtime-final-final/**/promotion_packet.json` | `book/integration/tests/runtime/test_runtime_promotion_packet_set.py` |
| `book/integration/carton/bundle/relationships/mappings/runtime/other_runtime_inventory.json` | `book/integration/carton/mappings/runtime/generate_other_runtime_inventory.py` | `book/evidence/experiments/runtime-final-final/suites/hardened-runtime/other_runtime_inventory.json` | `book/integration/tests/runtime/test_hardened_runtime_inventory.py` |
| `book/integration/carton/bundle/relationships/mappings/runtime/adversarial_summary.json` | promoted runtime-adversarial summary (no CARTON generator yet) | `book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/*` | `book/integration/tests/runtime/test_runtime_adversarial.py` |

## vfs_canonicalization

| Artifact(s) | Generator / source | Inputs | Guardrails |
| --- | --- | --- | --- |
| `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/{packet_set.json,promotion_receipt.json,path_canonicalization_map.json}` | `book/integration/carton/mappings/vfs_canonicalization/generate_path_canonicalization_map.py` | `book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/packet_set.json`<br>promotion packets referenced by that set under `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/out/` | `book/integration/tests/graph/test_vfs_canonicalization_map_is_generated.py`<br>`book/integration/tests/runtime/test_vfs_canonicalization_outputs.py`<br>`book/integration/tests/runtime/test_vfs_canonicalization_structural.py` |
