"""Registry definition for CARTON artifacts and jobs."""

from __future__ import annotations

from typing import List

from book.integration.carton.core.models import Artifact, Job, Registry
from book.integration.carton.jobs import contracts as contracts_jobs
from book.integration.carton.jobs import fixers as fixer_jobs
from book.integration.carton.jobs import mappings as mapping_jobs
from book.integration.carton.jobs import specs as specs_jobs


def build_registry() -> Registry:
    artifacts: List[Artifact] = [
        Artifact(
            id="vocab.ops",
            path="book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id"],
        ),
        Artifact(
            id="vocab.filters",
            path="book/integration/carton/bundle/relationships/mappings/vocab/filters.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id"],
        ),
        Artifact(
            id="system_profiles.digests",
            path="book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.relationships.operation_coverage",
            path="book/integration/carton/bundle/relationships/operation_coverage.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.relationships.operation_system_profiles",
            path="book/integration/carton/bundle/relationships/operation_system_profiles.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.relationships.profile_layer_ops",
            path="book/integration/carton/bundle/relationships/profile_layer_ops.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.relationships.filter_usage",
            path="book/integration/carton/bundle/relationships/filter_usage.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.relationships.anchor_field2",
            path="book/integration/carton/bundle/relationships/anchor_field2.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.relationships.concept_sources",
            path="book/integration/carton/bundle/relationships/concept_sources.json",
            role="mapping",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.views.operation_index",
            path="book/integration/carton/bundle/views/operation_index.json",
            role="view",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.views.profile_layer_index",
            path="book/integration/carton/bundle/views/profile_layer_index.json",
            role="view",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.views.filter_index",
            path="book/integration/carton/bundle/views/filter_index.json",
            role="view",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.views.anchor_index",
            path="book/integration/carton/bundle/views/anchor_index.json",
            role="view",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="carton.views.concept_index",
            path="book/integration/carton/bundle/views/concept_index.json",
            role="view",
            hash_mode="semantic_json",
            checks=["metadata_world_id", "metadata_inputs"],
        ),
        Artifact(
            id="validation.field2_ir",
            path="book/evidence/graph/concepts/validation/out/experiments/field2/field2_ir.json",
            role="provenance",
            hash_mode="semantic_json",
        ),
        Artifact(
            id="validation.system_profile_digests_ir",
            path="book/evidence/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json",
            role="provenance",
            hash_mode="semantic_json",
        ),
        Artifact(
            id="validation.vocab_status",
            path="book/evidence/graph/concepts/validation/out/vocab_status.json",
            role="status",
            hash_mode="semantic_json",
            checks=["inputs_field"],
        ),
        Artifact(
            id="validation.status",
            path="book/evidence/graph/concepts/validation/out/validation_status.json",
            role="status",
            hash_mode="semantic_json",
            checks=["top_level_world_id"],
        ),
        Artifact(
            id="contracts.vocab",
            path="book/integration/carton/bundle/contracts/vocab.contract.json",
            role="derived",
            hash_mode="semantic_json",
            schema="contracts_vocab.schema.json",
            checks=["top_level_world_id", "inputs_field"],
        ),
        Artifact(
            id="contracts.profiles",
            path="book/integration/carton/bundle/contracts/profiles.contract.json",
            role="derived",
            hash_mode="semantic_json",
            schema="contracts_profiles.schema.json",
            checks=["top_level_world_id", "inputs_field"],
        ),
        Artifact(
            id="contracts.coverage",
            path="book/integration/carton/bundle/contracts/coverage.contract.json",
            role="derived",
            hash_mode="semantic_json",
            schema="contracts_coverage.schema.json",
            checks=["top_level_world_id", "inputs_field"],
        ),
        Artifact(
            id="contracts.relationships",
            path="book/integration/carton/bundle/contracts/relationships.contract.json",
            role="derived",
            hash_mode="semantic_json",
            schema="contracts_relationships.schema.json",
            checks=["top_level_world_id", "inputs_field"],
        ),
    ]

    jobs: List[Job] = [
        Job(
            id="specs.write",
            kind="meta",
            description="Generate CARTON specs from registry",
            inputs=[],
            outputs=[
                "book/integration/carton/spec/carton_spec.json",
                "book/integration/carton/spec/fixers.json",
                "book/integration/carton/spec/invariants.json",
            ],
            runner=specs_jobs.write_specs,
            always_run=True,
        ),
        Job(
            id="mappings.vocab",
            kind="mapping",
            description="Generate vocab mappings (ops/filters + attestations + coverage)",
            inputs=["book/integration/carton/bundle/relationships/mappings/dyld-libs/usr/lib/libsandbox.1.dylib"],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
                "book/integration/carton/bundle/relationships/mappings/vocab/filters.json",
                "book/integration/carton/bundle/relationships/mappings/vocab/operation_names.json",
                "book/integration/carton/bundle/relationships/mappings/vocab/filter_names.json",
                "book/integration/carton/bundle/relationships/mappings/vocab/attestations.json",
                "book/integration/carton/bundle/relationships/mappings/vocab/ops_coverage.json",
            ],
            runner=mapping_jobs.run_vocab,
        ),
        Job(
            id="mappings.op_table",
            kind="mapping",
            description="Promote op-table mappings from profile-pipeline experiments",
            inputs=[
                "book/evidence/experiments/profile-pipeline/node-layout/out/summary.json",
                "book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_map.json",
                "book/evidence/experiments/profile-pipeline/op-table-operation/out/op_table_signatures.json",
                "book/evidence/experiments/profile-pipeline/op-table-vocab-alignment/out/op_table_vocab_alignment.json",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/op_table/op_table_operation_summary.json",
                "book/integration/carton/bundle/relationships/mappings/op_table/op_table_map.json",
                "book/integration/carton/bundle/relationships/mappings/op_table/op_table_signatures.json",
                "book/integration/carton/bundle/relationships/mappings/op_table/op_table_vocab_alignment.json",
                "book/integration/carton/bundle/relationships/mappings/op_table/metadata.json",
            ],
            runner=mapping_jobs.run_op_table,
        ),
        Job(
            id="mappings.anchors",
            kind="mapping",
            description="Generate anchor field2 and filter maps",
            inputs=[
                "book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/anchors/anchor_field2_map.json",
                "book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json",
                "book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json",
            ],
            runner=mapping_jobs.run_anchors,
        ),
        Job(
            id="mappings.tag_layouts",
            kind="mapping",
            description="Generate tag layouts and tag u16 roles",
            inputs=[
                "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json",
                "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_u16_roles.json",
            ],
            runner=mapping_jobs.run_tag_layouts,
        ),
        Job(
            id="mappings.system_profiles",
            kind="mapping",
            description="Generate system profile digests and attestations",
            inputs=[
                "book/evidence/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json",
                "book/integration/carton/bundle/relationships/mappings/system_profiles/static_checks.json",
                "book/integration/carton/bundle/relationships/mappings/system_profiles/attestations.json",
                "book/integration/carton/bundle/relationships/mappings/system_profiles/header_contract.json",
            ],
            runner=mapping_jobs.run_system_profiles,
        ),
        Job(
            id="mappings.runtime_promote",
            kind="promotion",
            description="Promote runtime mappings from promotion packets",
            inputs=["book/integration/carton/bundle/relationships/mappings/runtime/packet_set.json"],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/runtime/promotion_receipt.json",
                "book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_manifest.json",
            ],
            runner=mapping_jobs.run_runtime_promote,
        ),
        Job(
            id="mappings.runtime_expectations",
            kind="mapping",
            description="Generate runtime expectations from runtime cuts + traces",
            inputs=["book/integration/carton/bundle/relationships/mappings/runtime_cuts/runtime_story.json"],
            outputs=["book/integration/carton/bundle/relationships/mappings/runtime/expectations.json"],
            runner=mapping_jobs.run_runtime_expectations,
        ),
        Job(
            id="mappings.runtime_lifecycle",
            kind="mapping",
            description="Generate lifecycle mappings from validation outputs",
            inputs=[
                "book/evidence/graph/concepts/validation/out/lifecycle/entitlements.json",
                "book/evidence/graph/concepts/validation/out/lifecycle/extensions_dynamic.md",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle.json",
                "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_story.json",
                "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_coverage.json",
            ],
            runner=mapping_jobs.run_runtime_lifecycle,
        ),
        Job(
            id="mappings.runtime_inventory",
            kind="mapping",
            description="Normalize hardened runtime inventory paths",
            inputs=[
                "book/evidence/experiments/runtime-final-final/suites/hardened-runtime/other_runtime_inventory.json",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/runtime/other_runtime_inventory.json",
            ],
            runner=mapping_jobs.run_runtime_other_inventory,
        ),
        Job(
            id="mappings.vfs_canonicalization",
            kind="promotion",
            description="Generate VFS canonicalization mapping from promotion packets",
            inputs=[
                "book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/packet_set.json",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/path_canonicalization_map.json",
                "book/integration/carton/bundle/relationships/mappings/vfs_canonicalization/promotion_receipt.json",
            ],
            runner=mapping_jobs.run_vfs_canonicalization,
        ),
        Job(
            id="mappings.policygraph_node_fields",
            kind="mapping",
            description="Generate policygraph node field mapping summary",
            inputs=[
                "book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields.json",
                "book/evidence/syncretic/policygraph/node-fields/policygraph_node_arg16.json",
                "book/evidence/syncretic/policygraph/node-fields/policygraph_node_unknowns.json",
                "book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields_receipt.json",
                "book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields.md",
            ],
            outputs=[
                "book/integration/carton/bundle/relationships/mappings/policy/policygraph_node_fields.json",
            ],
            runner=mapping_jobs.run_policygraph_node_fields,
        ),
        Job(
            id="relationships.operation_coverage",
            kind="fixer",
            description="Build operation_coverage relationship",
            inputs=[
                "book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
                "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json",
            ],
            outputs=["book/integration/carton/bundle/relationships/operation_coverage.json"],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.operation_coverage"),
            module="book.integration.carton.fixers.operation_coverage",
            function="run",
        ),
        Job(
            id="relationships.operation_system_profiles",
            kind="fixer",
            description="Build operation_system_profiles relationship",
            inputs=[
                "book/integration/carton/bundle/relationships/operation_coverage.json",
            ],
            outputs=["book/integration/carton/bundle/relationships/operation_system_profiles.json"],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.operation_system_profiles"),
            module="book.integration.carton.fixers.operation_system_profiles",
            function="run",
        ),
        Job(
            id="relationships.profile_layer_ops",
            kind="fixer",
            description="Build profile_layer_ops relationship",
            inputs=[
                "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json",
                "book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
                "book/integration/carton/bundle/relationships/operation_coverage.json",
            ],
            outputs=["book/integration/carton/bundle/relationships/profile_layer_ops.json"],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.profile_layer_ops"),
            module="book.integration.carton.fixers.profile_layer_ops",
            function="run",
        ),
        Job(
            id="relationships.filter_usage",
            kind="fixer",
            description="Build filter_usage relationship",
            inputs=[
                "book/integration/carton/bundle/relationships/mappings/vocab/filters.json",
                "book/integration/carton/bundle/relationships/mappings/system_profiles/digests.json",
            ],
            outputs=["book/integration/carton/bundle/relationships/filter_usage.json"],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.filter_usage"),
            module="book.integration.carton.fixers.filter_usage",
            function="run",
        ),
        Job(
            id="relationships.anchor_field2",
            kind="fixer",
            description="Build anchor_field2 relationship",
            inputs=[
                "book/integration/carton/bundle/relationships/mappings/anchors/anchor_field2_map.json",
                "book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json",
            ],
            outputs=["book/integration/carton/bundle/relationships/anchor_field2.json"],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.anchor_field2"),
            module="book.integration.carton.fixers.anchor_field2",
            function="run",
        ),
        Job(
            id="relationships.concept_sources",
            kind="fixer",
            description="Build concept_sources relationship",
            inputs=["book/world/sonoma-14.4.1-23E224-arm64/world.json"],
            outputs=["book/integration/carton/bundle/relationships/concept_sources.json"],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.concept_sources"),
            module="book.integration.carton.fixers.concept_sources",
            function="run",
        ),
        Job(
            id="views.build",
            kind="fixer",
            description="Build CARTON views from relationships",
            inputs=[
                "book/integration/carton/bundle/relationships/operation_coverage.json",
                "book/integration/carton/bundle/relationships/profile_layer_ops.json",
                "book/integration/carton/bundle/relationships/filter_usage.json",
                "book/integration/carton/bundle/relationships/anchor_field2.json",
                "book/integration/carton/bundle/relationships/concept_sources.json",
            ],
            outputs=[
                "book/integration/carton/bundle/views/operation_index.json",
                "book/integration/carton/bundle/views/profile_layer_index.json",
                "book/integration/carton/bundle/views/filter_index.json",
                "book/integration/carton/bundle/views/anchor_index.json",
                "book/integration/carton/bundle/views/concept_index.json",
            ],
            runner=fixer_jobs.make_runner("book.integration.carton.fixers.build_views"),
            module="book.integration.carton.fixers.build_views",
            function="run",
        ),
        Job(
            id="contracts.manifest",
            kind="contracts",
            description="Build contracts and CARTON manifest",
            inputs=[
                "book/integration/carton/spec/carton_spec.json",
                "book/integration/carton/bundle/relationships/operation_coverage.json",
                "book/integration/carton/bundle/relationships/operation_system_profiles.json",
                "book/integration/carton/bundle/relationships/profile_layer_ops.json",
                "book/integration/carton/bundle/relationships/filter_usage.json",
                "book/integration/carton/bundle/relationships/anchor_field2.json",
                "book/integration/carton/bundle/relationships/concept_sources.json",
            ],
            outputs=[
                "book/integration/carton/bundle/contracts/vocab.contract.json",
                "book/integration/carton/bundle/contracts/profiles.contract.json",
                "book/integration/carton/bundle/contracts/coverage.contract.json",
                "book/integration/carton/bundle/contracts/relationships.contract.json",
                "book/integration/carton/bundle/CARTON.json",
            ],
            runner=contracts_jobs.build_manifest,
            always_run=True,
        ),
    ]

    invariants = {
        "canonical_profile_status": {
            "sys:airlock": "ok",
            "sys:bsd": "ok",
            "sys:sample": "ok",
        },
        "coverage_status": "ok",
    }

    return Registry(artifacts=artifacts, jobs=jobs, invariants=invariants)
