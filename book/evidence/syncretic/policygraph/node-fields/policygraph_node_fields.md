# PolicyGraph Node Fields

- world_id: `sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`
- record_size_bytes: `8`
- field_count: `4`
- arg16_field_index: `2`
- runtime_annotation: `none`

## Field Layout

| field_index | canonical_name | role | byte_offset | width_bits | edge_tag_count | payload_tag_count |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | u16_0 | edge | 0 | 16 | 117 | 0 |
| 1 | u16_1 | edge | 2 | 16 | 117 | 0 |
| 2 | policygraph_node_arg16 | payload | 4 | 16 | 0 | 117 |
| 3 | u16_3 | unassigned | 6 | 16 | 0 | 0 |

## policygraph_node_arg16 Summary

- total_values: `70`
- mapped_values: `34`
- opaque_values: `36`
- seeds_present: `14`
- anchor_hits_present: `23`
- probe_anchor_hits_present: `27`
- runtime_candidates: `14`
- runtime_matched: `0`
- runtime_missing_probe: `14`
- runtime_blocked: `0`

### Runtime Matched (scenario lane)

- none

### Runtime Missing Probes

- values: 0, 1, 2, 3, 4, 5, 6, 7, 26, 27, 34, 37, ... (14 total)

## Unknowns

- unknown_arg16_values: `36`
- top_unknowns_by_count: 165 (count=97), 3584 (count=27), 166 (count=9), 256 (count=8), 1281 (count=7), 49171 (count=6), 2560 (count=5), 2816 (count=5), 3072 (count=5), 3328 (count=5)

## Inputs

- anchor_ctx_filter_map: `book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json` (sha256=76498c627bd0254de8b1eb5eb014f60275a0c36cf02f09562257ba39ef8c9c5f)
- anchor_filter_map: `book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json` (sha256=f456f655196c6c1d2258b241dfe4600185cdc5d4b8aca989b0dd6361f1194834)
- anchor_hits: `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json` (sha256=65e23955d6a4d8427bc9e03a109af596c0be94b3fc8ae573f011bedf85efaec6)
- anchor_hits_delta: `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits_delta.json` (sha256=e64853be096c0f9a53c86e958ff158ca432bc89c620caa477205db86ad42ce7f)
- field2_inventory: `book/evidence/syncretic/policygraph/node-fields/field2_inventory.json` (sha256=67534340f3fde0e6b62d2d0689ec26ff2be30f39415a63060279c2feb8cb8cc2)
- field2_seeds: `book/evidence/experiments/field2-final-final/field2-atlas/field2_seeds.json` (sha256=bd4d70d9056c1944c5564eccf04c60a343b088d7cdbd9f84519c176b43cf629e)
- network_matrix_index: `book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/index.json` (sha256=86c5709f4fc3b3f74e787ce848fd5b9ea2214ef316c3745ea1fd297170b4377e)
- tag_layouts: `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` (sha256=eb3b1cfefae0aaf7260ac017b52fddd38b375922514468b4071f72281af6b2ac)
- unknown_nodes: `book/evidence/syncretic/policygraph/node-fields/unknown_nodes.json` (sha256=1bf0a382b80db82ca6a1a78a8892f75b327c88235622c76429305a3464080f04)
- vocab_filters: `book/integration/carton/bundle/relationships/mappings/vocab/filters.json` (sha256=637e53a6123199460af10a3699b3dc5bb5337bf1622ac02d5efdf141a436d35e)
- vocab_ops: `book/integration/carton/bundle/relationships/mappings/vocab/ops.json` (sha256=8bfec7acc3afe687e7117909658eafafa3ddf173f8300ea90380bbffd7a2f8a2)

## Outputs

- fields: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields.json`
- arg16: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_arg16.json`
- unknowns: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_unknowns.json`
- receipt: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields_receipt.json`
- report: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields.md`
