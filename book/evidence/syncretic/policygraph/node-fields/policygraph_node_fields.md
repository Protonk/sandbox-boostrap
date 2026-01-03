# PolicyGraph Node Fields

- world_id: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`
- record_size_bytes: `8`
- field_count: `4`
- arg16_field_index: `2`
- runtime_annotation: `book/tools/policy/runtime_annotation.promotion_packet.json (run_id=738fc3d0-1d12-4608-9a97-90addfbc8d4c, artifact_index_sha256=3c97d7dd4eba9a012bb8a956ef4019435e927558144c0ad532685b63765f740f)`

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
- runtime_matched: `8`
- runtime_missing_probe: `6`
- runtime_blocked: `0`

### Runtime Matched (scenario lane)

| arg16 | filter_name | operation | actual | stage | lane | scenario_id |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | path | file-read* | allow | operation | scenario | adv:path_edges_private:allow-tmp |
| 1 | mount-relative-path | file-read* | allow | operation | scenario | adv:mount_relative_path:allow-subpath |
| 2 | xattr | file-read-xattr | allow | operation | scenario | adv:xattr:allow-foo-read |
| 3 | file-mode | file-read* | allow | operation | scenario | adv:file_mode:allow-private |
| 5 | global-name | mach-lookup | allow | operation | scenario | field2-5-mach-global |
| 6 | local-name | mach-lookup | allow | operation | scenario | adv:mach_local_regex:allow-cfprefsd-local |
| 7 | local | mach-lookup | allow | operation | scenario | field2-7-mach-local |
| 2560 | opaque | network-outbound | allow | operation | scenario | field2-2560-flow-divert |

### Runtime Missing Probes

- values: 4, 26, 27, 34, 37, 49

## Unknowns

- unknown_arg16_values: `36`
- top_unknowns_by_count: 165 (count=97), 3584 (count=27), 166 (count=9), 256 (count=8), 1281 (count=7), 49171 (count=6), 2560 (count=5), 2816 (count=5), 3072 (count=5), 3328 (count=5)

## Inputs

- anchor_ctx_filter_map: `book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json` (sha256=76498c627bd0254de8b1eb5eb014f60275a0c36cf02f09562257ba39ef8c9c5f)
- anchor_filter_map: `book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json` (sha256=f456f655196c6c1d2258b241dfe4600185cdc5d4b8aca989b0dd6361f1194834)
- anchor_hits: `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json` (sha256=af7187729d0741d9f062603e599f32f4808039ed49bad55fdef0ccf547e87fa5)
- anchor_hits_delta: `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits_delta.json` (sha256=d9bdfc3269c4157fceb6720d07466524c440b20ab9915b67f30e004d5a4c340f)
- field2_inventory: `book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json` (sha256=afe851221c28068cefa3e963ffea4199903adafc4f44b395564a5ebec0ac3cdb)
- field2_seeds: `book/evidence/experiments/field2-final-final/field2-atlas/field2_seeds.json` (sha256=a3ab73b81db231db19fadf35f3931c9d382f10406d75f24c567bb06b27a721b0)
- network_matrix_index: `book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/index.json` (sha256=86c5709f4fc3b3f74e787ce848fd5b9ea2214ef316c3745ea1fd297170b4377e)
- tag_layouts: `book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json` (sha256=eb3b1cfefae0aaf7260ac017b52fddd38b375922514468b4071f72281af6b2ac)
- unknown_nodes: `book/evidence/experiments/field2-final-final/field2-filters/out/unknown_nodes.json` (sha256=525ecdccea5cdf20860334630303021c9f5c4fb40f4dfbadf576bb045b129cc2)
- vocab_filters: `book/integration/carton/bundle/relationships/mappings/vocab/filters.json` (sha256=637e53a6123199460af10a3699b3dc5bb5337bf1622ac02d5efdf141a436d35e)
- vocab_ops: `book/integration/carton/bundle/relationships/mappings/vocab/ops.json` (sha256=8bfec7acc3afe687e7117909658eafafa3ddf173f8300ea90380bbffd7a2f8a2)

## Outputs

- fields: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields.json`
- arg16: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_arg16.json`
- unknowns: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_unknowns.json`
- receipt: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields_receipt.json`
- report: `book/evidence/syncretic/policygraph/node-fields/policygraph_node_fields.md`
