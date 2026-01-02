# Frontier Delta Report

world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5
run_id: 7a75efa8-594f-4af8-8e5c-f5d1d6ebef2a
new_run: book/evidence/experiments/runtime-frontiers/out/7a75efa8-594f-4af8-8e5c-f5d1d6ebef2a
baseline_packets: book/evidence/experiments/runtime-checks/out/promotion_packet.json, book/evidence/experiments/runtime-adversarial/out/promotion_packet.json, book/evidence/experiments/hardened-runtime/out/promotion_packet.json, book/evidence/experiments/anchor-filter-map/out/promotion_packet.json, book/evidence/experiments/anchor-filter-map/iokit-class/out/promotion_packet.json
generated_by: book/evidence/experiments/runtime-frontiers/frontier_delta.py

## Probe fidelity
tier: mapped
evidence: book/evidence/experiments/runtime-frontiers/out/7a75efa8-594f-4af8-8e5c-f5d1d6ebef2a/runtime_events.normalized.json
- total_observations: 19
- intended_op_witnessed: 16
- op_filter_literal_witnessed: 16
- missing_callout: 3
missing_details:
- frontier:anchor_filters:mach_cfprefsd: mach-lookup target=com.apple.cfprefsd.agent filter=None intended_op_witnessed=False
- frontier:anchor_filters:mach_bogus: mach-lookup target=com.apple.sandbox-lore.frontier.bogus filter=None intended_op_witnessed=False
- frontier:unknown_ops:process_fork: process-fork target=self filter=None intended_op_witnessed=False

## Coverage delta
tier: mapped
evidence: book/evidence/graph/mappings/runtime/packet_set.json, book/evidence/experiments/runtime-frontiers/out/7a75efa8-594f-4af8-8e5c-f5d1d6ebef2a/runtime_events.normalized.json, book/evidence/experiments/runtime-frontiers/out/7a75efa8-594f-4af8-8e5c-f5d1d6ebef2a/path_witnesses.json
notes: filter coverage uses seatbelt callout filter_type_name; path pairs are requested_path -> normalized_path.
- ops: baseline=3 new=6 added=4
- filters: baseline=3 new=1 added=0
- path_resolution_pairs: baseline=36 new=16 added=7
- policy_layers_disagreements: baseline=25 new=18 added=18
added_ops: file-read-data, file-search, file-test-existence, file-write-data
added_path_pairs:
- /private/etc/hosts -> /private/etc/hosts
- /private/tmp/sbpl_rt -> /private/tmp/sbpl_rt
- /private/var/log -> /private/var/log
- /tmp/sbpl_rt -> /private/tmp/sbpl_rt
- /tmp/sbpl_rt -> /tmp/sbpl_rt
- /var/log -> /private/var/log
- /var/log -> /var/log
added_policy_disagreements: frontier:anchor_filters:mach_cfprefsd, frontier:anchor_filters:read_data_/etc/hosts, frontier:anchor_filters:read_data_/private/etc/hosts, frontier:anchor_filters:search_/private/var/log, frontier:anchor_filters:search_/var/log, frontier:system_ops:read_data_/etc/hosts, frontier:system_ops:read_data_/private/etc/hosts, frontier:system_ops:search_/private/tmp/sbpl_rt, frontier:system_ops:search_/tmp/sbpl_rt, frontier:system_ops:test_exists_/etc/hosts, frontier:system_ops:test_exists_/private/etc/hosts, frontier:system_ops:write_data_/private/tmp/strict_ok/allow.txt, frontier:system_ops:write_data_/tmp/sbpl_rt/write.txt, frontier:unknown_ops:process_fork, frontier:unknown_ops:read_xattr_/tmp/bar, frontier:unknown_ops:read_xattr_/tmp/foo, frontier:unknown_ops:write_xattr_/tmp/bar, frontier:unknown_ops:write_xattr_/tmp/foo
