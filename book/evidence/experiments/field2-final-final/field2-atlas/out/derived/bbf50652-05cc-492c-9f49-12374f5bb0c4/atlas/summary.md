<!-- upstream_run_id=bbf50652-05cc-492c-9f49-12374f5bb0c4 artifact_index_sha256=093010d1257d3f1587f4e9c804ca0072de192b93375d4d22b7dc3dc47aaaae90 packet=book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out/promotion_packet.json -->
| field2 | status | profiles | anchors | runtime_scenario |
| --- | --- | --- | --- | --- |
| 0 | runtime_backed | 38 | 8 | adv:path_edges_private:allow-tmp |
| 1 | runtime_backed | 38 | 8 | adv:mount_relative_path:allow-subpath |
| 2 | runtime_backed | 19 | 1 | adv:xattr:allow-foo-read |
| 3 | runtime_backed | 24 | 1 | adv:file_mode:allow-private |
| 4 | missing_probe | 29 | 4 | adv:ipc_posix_shm:allow-shm |
| 5 | runtime_backed | 28 | 7 | field2-5-mach-global |
| 6 | runtime_backed | 14 | 1 | adv:mach_local_regex:allow-cfprefsd-local |
| 7 | runtime_backed | 11 | 2 | field2-7-mach-local |
| 26 | missing_probe | 5 | 1 | adv:authorization_right:allow-right |
| 27 | missing_probe | 1 | 0 | adv:preference_domain:allow-domain |
| 34 | runtime_backed | 1 | 0 | hardened:notifications_allow:allow-darwin |
| 37 | runtime_backed | 0 | 1 | hardened:sysctl_read_allow:allow-kern-ostype |
| 49 | missing_probe | 0 | 1 | adv:xpc_service_name:allow-cfprefsd-xpc |
| 2560 | runtime_backed | 5 | 2 | field2-2560-flow-divert |
