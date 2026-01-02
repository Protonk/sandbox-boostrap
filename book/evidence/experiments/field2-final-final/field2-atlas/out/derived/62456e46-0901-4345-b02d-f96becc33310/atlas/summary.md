<!-- upstream_run_id=62456e46-0901-4345-b02d-f96becc33310 artifact_index_sha256=88d53d9d222076617cb524c19d7f41a6f20ab4e57205379f83c7e6b691dbfaf3 packet=book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out/promotion_packet.json -->
| field2 | status | profiles | anchors | runtime_scenario |
| --- | --- | --- | --- | --- |
| 0 | runtime_backed | 38 | 8 | adv:path_edges_private:allow-tmp |
| 1 | runtime_backed | 38 | 8 | adv:mount_relative_path:allow-subpath |
| 2 | runtime_backed | 19 | 1 | adv:xattr:allow-foo-read |
| 3 | runtime_backed | 24 | 1 | adv:file_mode:allow-private |
| 4 | no_runtime_candidate | 29 | 4 |  |
| 5 | runtime_backed | 28 | 7 | field2-5-mach-global |
| 6 | runtime_backed | 14 | 1 | adv:mach_local_regex:allow-cfprefsd-local |
| 7 | runtime_backed | 11 | 2 | field2-7-mach-local |
| 26 | no_runtime_candidate | 5 | 1 |  |
| 27 | no_runtime_candidate | 1 | 0 |  |
| 34 | runtime_backed | 1 | 0 | hardened:notifications_allow:allow-darwin |
| 37 | runtime_backed | 0 | 1 | hardened:sysctl_read_allow:allow-kern-ostype |
| 49 | no_runtime_candidate | 0 | 1 |  |
| 2560 | runtime_backed | 5 | 2 | field2-2560-flow-divert |
