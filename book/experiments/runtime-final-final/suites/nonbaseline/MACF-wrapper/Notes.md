# Notes

- Runtime world: `sonoma-14.6.1-debug-vm` (macOS 14.6.1 23G93, SIP disabled, Developer Mode enabled, fbt/syscall providers available).
- Enumerated `mac_*` fbt entry probes via `sb/list_macf_wrappers.sh`; recorded in `out/meta/macf_wrapper_probes.txt` and selected `mac_vnode_check_open` + `mac_vnop_setxattr` in `out/meta/selected_hooks.json`.
- D scripts now emit typed arguments for `mac_vnode_check_open` (ctx/vp/acc_mode) and `mac_vnop_setxattr` (vp/name_ptr/buf_ptr/len) plus syscall context for open*/setxattr/fsetxattr gated by `pid == $target`.
- Xattr scan (`sb/scan_xattr_hooks.d` via `bin/run_xattr_scan.sh`) produced no mac_*xattr* hits for the canonical xattr command; `mac_vnop_setxattr` remains unobserved on this world despite being present in fbt.
- Smoketests via `bin/run_smoketest.sh` (manifests + summaries under `out/meta/`):
  - `/bin/ls /tmp` → `mac_vnode_check_open` hooks correlated with `open*` syscalls and paths (raw `out/raw/macf_vnode_open_ls.log`, normalized `out/json/macf_vnode_open_ls.json`, summary `out/meta/macf_vnode_open_ls_summary.json`).
  - `/usr/bin/xattr -w … out/tmp/macf_wrapper_xattr_test` → `open` hooks + `fsetxattr` syscalls observed; no mac_*xattr* hook fired (raw `out/raw/macf_setxattr_test.log`, normalized `out/json/macf_setxattr_test.json`, summary `out/meta/macf_setxattr_test_summary.json`).
- `normalize.py` correlates hooks to the latest compatible syscall in the same (pid, tid) within 10 ms and keeps syscall fields (path/flags/fd/xattr_name/size) alongside raw hook args; per-run summaries capture hook/syscall counts and timing deltas (open deltas observed 4–27 µs; xattr scenario single open delta ~19 µs, comfortably within the 10 ms window).
