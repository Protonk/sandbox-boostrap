# MACF wrapper runtime experiment

## Purpose
- Capture runtime MACF wrapper calls (e.g., `mac_vnode_check_open`, `mac_vnop_setxattr`) on controlled processes, independent of `mac_policy_register`, and normalize them into JSON events for later correlation with static sandbox work.

## Setup
- World: `sonoma-14.6.1-debug-vm` (macOS 14.6.1 23G93, SIP disabled, Developer Mode enabled, fbt/syscall providers available; runtime-only VM distinct from the static Sonoma 14.4.1 baseline; world metadata in `book/world/sonoma-14.6.1-debug-vm/world.json`).
- Hooks enumerated via `sb/list_macf_wrappers.sh` → `out/meta/macf_wrapper_probes.txt`; selected hooks recorded in `out/meta/selected_hooks.json` (starter set: `mac_vnode_check_open`, `mac_vnop_setxattr`).
- Probes filter to a single traced process (`pid == $target`) using generated D scripts from `capture.py`; manual template in `sb/macf_wrappers.d` documents the format and includes syscall context probes (open*, setxattr/fsetxattr) to correlate hook events with userland paths/flags.
- Capture pipeline: `capture.py` renders the D script, runs DTrace (`-c` command), normalizes via `normalize.py` (correlates hook events with nearby syscalls on the same pid/tid), and writes a run manifest under `out/meta/`.

## Captured hooks and scenarios
- Hook inventory: `out/meta/macf_wrapper_probes.txt` (fbt `mac_*` entry probes on this VM).
- Selected hooks metadata: `out/meta/selected_hooks.json` (mac_vnode_check_open observed; mac_vnop_setxattr present in fbt but not observed in our scenarios; xattr scan log `out/raw/xattr_scan.log` recorded no mac_*xattr* hits for the canonical xattr command).
- Smoketest scenarios via `bin/run_smoketest.sh` (manifests and summaries in `out/meta/`):
  - `macf_vnode_open_ls` (`scenario`: `vnode_open_ls_tmp`): `/bin/ls /tmp` → raw `out/raw/macf_vnode_open_ls.log`, normalized `out/json/macf_vnode_open_ls.json`, summary `out/meta/macf_vnode_open_ls_summary.json` (8 `mac_vnode_check_open` events, each correlated with an `open` syscall; deltas 4–27 µs within the 10 ms window).
  - `macf_setxattr_test` (`scenario`: `xattr_tmp_file`): `/usr/bin/xattr -w … out/tmp/macf_wrapper_xattr_test` → raw `out/raw/macf_setxattr_test.log`, normalized `out/json/macf_setxattr_test.json`, summary `out/meta/macf_setxattr_test_summary.json` (only `mac_vnode_check_open` observed; `fsetxattr` syscalls present but no mac_*xattr* hooks fired on this VM).

## Limits and interpretation
- Runtime-only evidence on a debug VM (SIP disabled, macOS 14.6.1); not the frozen Sonoma 14.4.1 baseline.
- Hook list limited to `mac_*` fbt entry probes visible here; no registration timing or MACF op-table alignment.
- Xattr path remains incomplete: `mac_vnop_setxattr` is present in the symbol table but not observed for the canonical xattr scenario; no alternative mac_*xattr* wrapper fired in the scan, so xattr evidence is currently “not observed on this VM.”
- Arguments remain opaque pointers/flags except for lightweight decoding (access mode bits, syscall paths/flags/xattr sizes); no dereferences of kernel pointers.
- Role: treat this as a bounded runtime witness for the SIP-disabled 14.6.1 debug world, useful to contrast with the SIP-on 14.4.1 baseline where fbt is unavailable. Not promoted to shared infrastructure; maintenance stays experiment-local unless a concrete world-aligned consumer appears.
- Status: partial — open hooks observed with syscall correlation; xattr hooks unobserved; scope intentionally narrow to avoid over-generalizing beyond this runtime world.
