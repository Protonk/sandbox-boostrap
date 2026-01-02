# MACF wrapper runtime experiment – Plan

## Purpose
- Capture runtime MACF wrapper calls (`mac_*` hooks) from controlled processes on the debug VM without depending on `mac_policy_register`.

## Scope
- Environment: runtime-only debug VM (`sonoma-14.6.1-debug-vm`), macOS 14.6.1 (23G93), SIP disabled, Developer Mode enabled, full disk + developer access granted to Terminal; DTrace `fbt`/`syscall` providers available (`--yolo` codex harness).
- This is a different world from the static Sonoma 14.4.1 baseline; all `out/` artifacts here are runtime-only, VM-specific evidence and must not be treated as extensions of the 14.4.1 static corpus.
- Hooks: `fbt:mach_kernel:mac_*:entry` probes selected from an enumerated allowlist.
- Processes: controlled commands invoked via DTrace `-c`/`-p`; filter by `pid == $target` in the probe script.

## Outputs
- Raw DTrace logs under `out/raw/`.
- Normalized JSON events under `out/json/` (bound to `sonoma-14.6.1-debug-vm`).
- Run manifests, per-run summaries, and probe inventories under `out/meta/` (carry `world_id` and scenario).

## Dependencies
- Reuse the runtime DTrace/normalize pipeline pattern from `book/experiments/runtime-final-final/suites/nonbaseline/runtime-mac_policy`.
- No kernel patching or registration hooks; `fbt` provider only.

## Execution sketch
- Enumerate MACF wrapper probes and choose a small starter set (vnode + exec).
- Capture wrapper calls for a controlled process (e.g., `ls`) using `sb/macf_wrappers.d`.
- Normalize raw logs into JSON with per-hook args, decoded syscall context, and process identity.
- Keep Report/Notes in sync with artifacts and status.
