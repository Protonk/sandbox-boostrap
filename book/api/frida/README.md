# frida (API)

This package centralizes Frida helpers used across experiments and tools on the Sonoma baseline. It provides:

- A spawn/attach runner that emits JSONL events.
- An EntitlementJail XPC-session harness with attach-first Frida hooks.
- A curated set of stable hook scripts under `book/api/frida/hooks/`.

## Entry points
- `book.api.frida.runner.run` (spawn or attach a pid).
- `book.api.frida.entitlementjail.run_from_args` (EntitlementJail xpc session + Frida attach).
- CLI: `python -m book.api.frida.cli run ...` or `python -m book.api.frida.cli ej-session ...`.

## Hooks
Stable hooks promoted from `book/experiments/frida-testing/hooks/` live in:

- `book/api/frida/hooks/smoke.js`
- `book/api/frida/hooks/fs_open_selftest.js`
- `book/api/frida/hooks/sandbox_check_minimal.js`
- `book/api/frida/hooks/sandbox_check_trace.js`
- `book/api/frida/hooks/execmem_trace.js`

Exploratory hooks remain in `book/experiments/frida-testing/hooks/`.

## Output schema (summary)
Both runners emit:
- `frida/events.jsonl` (JSONL events, with `runner` and `send` payloads)
- `frida/meta.json` (script hash, host info, attach metadata)

The EntitlementJail harness also emits:
- `ej/run_xpc.json`
- `manifest.json`

All paths inside JSON are repo-relative via `book.api.path_utils`.

## Notes
- EntitlementJail XPC sessions may require elevated permissions outside the harness sandbox.
- The world baseline is resolved via `book.api.profile_tools.identity.baseline_world_id`.
