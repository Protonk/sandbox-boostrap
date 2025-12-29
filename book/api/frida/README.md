# frida (API)

This package centralizes Frida helpers used across experiments and tools on the Sonoma baseline. It provides:

- A spawn/attach runner that emits JSONL events.
- A curated set of stable hook scripts under `book/api/frida/hooks/`.

## Entry points
- `book.api.frida.runner.run` (spawn or attach a pid).
- CLI: `python -m book.api.frida.cli run ...`.

EntitlementJail attach-first Frida runs live under `book/api/entitlementjail/frida.py`.

## Hooks
Stable hooks promoted from `book/experiments/frida-testing/hooks/` live in:

- `book/api/frida/hooks/smoke.js`
- `book/api/frida/hooks/fs_open_selftest.js`
- `book/api/frida/hooks/sandbox_check_minimal.js`
- `book/api/frida/hooks/sandbox_check_trace.js`
- `book/api/frida/hooks/execmem_trace.js`

Exploratory hooks remain in `book/experiments/frida-testing/hooks/`.

## Output schema (summary)
Runner emits:
- `frida/events.jsonl` (JSONL events, with `runner` and `send` payloads)
- `frida/meta.json` (script hash, host info, attach metadata)

All paths inside JSON are repo-relative via `book.api.path_utils`.

## Notes
- The world baseline is resolved via `book.api.profile.identity.baseline_world_id`.
