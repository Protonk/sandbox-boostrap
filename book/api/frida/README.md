# frida (API)

This package centralizes Frida helpers used across experiments and tools on the Sonoma baseline. It provides:

- A spawn/attach runner that emits trace events to `events.jsonl`.
- A curated set of stable hook scripts under `book/api/frida/hooks/` (with `*.manifest.json`).
- Headless tooling to normalize/query/index/export/validate runs.

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

Hooks in `book/api/frida/hooks/` are loaded via a deterministic assembly step (shared helper + hook source); see `book/api/frida/hooks/_shared/trace_helper.js`.

## Run products (compatibility surface)
The compatibility surface is explicitly frozen in `book/api/frida/TRACE_COMPATIBILITY.md`:
- Run directory contract is `meta.json` + `events.jsonl`
- Current hook `send()` payload shapes remain representable (payload is preserved verbatim under the trace envelope)

Trace v1 envelope is documented in `book/api/frida/TRACE_SCHEMA_V1.md` and machine-checked by `book/api/frida/schemas/trace_event_v1.schema.json`.

## Headless tooling
- Normalize legacy runs in-place: `python -m book.api.frida.cli normalize <run_dir>`
- Query via DuckDB (requires `duckdb` CLI): `python -m book.api.frida.cli query <run_dir> --sql-file book/api/frida/queries/send_events.sql`
- Build cached index: `python -m book.api.frida.cli index <run_dir>`
- Export Chrome Trace artifact: `python -m book.api.frida.cli export <run_dir>`
- Validate schema/query/export invariants: `python -m book.api.frida.cli validate <run_dir...>`
- Generate a new hook + manifest scaffold: `python -m book.api.frida.cli generate-hook --input book/api/frida/fixtures/generator_inputs/example_exports_v1.json`
- Build TypeScript-authored hooks into the runtime catalog: `python -m book.api.frida.cli build-ts-hooks --check`

Hook manifests are specified in `book/api/frida/HOOK_MANIFEST_V1.md` and live next to hook scripts as `*.manifest.json`.

The optional `rpc.exports.configure` surface is standardized by `book/api/frida/CONFIGURE_CONTRACT_V1.md`.

## Notes
- The world baseline is resolved via `book.api.profile.identity.baseline_world_id`.
