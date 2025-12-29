# Hook Manifest v1

This document defines the v1 *hook manifest* format for Frida agent scripts in `book/api/frida/hooks/`.

The hook manifest is a small, machine-readable contract that is intended to be:
- **Headless**: usable by scripts and CI without opening any UI.
- **Deterministic**: static JSON checked into the repo.
- **Snapshot-friendly**: safe to embed verbatim into a run’s `meta.json` so the run is self-describing even if hook source files later change.

The machine-checkable schema is `book/api/frida/schemas/hook_manifest_v1.schema.json`.

## Convention

For a hook script `X.js`, the manifest lives next to it as `X.manifest.json`.

Example:
- Script: `book/api/frida/hooks/fs_open_selftest.js`
- Manifest: `book/api/frida/hooks/fs_open_selftest.manifest.json`

## Required fields (v1)

- `schema_name`: `"book.api.frida.hook_manifest"`
- `schema_version`: `1`
- `hook.id`: stable identifier (string)
- `hook.script_path`: repo-relative path to the hook script
- `trace_event_schema`: the trace-event envelope schema this hook is intended to run under (today: trace v1)
- `rpc_exports`: list of `rpc.exports` function names (strings)
- `configure`: special-case declaration for `rpc.exports.configure`:
  - `supported`: boolean
  - `input_schema`: JSON Schema for the `configure(opts)` argument (or `null`)
- `module_expectations`: module-name expectations (best-effort; hooks should still be robust to missing modules)

The manifest may also declare `send_payload_kinds`, which is used for inventorying and cross-hook queries.

