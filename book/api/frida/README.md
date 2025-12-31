# Frida Trace Product (API)

This package defines a headless, deterministic “trace product” for Frida runs on the Sonoma baseline. The product boundary is a run directory containing `meta.json` + `events.jsonl`; everything else (normalization, index/query results, timeline export, validation reports) is derived, machine-verifiable output.

## Compatibility surface (frozen)

The compatibility surface is explicitly frozen in `book/api/frida/TRACE_COMPATIBILITY.md`:
- Run directory contract is `meta.json` + `events.jsonl`
- Existing hook `send()` payload shapes remain representable (agent payload is preserved verbatim under the trace v1 envelope)

Trace v1 envelope is documented in `book/api/frida/TRACE_SCHEMA_V1.md` and machine-checked by `book/api/frida/schemas/trace_event_v1.schema.json`.

## Run (generic runner)

Spawn or attach and emit a trace-v1 run directory:

- Spawn: `python -m book.api.frida.cli run --spawn ./book/experiments/frida-testing/targets/open_loop /etc/hosts --script book/api/frida/hooks/smoke.js --out-dir book/api/frida/out --duration-s 2`
- Attach: `python -m book.api.frida.cli run --attach-pid <pid> --script book/api/frida/hooks/smoke.js --out-dir book/api/frida/out --duration-s 2`

Outputs:
- `<out_dir>/<run_id>/meta.json`
- `<out_dir>/<run_id>/events.jsonl`

## Run (PolicyWitness attach-first)

PolicyWitness attach-first runs use the same trace product contract, but are orchestrated via the PolicyWitness XPC session runner:

`python -m book.api.policywitness.frida --profile-id <profile_id> --probe-id <probe_id> --script book/api/frida/hooks/fs_open_selftest.js --out-dir book/api/frida/out`

Outputs (under the PolicyWitness run root):
- `<out_dir>/<run_id>/frida/meta.json`
- `<out_dir>/<run_id>/frida/events.jsonl`

## Normalize

Normalize legacy/mixed event streams to canonical trace v1 (in-place):

`python -m book.api.frida.cli normalize <run_dir>`

## Validate

Validate schema/query/export/config/manifest invariants headlessly (JSON report, stable exit code):

`python -m book.api.frida.cli validate <run_dir...>`

Validate the pinned known-good fixture set (inventory gate):

`python -m book.api.frida.cli validate-known-good`

The pinned set is declared in `book/api/frida/trace_inventory.json`.

## Query / index (DuckDB-first)

Query results are JSON (stable key ordering, stable row ordering via DuckDB). Requires the `duckdb` CLI in `PATH`.

- Query directly from JSONL: `python -m book.api.frida.cli query <run_dir> --sql-file book/api/frida/queries/send_events.sql`
- Build cached index: `python -m book.api.frida.cli index <run_dir>`
- Query cached index: `python -m book.api.frida.cli query <run_dir> --use-index --sql-file book/api/frida/queries/send_events.sql`

## Export (timeline artifact)

Export a deterministic Chrome Trace JSON artifact (for optional Chrome/Perfetto UI viewing) plus a deterministic headless report:

`python -m book.api.frida.cli export <run_dir>`

Outputs:
- `<run_dir>/trace.chrometrace.json`
- `<run_dir>/trace.chrometrace.report.json`

## Manifests and script assembly

- Runtime hook catalog: `book/api/frida/hooks/*.js` + `book/api/frida/hooks/*.manifest.json`
- Manifest spec: `book/api/frida/HOOK_MANIFEST_V1.md`
- Loader-side deterministic assembly (shared helper + hook source): `book/api/frida/script_assembly.py` and `book/api/frida/hooks/_shared/trace_helper.js`
- Every run snapshots a manifest into `meta.json` (under `script.manifest`) and records hook + manifest hashes.

## Configuration / `configure()` (contract v1)

Configuration and `rpc.exports.configure` are standardized by `book/api/frida/CONFIGURE_CONTRACT_V1.md`.

Run record requirements (always present in `meta.json`):
- `script.config` (snapshot of provided config + source)
- `script.config_validation` (pass/fail + stable error)
- `script.configure` (absent/pass/fail/skipped + result/error)

Run stream stage events (in `events.jsonl`, `source=runner`):
- `kind=config-validation` / `kind=config-error`
- `kind=configure` / `kind=configure-error`

## Generator (hook scaffold)

Generate a deterministic hook + manifest scaffold into the runtime catalog:

`python -m book.api.frida.cli generate-hook --input book/api/frida/fixtures/generator_inputs/example_exports_v1.json`

Input format spec: `book/api/frida/HOOK_GENERATOR_INPUT_V1.md`.

## TypeScript-first hooks (build into runtime catalog)

TypeScript sources live under `book/api/frida/hooks_ts/` and compile into runtime artifacts under `book/api/frida/hooks/`.

CI-style “up to date” gate (no writes): `python -m book.api.frida.cli build-ts-hooks --check`

## Baseline note

The world baseline for tooling is resolved via `book.api.profile.identity.baseline_world_id`.
