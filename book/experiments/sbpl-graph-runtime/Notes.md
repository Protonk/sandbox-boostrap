# SBPL ↔ Graph ↔ Runtime – Notes

Use this file for concise notes on commands, hurdles, and intermediate results.

## Initial strict profiles

- Authored minimal profiles: `allow_all.sb`, `deny_all.sb`, `deny_except_tmp.sb`, `metafilter_any.sb` (param_path.sb exists but fails to compile without param injection).
- Compiled via `book/examples/sbsnarf/sbsnarf.py` (absolute paths) → binaries in `out/*.sb.bin`.
- Decoded headers/sections into `out/ingested.json` using `profile_ingestion.py` (modern-heuristic variant).
- Runtime probes: now running via `sandbox_runner`/`sandbox_reader`. allow_all runs (OS perms still deny `/etc/hosts` write); deny_all/deny_except_tmp align through runtime-checks. `metafilter_any` now passes (allow foo/bar, deny other) after adding `/private/tmp` literals and using reader to avoid exec overhead.
- Wrapper available: runtime-checks harness can exercise these compiled blobs via `book/tools/sbpl/wrapper/wrapper --blob`; reuse that path for future triple captures instead of relying on `sandbox-exec`.
- System profiles: airlock remains EPERM on this host; bsd SBPL/compiled blob applies. Consider adding a `bsd`-like profile as a “system-style” triple if needed; otherwise keep the synthetic set as the runtime focus here.

## Param path adjustments (current run)

- Added a literal-filtered `(allow process-exec ...)` for `book/api/file_probe/file_probe` inside `profiles/param_path.sb` to keep a `(deny default)` helper alive during file probes.
- Recompiled the existing profiles with `python -m book.api.profile_tools compile book/experiments/sbpl-graph-runtime/profiles/*.sb --out-dir book/experiments/sbpl-graph-runtime/out --no-preview`; `param_path.sb` failed with `invalid data type of path filter; expected pattern, got boolean`, likely because `(param "ROOT")` is unresolved in the current compiler wrapper. Other profiles compiled and were re-ingested into `out/ingested.json`.

## Concrete param profile + static expectations

- Added `profiles/param_path_concrete.sb` as a temporary instantiation with a literal ROOT at `/tmp/sbpl_rt/param_root` plus the process-exec escape hatch; compiled successfully to `out/param_path_concrete.sb.bin` and re-ingested into `out/ingested.json`.
- Created `out/static_expectations.json` capturing SBPL-level allow/deny expectations for the synthetic profiles (allow_all, deny_all, deny_except_tmp, metafilter_any, param_path_concrete) to serve as a machine-readable contract for upcoming runtime probes.
- `static_expectations.json` now carries best-effort node hooks (op_table raw entries and literal-matched node indices/tags where present) from the heuristic decoder; `param_path_concrete` links back to the template via `template_of` in `triples_manifest.json`.
- Contract tagged `schema_version: provisional` with `runtime_join_key: expectation_id` and per-expectation flags (`entrypoint_resolved`, `terminal_resolved`, `terminal_source`) to make provisional edges explicit. The runtime harness should log against `expectation_id` and record op/path/errno plus any observed op_index to keep runtime ↔ static joins stable.
- Runtime log schema (provisional tag) captured at `book/experiments/runtime-checks/runtime_log_schema.v0.1.json`; `run_probes.py` now emits `expectation_id` (when present), op/path, and a structured `runtime_result`/`violation_summary` so runtime outputs can key back to static expectations.

## Provisional runtime outcomes (Sonoma 14.4.1, unsandboxed caller)

- Golden triples (SBPL → graph → runtime align; expectation_ids populated): `runtime:allow_all`, `runtime:metafilter_any`, `bucket4:v1_read`. `/etc/hosts` write failures are attributed to OS perms outside sandbox scope.
- Platform-only: `sys:bsd`, `sys:airlock`, `sys:sample` remain apply-gated (EPERM/execvp) even unsandboxed; treated as platform-only policies, not harness bugs.
- Custom apply-gate outlier: `bucket5:v11_read_subpath` still blocked with EPERM on deny probes; keep non-golden.
- Strict profiles (quarantined): `runtime:param_path_concrete` (deny-default + process-exec) and `runtime:param_path_bsd_bootstrap` (deny-default + import bsd.sb) both remain blocked at runtime (exec -6 or EPERM on subpath I/O). Conclusion: on this host, a viable deny-default helper needs broader bootstrap allowances; no strict profile is promoted in this provisional cut.

## Latest harness rerun (runtime_tools, SBPL mode)

- Switched `book/profiles/golden-triple/expected_matrix.json` to SBPL inputs for `allow_all` / `metafilter_any` to avoid wrapper `sandbox_init` errors (“no version specified”) on blobs. Added a minimal strict profile (`runtime:strict_1`) to the matrix.
- Command: `python -m book.api.runtime_tools run --matrix book/profiles/golden-triple/expected_matrix.json --out book/profiles/golden-triple`.
- Results: `runtime:allow_all`, `runtime:metafilter_any`, `bucket4:v1_read`, and new `runtime:strict_1` all `status: ok` in `book/profiles/golden-triple/runtime_results.json`. `bucket5:v11_read_subpath` remains `partial` (read on `/tmp/foo` still returns `EPERM` despite subpath allow). Wrapper “no version specified” errors cleared by SBPL mode; blob apply remains avoided for these runs.

## Bucket5 vs bucket4/strict_1 literals (decoded)

- Compiled and decoded the SBPL runtime profiles with `profile_tools.compile_sbpl_file` + `decoder.decode_profile_dict`.
- Literal pools:
  - `bucket5:v11_read_subpath` carries `/tmp/foo` (and shim literals for `/System`, `/usr`, `/bin`, `/dev`, `/tmp`, `/private`, `/tmp`), **no `/private/tmp` literal**.
  - `runtime:strict_1` carries `/private/tmp/strict_ok` plus `/etc/hosts` denies and the same shim literals; canonical path `/private/tmp/strict_ok` is present.
  - `bucket4:v1_read` has no path literals in the pool (allow on op-table bucket without explicit path anchor).
- Reading `/tmp/foo` at runtime canonicalizes to `/private/tmp/foo`; `bucket5` has only `/tmp/foo` in the literal pool, so the kernel compares against a non-matching literal and denies. `strict_1` embeds the canonical `/private/tmp/strict_ok` path and succeeds. This lines up with the VFS canonicalization experiment’s conclusion that `/tmp/...` is enforced via `/private/tmp/...` literals on this host.
- Node snippets (decoded via `decoder.decode_profile_dict` after SBPL compile):
  - `bucket5`: node 16 (tag 0) and node 22 (tag 6) reference literal `Ftmp/foo`; no nodes reference `/private/tmp/foo`. Other literal refs are shim paths (System/usr/bin/dev/tmp/private).
  - `strict_1`: literal pool includes `U/private/tmp/strict_ok` even though literal_refs show only shim anchors; the canonical literal is present in the pool.
  - `bucket4`: path-agnostic, no path literals in pool.

## Parameterized SBPL (compile + runtime witness)

- Added parameterized specimens:
  - `profiles/param_root_shim.sb` (deny-default allow-root; intended for blob apply, but exec-based probes are brittle).
  - `profiles/param_write_gate.sb` (boolean-gated write allow via `(when (param "ALLOW_DOWNLOADS") ...)`).
  - `profiles/param_deny_root_allow_default.sb` (allow-default deny-root; stable carrier for blob-mode runtime probes).
- Compile-time observation: for `(when (param "ALLOW_DOWNLOADS") ...)`, parameter *presence* gates compilation; different provided values compile to the same blob (mapped; guarded by validation).
- Runtime harness: deny-default + exec-based blob probes can die with SIGABRT when the wrapped helper (`/bin/cat`) cannot fully bootstrap under the applied policy; for a stable blob-mode parameterization witness, use allow-default + parameterized deny-root.
- Promoted a blob-mode witness into `book/profiles/golden-triple/` as `runtime:param_deny_root_ok` (compiled with `ROOT=/private/tmp/ok`) and recorded aligned runtime results in `book/profiles/golden-triple/runtime_results.json`.
