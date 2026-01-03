# policywitness-deny-atlas (Plan)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Goal

Create a reproducible, observer-backed deny atlas for PolicyWitness profiles using `book.api.witness`. The atlas must explicitly distinguish resolved denies from unresolved permission-shaped outcomes.

## Inputs and tooling

- PolicyWitness API: `book.api.witness.client`, `book.api.witness.enforcement`, `book.api.witness.lifecycle`.
- Observer: `book.api.witness.observer` (manual `--last` default; external range available via `--observer-mode external`).
- Vocab (canonical): `book/integration/carton/bundle/relationships/mappings/vocab/ops.json`, `book/integration/carton/bundle/relationships/mappings/vocab/filters.json`, `book/integration/carton/bundle/relationships/mappings/vocab/ops_coverage.json`.
- Path helpers: `book.api.path_utils` for repo-relative outputs.

## Deny set (initial probes)

Use a minimal probe set intended to produce a denial in most profiles, plus controls:

1) `fs_op --op open_read --path /private/var/db/launchd.db/com.apple.launchd/overrides.plist --allow-unsafe-path`
2) `fs_op --op open_read --path-class tmp --target specimen_file` (expected allow)
3) `sandbox_check --operation file-read-data --path /etc/hosts` (not a deny claim, just a baseline)
4) `net_op --op tcp_connect --host 127.0.0.1 --port 9` (expected host error; should remain non-deny)

If `probe_catalog` shows a Mach/XPC probe (for example a `mach_*` or `bootstrap`-named probe), add one "mach-lookup shaped" call to increase coverage.

## Step-by-step plan

1) **Discovery**
   - Call `client.list_profiles()` and filter `kind == "probe"`.
   - Save `profiles.json` snapshot (repo-relative path).
   - For each base profile, record profile id + bundle id from `show_profile`.

2) **Probe execution**
   - For each profile:
     - Run the deny set using `client.run_probe` with
       `OutputSpec(bundle_root=<out_root>, bundle_run_id=<run_id>)` so each run
       is bundle-shaped and emits `artifact_index.json`.
     - Keep `plan_id` stable, set `row_id` per probe.
     - Default to manual observer (`--manual-observer-last`) to avoid missing deny lines.
     - Use `--include-stateful-probes` when you need stronger deny yield; it adds `downloads_rw`
       and home listdir probes with per-run unique file names.
     - Use `--include-downloads-ladder` to add a downloads ladder:
       `fs_op create` (path-class downloads), `fs_op create` (direct host path),
       `fs_coordinated_op write` (path-class downloads), and a `sandbox_check` control.

3) **Observer parsing**
   - For each probe result, load the observer report (or record missing).
   - Extract:
     - `observed_deny` (boolean)
     - `predicate`
     - log excerpt lines
   - Prefer `deny_lines` from the observer report; fall back to `MetaData` JSON if present.
   - Parse the log payload for fields:
     - `operation`
     - `primary-filter`
     - `primary-filter-value`
     - `target`
     - If the log line omits the filter, infer `path` for `file-*` operations and record `filter_inferred`.
   - Map `operation` to vocab `ops.json`; map `primary-filter` to `filters.json`.

4) **Resolution assignment**
   - **Resolved**: observer report exists, `observed_deny == true`, and operation/filter map to vocab.
   - **Unresolved**: permission-shaped outcome with no observer evidence or unmapped fields.
   - Record explicit `limits` for each record (missing observer, unmapped operation/filter, `filter_inferred`, etc.).

5) **Atlas emission**
   - Write `deny_atlas.json` with rows:
     - `profile_id`, `probe_id`, `probe_args`, `operation`, `filter`, `target`
     - `observed_deny`, `normalized_outcome`, `errno`
     - `binding_status`, `limits`
     - `observer_report_path`, `probe_log_path`
   - Write `runs.jsonl` with full per-probe `ProbeResult` + parsed observer summary.

6) **Repeatability**
   - Re-run the deny set twice (same flags) and require identical resolved rows for a stability pass.
   - If a row flips, record it as unstable and keep the atlas `partial`.

7) **Report updates**
   - Update `Report.md` with what was run, the highest-signal deny records, and any blockers.
   - Do not upgrade unresolved outcomes without observer-backed evidence.

## Data schema (suggested)

```json
{
  "schema_version": 1,
  "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
  "records": [
    {
      "profile_id": "minimal",
      "probe_id": "fs_op",
      "probe_args": ["--op", "open_read", "--path", "..."],
      "normalized_outcome": "permission_error",
      "errno": 1,
      "observed_deny": true,
      "operation": "file-read-data",
      "filter": "path",
      "target": "/private/var/db/launchd.db/com.apple.launchd/overrides.plist",
      "binding_status": "resolved",
      "limits": [],
      "probe_log_path": "book/evidence/experiments/runtime-final-final/suites/policywitness-deny-atlas/out/<run_id>/...",
      "observer_report_path": "book/evidence/experiments/runtime-final-final/suites/policywitness-deny-atlas/out/<run_id>/..."
    }
  ]
}
```

## Status targets

- Initial run: `partial` (expect missing denies or missing observer output).
- Promote to `ok` only after multiple profiles show resolved denies with stable operation/filter mapping.
