# Entitlement Diff – Research Report

## Purpose
Use EntitlementJail 1.x’s process zoo to compare entitlement deltas across profiles with host-bound runtime witnesses, and document API semantics used by downstream tooling. Permission-shaped failures are treated as runtime outcomes unless deny evidence is captured.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (SIP enabled).
- Runtime witness tool: `book/tools/entitlement/EntitlementJail.app` (EntitlementJail 1.x CLI).
- Primary workflows: `run-xpc` with `--profile` ids; `run-matrix` groups; wait/attach flows.
- Log capture: attempted via `--log-path-class tmp --log-name ...`, but writes fail with `write_failed` (operation not permitted) under the service tmp dir; deny evidence is not captured.
- Out of scope: `run-system` / `run-embedded`, DTrace work, or cross-host claims.

## Execution summary
- Implemented EntitlementJail 1.x runner + scenario modules and ran all probes via `run_entitlementjail.py`.
- Captured inventory, evidence bundle, matrix groups, and core probe scenarios (bookmarks, downloads_rw, net_client, probe_families, bookmark_roundtrip).
- Exercised wait/attach workflows (wait_attach, wait_timeout_matrix, wait_path_class, wait_multi_trigger, wait_probe_wait, wait_hold_open, wait_create, wait_interval, attach_holdopen_default).
- Exercised additional API claims: health_check_profile, run_matrix_out, bundle_evidence_out, quarantine_lab.
- Wait/attach workflow details live in `book/experiments/entitlement-diff/wait-attach-flow.md`.

## API claims vs witnesses
| API claim (EntitlementJail.md) | Scenario/output | Status / notes |
| --- | --- | --- |
| `run-xpc --profile <id>` selects a profile without explicit bundle id | `book/experiments/entitlement-diff/out/ej/bookmarks.json` | ok (host witness) |
| `--wait-path-class` + `--wait-name` implies FIFO wait under container | `book/experiments/entitlement-diff/out/ej/wait_path_class.json` | partial runtime (wait-ready FIFO path under service tmp) |
| `--wait-fifo` + `--wait-create` auto-creates FIFO | `book/experiments/entitlement-diff/out/ej/wait_create.json` | partial runtime (FIFO created and stat shows FIFO) |
| `--wait-exists` honors `--wait-interval-ms` | `book/experiments/entitlement-diff/out/ej/wait_interval.json` | partial runtime (details.wait_interval_ms reflects inputs) |
| `--wait-timeout-ms` is in milliseconds; timeout yields `normalized_outcome=timeout` | `book/experiments/entitlement-diff/out/ej/wait_timeout_matrix.json` | partial runtime (fast triggers ok, slow triggers timeout) |
| `--attach <seconds>` implies hold-open unless overridden | `book/experiments/entitlement-diff/out/ej/attach_holdopen_default.json` | partial runtime (attach-only run lasts ~3.2s vs ~0.2s with `--hold-open 0`) |
| `health-check --profile <id>` supported | `book/experiments/entitlement-diff/out/ej/health_check_profile.json` | ok (exit_code 0 for minimal/debuggable) |
| `run-matrix --out` sets `data.output_dir` to the supplied path | `book/experiments/entitlement-diff/out/ej/run_matrix_out.json` | ok (output_dir matches `--out`) |
| `bundle-evidence --out --include-health-check` reports output_dir | `book/experiments/entitlement-diff/out/ej/bundle_evidence_out.json` | ok (output_dir matches `--out`) |
| `quarantine-lab` text payload path executes | `book/experiments/entitlement-diff/out/ej/quarantine_lab.json` | ok (no execution; exit_code 0) |
| `--log-path-class` writes capture under service tmp | `book/experiments/entitlement-diff/out/ej/downloads_rw.json` | blocked (write_failed; log file missing) |

## Evidence & artifacts
- Inventory and discovery: `book/experiments/entitlement-diff/out/ej/inventory.json`.
- Evidence bundle: `book/experiments/entitlement-diff/out/ej/evidence.json`, `book/experiments/entitlement-diff/out/ej/evidence/latest`.
- Matrix groups: `book/experiments/entitlement-diff/out/ej/matrix.json`, `book/experiments/entitlement-diff/out/ej/matrix/<group>/run-matrix.*`.
- Core scenarios: `book/experiments/entitlement-diff/out/ej/bookmarks.json`, `book/experiments/entitlement-diff/out/ej/downloads_rw.json`, `book/experiments/entitlement-diff/out/ej/net_client.json`, `book/experiments/entitlement-diff/out/ej/probes_userdefaults.json`, `book/experiments/entitlement-diff/out/ej/probes_filesystem.json`, `book/experiments/entitlement-diff/out/ej/bookmark_roundtrip.json`.
- Wait/attach outputs: `book/experiments/entitlement-diff/out/ej/wait_attach.json`, `book/experiments/entitlement-diff/out/ej/wait_timeout_matrix.json`, `book/experiments/entitlement-diff/out/ej/wait_path_class.json`, `book/experiments/entitlement-diff/out/ej/wait_multi_trigger.json`, `book/experiments/entitlement-diff/out/ej/wait_probe_wait.json`, `book/experiments/entitlement-diff/out/ej/wait_hold_open.json`, `book/experiments/entitlement-diff/out/ej/wait_create.json`, `book/experiments/entitlement-diff/out/ej/wait_interval.json`, `book/experiments/entitlement-diff/out/ej/attach_holdopen_default.json`.
- API surface checks: `book/experiments/entitlement-diff/out/ej/health_check_profile.json`, `book/experiments/entitlement-diff/out/ej/run_matrix_out.json`, `book/experiments/entitlement-diff/out/ej/bundle_evidence_out.json`, `book/experiments/entitlement-diff/out/ej/quarantine_lab.json`.
- Workflow narrative: `book/experiments/entitlement-diff/wait-attach-flow.md`.

## Blockers / risks
- Deny evidence is not captured: log capture writes fail with `write_failed` under the service tmp dir; runtime outcomes are partial until an out-of-sandbox log observer is used.
- Legacy SBPL diff artifacts were removed during the EntitlementJail 1.x reset; regenerate them if still needed for profile-level diffs.

## Next steps
- If deny evidence is required, use an out-of-sandbox observer and correlate by `data.details.service_pid` / `data.details.process_name`.
- Regenerate SBPL diff outputs only if static diffs remain part of the experiment’s goals.
