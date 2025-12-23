# Entitlement Diff – Research Report

## Purpose
Trace how selected entitlements alter compiled sandbox profiles and the resulting allow/deny behavior. Ground the entitlement concept in concrete profile/filter/parameter changes and, where possible, runtime probes.

## Baseline & scope
- World: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (SIP enabled).
- Tooling: `entitlement_sample` binaries, App Sandbox stubs under `sb/`, `build_profiles.py` to inline/compile, `diff_profiles.py` to decode/diff, `run_probes.py` for blob-applied runtime probes, and `book/tools/entitlement/EntitlementJail.app` for App Sandbox runtime witnesses. The jail runner remains `run_probes_jail.py` (process-exec path, currently blocked), and the in-process witness uses `run-xpc` (captured by `run_xpc_matrix.py` with log windows).
- Entitlements: baseline has only app-sandbox; variant enables `com.apple.security.network.server` and a single mach-lookup global-name (`com.apple.cfprefsd.agent`). Bookmarks app-scope is used as the modern entitlement example for App Sandbox runtime witnesses.

## Deliverables / expected outcomes
- Minimal C sample and signed variants (`entitlement_sample`, `entitlement_sample_unsigned`) with extracted entitlements recorded in `out/*.entitlements.plist`.
- A reproducible method for deriving per-entitlement App Sandbox profiles suitable for decoding and comparison (App Sandbox stubs → expand/compile to blobs via libsandbox).
- Planned diffs that connect entitlement keys → SBPL parameters/filters → compiled graph deltas → runtime allow/deny behavior.
- A short manifest tying binaries, profiles, decoded diffs, and probe logs together for this host.
- A second runtime runner using `EntitlementJail.app` that captures behavior when executing probes under the jail (expected to reflect an App Sandbox parent), with structured outputs suitable for comparing against wrapper-applied behavior.
  - Skeleton witness: `out/jail_env_probe.json` establishes the observed `HOME`/`TMPDIR`/`PWD` under the jail.
- An EntitlementJail `run-xpc` witness record that contrasts baseline vs `com.apple.security.files.bookmarks.app-scope` behavior without `process-exec*` (partial runtime evidence).
- EntitlementJail `run-xpc` witness sets for downloads read-write and network client, with log captures around each probe (partial runtime evidence).

## Plan & execution log
### Completed
- Sample program built (`entitlement_sample`) and unsigned variant captured with entitlements in `out/entitlement_sample*.entitlements.plist`.
- App Sandbox stubs derived from `book/profiles/textedit/application.sb` with pinned params/entitlements (`sb/appsandbox-*.sb`); `build_profiles.py` expands/compiles to `sb/build/*.expanded.sb` and `.sb.bin`.
- Added App Sandbox stubs for `network.client`, downloads read-write, and bookmarks app-scope; rebuilt `sb/build/*.expanded.sb`/`.sb.bin` and refreshed `out/decoded_profiles.json` + `out/profile_diffs.json` to cover baseline + multiple variants.
- Decoded both blobs and wrote structural deltas to `out/profile_diffs.json` (ops present via op_table indices, literal adds/removals, literal_refs deltas, tag deltas) alongside raw decodes in `out/decoded_profiles.json`.
- Runtime probes via `book/tools/sbpl/wrapper/wrapper --blob` with staged binaries under `/private/tmp/entitlement-diff/app_bundle/`:
  - baseline (app sandbox only): `entitlement_sample` bind denied (`bind: Operation not permitted`), `mach_probe com.apple.cfprefsd.agent` allowed.
  - network_mach (network.server + mach allowlist): bind allowed, mach-lookup allowed.
  Results recorded in `out/runtime_results.json`.
- Implemented the EntitlementJail-based runner (`run_probes_jail.py`) as a second runtime witness and executed an env-probe + exec-gate discriminant run:
  - Observed jail environment: `HOME=/Users/achyland/Library/Containers/com.yourteam.entitlement-jail/Data` (see `out/jail_env_probe.json`).
  - Per-run capture isolation: jail outputs are written under `stage_root/jail_out/<session_id>/...` to avoid stale `.done` reuse between runs (see `meta.session_id` in `out/jail_env_probe.json`).
  - Exec-gate discriminant (see `out/jail_env_probe.json` → `exec_gate`):
    - In-place system binary executes: `/usr/bin/true` is `executed`.
    - Relocated system binary fails: a staged copy of `/usr/bin/true` under `stage_root` is `blocked` (`rc=126`, `Operation not permitted`).
    - All staged probe Mach-Os (`file_probe`, `mach_probe`, `entitlement_sample{,_unsigned}`) are `blocked` with the same exec failure.
  - Authoritative denial witness (partial, runtime): kernel log capture shows `process-exec*` denies for the staged paths:
    - `out/jail_logs_exec_gate_relocated_true_c7c4fdfb854b7ca0.log` includes `deny(1) process-exec* .../relocated_true_c7c4fdfb854b7ca0`.
    - `out/jail_logs_exec_gate_file_probe_usage_c7c4fdfb854b7ca0.log` includes `deny(1) process-exec* .../file_probe`.
  - Because `process-exec*` is denied for staged paths on this host, the jail witness cannot yet execute our probe binaries from the container stage root; `out/jail_runtime_results.json` is therefore `blocked` with `failure_kind: EXEC_GATE_LOCATION_OR_WRITABLE_DENIED`.
- Ran EntitlementJail `run-xpc` probes for baseline vs bookmarks app-scope services (in-process, no `process-exec*`):
  - Both services report containerized `HOME`/`TMPDIR` and App Sandbox in `capabilities_snapshot` + `world_shape`.
  - `bookmark_make` fails under `ProbeService_minimal` with a ScopedBookmarksAgent creation error, but succeeds under `ProbeService_bookmarks_app_scope` and returns a bookmark token.
  - `bookmark_op --op stat` succeeds under `ProbeService_bookmarks_app_scope` for the created bookmark target.
  - Results recorded in `out/jail_xpc_bookmarks_witness.json` (runtime witness, **partial**; log capture included).
- Ran EntitlementJail `run-xpc` probes for downloads read-write and network client (baseline vs entitlement service):
  - Downloads: `downloads_rw` is `permission_error` under `ProbeService_minimal`, and `ok` under `ProbeService_downloads_rw`.
  - Network: `net_op tcp_connect` is `permission_error` under `ProbeService_minimal`; `ProbeService_net_client` connects successfully when a local listener is running (listener accept recorded in the witness JSON).
  - Log windows are now scoped to kernel `Sandbox:` lines that include the service process name (and `ScopedBookmarkAgent` for bookmarks). In this run, the bookmarks logs captured the agent’s `file-read-data` denies, while the downloads/net-client runs produced empty log windows (no service-attributed kernel lines observed).

### Planned
- With `process-exec*` denied for container-staged paths, the next phase is to decide whether to route around the exec gate or treat it as the witness conclusion.

  1) **Route around: bundle the probes (new witness variant)**
     - Build a separate, explicitly experimental App Sandbox parent runner that embeds `file_probe`, `mach_probe`, and the entitlement-diff samples as nested code inside the app bundle, then exec them from within the bundle.
     - Treat this as a distinct witness with its own provenance (codesign identity, hashes, entitlements) rather than modifying the notarized `EntitlementJail.app` in place.

  2) **Treat as conclusion (current witness)**
     - Record that, on this host baseline, an App Sandbox parent can execute in-place platform binaries but cannot `process-exec*` arbitrary staged binaries from its container stage root; therefore, parity vs wrapper-applied blobs is not measurable via this witness path without altering packaging/signing.

## Evidence & artifacts
- Source and build scaffolding for `entitlement_sample` under this experiment directory; extracted entitlements in `out/entitlement_sample*.entitlements.plist`.
- App Sandbox stubs and compiled outputs in `sb/` and `sb/build/` (expanded SBPL + blobs); build helper `build_profiles.py`.
- Decodes and structural diffs in `out/decoded_profiles.json` and `out/profile_diffs.json` (includes literal_refs and tag_literal_refs); manifest recorded in `out/manifest.json`.
- Runtime results in `out/runtime_results.json` (baseline: network bind/outbound denied, mach allowed, container file read/write allowed; network_mach: bind allowed, mach allowed, file read/write allowed, outbound `nc` to localhost still denied).
- Jail-run witness artifacts: `out/jail_env_probe.json`, `out/jail_runtime_results.json`, `out/jail_entitlements.json`, `out/jail_parity_summary.json`, plus exec-gate log captures `out/jail_logs_exec_gate_{relocated_true,file_probe_usage}_c7c4fdfb854b7ca0.log`.
- EntitlementJail in-process witness artifacts:
  - `out/jail_xpc_bookmarks_witness.json` (baseline vs bookmarks app-scope probes; includes raw JSON outputs and bookmark token).
  - `out/jail_xpc_downloads_rw_witness.json` (baseline vs downloads read-write probes).
  - `out/jail_xpc_net_client_witness.json` (baseline vs network client probes).
  - `out/jail_xpc_logs/` (per-run log captures scoped to service process names; some runs are empty, treat as partial attribution).
- EntitlementJail runner for these probes: `run_xpc_matrix.py` (scenario runner + log capture).

## Static diff ↔ runtime witness mapping (partial)

These mappings are **partial**: the decoded profiles show tag-count shifts but no literal/literal_ref deltas that include entitlement key strings.

- **bookmarks_app_scope**: Expected baseline cannot create/resolve security-scoped bookmarks while app-scope can; observed `bookmark_make` fails under `ProbeService_minimal`, succeeds under `ProbeService_bookmarks_app_scope`, and `bookmark_op --op stat` succeeds (`out/jail_xpc_bookmarks_witness.json`); static diff shows no literal/literal_ref deltas, a new tag `244` (baseline 0 → variant 1), and no entitlement key strings in decoded literals.
- **downloads_rw**: Expected baseline denies Downloads write while entitlement allows; observed `downloads_rw` is `permission_error` under `ProbeService_minimal` and `ok` under `ProbeService_downloads_rw` (`out/jail_xpc_downloads_rw_witness.json`); static diff shows no literal/literal_ref deltas and multiple tag-count shifts (see `out/profile_diffs.json`), with no entitlement key strings in decoded literals.
- **net_client**: Expected baseline denies outbound connect while entitlement allows; observed `net_op tcp_connect` is `permission_error` under `ProbeService_minimal` and `ProbeService_net_client` connects successfully with a local listener (`out/jail_xpc_net_client_witness.json`); static diff shows no literal/literal_ref deltas and broad tag-count shifts (see `out/profile_diffs.json`), with no entitlement key strings in decoded literals.
- **network_mach** (wrapper-applied): Expected network server allow + mach-lookup allowlist; observed bind denied in baseline and allowed in `network_mach`, mach-lookup allowed in both (`out/runtime_results.json`); static diff shows no literal/literal_ref deltas and tag-count shifts only (see `out/profile_diffs.json`), with no entitlement key strings in decoded literals.

## Blockers / risks
- Runtime observations are limited to the staged binaries and simple probes; broader coverage (other ops/filters) remains open.
- Entitlement-driven decode diffs are structural; filter/semantic alignment is still provisional until more tag/field2 mapping and runtime coverage exist.
- The jail runner may refuse to execute probes from the current staging location (`/private/tmp/...`) or may force containerized paths; this could make the jail path `blocked` until we restage probes to observed container directories.
- Current jail-run is `blocked` earlier than expected: even from the observed jail container `HOME`, executing a staged probe binary (`file_probe`) fails with `Operation not permitted`. Kernel log witnesses show this is a `process-exec*` deny for staged paths (see `out/jail_logs_exec_gate_file_probe_usage_c7c4fdfb854b7ca0.log`).
- The EntitlementJail `run-xpc` results are **partial** runtime witnesses: they show entitlement-dependent API outcomes, but log correlation is incomplete (some runs emit no service-attributed kernel lines).
- Bookmarks is the only modern entitlement exercised here; Photos is intentionally out of scope for this run.
- Log windows include unrelated `Sandbox:` denies (not from the probe service); attribution requires PID scoping or tighter predicates to avoid over-reading.

## Next steps
- Decide whether the exec-gate witness is “done” (a clean `process-exec*` block) or whether to build a bundled-probes app variant and extend `run_probes_jail.py` to exec from the bundle, then rerun the shared probe matrix and regenerate `out/jail_parity_summary.json`.
- Tighten log attribution for `run-xpc` probes by scoping to the XPC PID (or a more reliable per-run identifier) and expanding the window when service-attributed kernel lines are missing.
- For network client, keep a controlled local listener so the allow case is “connect succeeds” and listener acceptance is recorded alongside the probe result.
- Extend SBPL diffs to explicitly note which literal_refs/tags align with the new entitlement variants (bookmarks, downloads, network client) and keep claims **partial** until runtime + log attribution align.
