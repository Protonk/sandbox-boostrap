# codex-sandbox (Report)

## Purpose

Determine whether the Codex harness is sandboxed by comparing six host-grounded sensors (S0-S5) across the two harness modes (normal vs elevated), so policy-facing runs do not misattribute harness gates as sandbox policy decisions.

## Baseline and scope

- Host baseline: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Bedrock surfaces referenced (bedrock tier):
  - `book/evidence/graph/mappings/vocab/ops.json`
  - `book/evidence/graph/mappings/vocab/filters.json`
  - `book/evidence/graph/mappings/vocab/ops_coverage.json`
- Scope: harness detection only; no SIP/TCC changes; no policy claims beyond the harness boundary.

## Deliverables / expected outcomes

- A reproducible, six-sensor harness check (S0-S5) with normal vs elevated comparison.
- Run artifacts under `book/evidence/experiments/codex-sandbox/out/codex-sandbox/`.
- A clear outcome statement on harness sandboxing with reliability notes.

## Sensors (S0-S5) and evidence tiers

All sensor outputs are host observations (mapped tier) unless noted; conclusions drawn across sensors are hypothesis tier.

S0. **Self sandboxed** (preflight, scenario)
- Mechanism: `sandbox_check(getpid(), NULL, ...)`.
- Mapped evidence: direct return code in `s0_self_sandbox.json`.

S1. **Mach-lookup preflight** (preflight, scenario)
- Mechanism: `sandbox_check(getpid(), "mach-lookup", filter, service_name)`.
- Mapped evidence: return code in `s1_mach_lookup.json`.
- Reliability note (hypothesis tier): filter constants are missing on this host, so early runs either skipped S1 or produced invalid-args; later runs used an unfiltered fallback and are coarse.

S2. **Bootstrap sentinel** (bootstrap, scenario)
- Mechanism: `bootstrap_look_up` against `com.apple.cfprefsd.agent`.
- Mapped evidence: `kr` in `s2_bootstrap_lookup.json`.

S3. **Sentinel XPC probe** (bootstrap or operation, scenario)
- Mechanism: `policy-witness xpc run --profile minimal fs_op --op stat --path-class tmp`.
- Mapped evidence: `normalized_outcome` and `layer_attribution` in `s3_sentinel_xpc.json`.

S4. **SBPL apply heuristic** (apply, baseline)
- Mechanism: `book/tools/sbpl/wrapper/wrapper --preflight enforce --sbpl allow_all.sb -- /usr/bin/true`.
- Mapped evidence: apply markers in `s4_sbpl_apply.json`.

S5. **Log corroboration** (observer, scenario)
- Mechanism: `log show --last 10s` with sandbox predicate.
- Hypothesis tier: `log show` fails under sandbox and is noisy under elevated; use only as supporting signal.

## Plan and execution log

- Runner: `book/evidence/experiments/codex-sandbox/codex_sandbox.py`.
- Pass A (normal harness): multiple runs to confirm stability.
- Pass B (elevated harness): multiple runs to confirm stability.

## Evidence and artifacts

### Normal harness (sandboxed)

Runs captured under `book/evidence/experiments/codex-sandbox/out/codex-sandbox/`:
- `42b268d9-dc59-43bd-87fc-5ee074c8a42b`
- `d0c480dc-8b05-4d42-9792-6f846ce196ab`
- `2f63d887-46c2-46fa-a36a-e1b46e060911`
- `8a0ffee3-705d-4fe8-801a-c59a254e8510`
- `8992a587-9d3b-4599-853f-6983e1f26b7d`

Mapped observations (consistent across runs):
- S0: `rc=1` (sandboxed).
- S2: `kr=1100` (BOOTSTRAP_NOT_PRIVILEGED).
- S3: `normalized_outcome=xpc_error` with `xpc:openSession_failed` (error 159).
- S4: apply-stage EPERM despite preflight ok.

S1 variability:
- Early runs skipped S1 due to missing filter constants or returned invalid args; later runs used unfiltered fallback (`rc=1`).
- This remains a coarse signal on this host (hypothesis tier).

S5:
- `log show` fails with `Cannot run while sandboxed` (supporting, hypothesis tier).

### Elevated harness (unsandboxed)

Runs captured under `book/evidence/experiments/codex-sandbox/out/codex-sandbox/`:
- `c037475a-79eb-4500-8156-813fd246c596`
- `985ab309-a883-4852-bfa6-0537f8a24362`
- `5d0e304f-db39-4130-aac2-aede2627572b`
- `8c7c7dd3-5161-4116-b6c4-d01c3bc58c82`
- `27d8439e-ffb8-4fa3-9bd6-bb78fa9e5d0b`

Mapped observations (consistent across runs):
- S0: `rc=0` (not sandboxed).
- S2: `kr=0` (bootstrap ok).
- S3: `normalized_outcome=ok` (operation-stage ok).
- S4: apply ok.

S1 variability:
- Early run invalid args when a filter constant was assumed; later runs used unfiltered fallback with `rc=0`.

S5:
- `log show` succeeds but deny lines are unrelated to the current PID; not a reliable indicator (hypothesis tier).

## Representative evidence (mapped tier unless noted)

- S0 normal: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/2f63d887-46c2-46fa-a36a-e1b46e060911/s0_self_sandbox.json`.
- S0 elevated: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/5d0e304f-db39-4130-aac2-aede2627572b/s0_self_sandbox.json`.
- S2 normal: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/2f63d887-46c2-46fa-a36a-e1b46e060911/s2_bootstrap_lookup.json`.
- S2 elevated: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/5d0e304f-db39-4130-aac2-aede2627572b/s2_bootstrap_lookup.json`.
- S3 normal: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/2f63d887-46c2-46fa-a36a-e1b46e060911/s3_sentinel_xpc.json`.
- S3 elevated: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/5d0e304f-db39-4130-aac2-aede2627572b/s3_sentinel_xpc.json`.
- S4 normal: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/2f63d887-46c2-46fa-a36a-e1b46e060911/s4_sbpl_apply.json`.
- S4 elevated: `book/evidence/experiments/codex-sandbox/out/codex-sandbox/5d0e304f-db39-4130-aac2-aede2627572b/s4_sbpl_apply.json`.
- S1 fallback (coarse): `book/evidence/experiments/codex-sandbox/out/codex-sandbox/2f63d887-46c2-46fa-a36a-e1b46e060911/s1_mach_lookup.json`.
- S1 skipped (missing filter constant): `book/evidence/experiments/codex-sandbox/out/codex-sandbox/8a0ffee3-705d-4fe8-801a-c59a254e8510/s1_mach_lookup.json`.
- S5 blocked (hypothesis): `book/evidence/experiments/codex-sandbox/out/codex-sandbox/2f63d887-46c2-46fa-a36a-e1b46e060911/s5_log_corroboration.json`.
- S5 noisy (hypothesis): `book/evidence/experiments/codex-sandbox/out/codex-sandbox/5d0e304f-db39-4130-aac2-aede2627572b/s5_log_corroboration.json`.

## Outcome summary

Hypothesis tier conclusion: normal harness mode is sandboxed and elevated mode is not. This is supported by a four-sensor alignment (S0, S2, S3, S4) across multiple runs, with S1 and S5 remaining coarse or unreliable on this host.

## Reliability assessment

- **High reliability (mapped tier):** S0, S2, S3, S4.
- **Limited reliability:** S1 (filter constants missing, unfiltered fallback only).
- **Low reliability:** S5 (blocked under sandbox, noisy under elevated).

## Blockers / risks

- `sandbox.h` lacks `SANDBOX_FILTER_*` constants on this host, forcing an unfiltered S1 fallback.
- S5 is noisy or blocked, so it cannot be used as a primary signal for harness state.

## Next steps

- If a usable filter constant source appears, enable filtered S1 checks for service-specific preflight.
- If a PID-scoped sandbox log source becomes available under normal harness, re-evaluate S5.
