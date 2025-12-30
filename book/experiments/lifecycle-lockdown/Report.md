# lifecycle-lockdown (Report)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1 / 23E224, arm64).

## Purpose

Evaluate whether `book.api.lifecycle` probe outputs are supportable by independent witnesses on this host baseline.

This report summarizes the first host runs of `run_lockdown.py` and records what is (and is not) supportable from the committed artifacts.

## Open questions

See `book/experiments/lifecycle-lockdown/Plan.md`.

## Evidence (expected locations)

- Entitlements cross-check outputs under `book/experiments/lifecycle-lockdown/out/entitlements/`
- Apply cross-check outputs under `book/experiments/lifecycle-lockdown/out/apply/`

## Results (current)

### A) Entitlements + signing metadata

Observation: `book.api.lifecycle entitlements` agrees with `codesign` about “entitlements present” for the same binary across two signing variants.

- Unsigned build:
  - Security.framework view: `entitlements_present=false`, `signing_identifier=entitlements_example`
  - codesign view: no entitlements payload reported
- Ad-hoc signed with explicit (empty) entitlements plist:
  - Security.framework view: `entitlements_present=true`, `signing_identifier` changes (adhoc id suffix)
  - codesign view: entitlements payload reported as an empty dict (`<dict></dict>`)

Evidence:
- `book/experiments/lifecycle-lockdown/out/entitlements/summary.json`
- `book/experiments/lifecycle-lockdown/out/entitlements/entitlements_unsigned.json`
- `book/experiments/lifecycle-lockdown/out/entitlements/entitlements_signed.json`
- `book/experiments/lifecycle-lockdown/out/entitlements/codesign_entitlements_signed.stdout.txt`

Tier: `mapped` (metadata visibility on this host).

### B) Apply attempts + preflight + wrapper markers

Observation: wrapper-side preflight classification and wrapper markers line up, but this harness environment appears to block apply even for a “passing neighbor” profile.

- Gate SBPL shape (`minimal_failing.sb`):
  - Preflight scan: `likely_apply_gated_for_harness_identity`
  - Wrapper + API with preflight `enforce`: preflight blocks before apply (no `sbpl-apply` markers).
  - Wrapper + API with preflight `force`: apply is attempted and fails with `errno=1 (EPERM)` for both:
    - SBPL mode (`sandbox_init`)
    - blob mode (`sandbox_apply`)
- Passing neighbor (`passing_neighbor.sb`):
  - Wrapper preflight marker: `no_known_apply_gate_signature`
  - Apply still fails with `errno=1 (EPERM)` (`sandbox_init` in SBPL mode, `sandbox_apply` in blob mode).

This means the experiment has not yet separated “profile-shape apply gating” from “ambient harness constraint that blocks sandbox_init/sandbox_apply”.

Evidence:
- `book/experiments/lifecycle-lockdown/out/apply/summary.json`
- `book/experiments/lifecycle-lockdown/out/apply/api_apply_attempt_passing.json`
- `book/experiments/lifecycle-lockdown/out/apply/api_apply_attempt_gate.json`
- `book/experiments/lifecycle-lockdown/out/apply/wrapper_sbpl_passing.stderr.txt`
- `book/experiments/lifecycle-lockdown/out/apply/wrapper_sbpl_gate_force.stderr.txt`
- `book/experiments/lifecycle-lockdown/out/apply/wrapper_blob_gate_force.stderr.txt`

Tier: `hypothesis` (apply-stage EPERM; confounded by harness/environment constraints).

## Next step (blocked / needs direction)

To answer the “harness constraint vs profile-shape gate” ambiguity, rerun the apply portion under a clean, non-nested execution lane (candidate: `book.api.runtime` `launchd_clean` channel) and compare whether the passing neighbor can apply cleanly there.

## Limits

- This experiment is host-scoped and does not generalize beyond `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Apply-stage `EPERM` remains apply-stage evidence; it is not a policy decision.
