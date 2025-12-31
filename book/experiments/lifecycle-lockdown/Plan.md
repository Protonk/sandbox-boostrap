# lifecycle-lockdown (Plan)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1 / 23E224, arm64).

## Purpose

Establish whether the *claims implied by `book.api.lifecycle` probe outputs* are supportable via multiple, independent witnesses on this host baseline.

This experiment is not about sandbox semantics. It is about whether our lifecycle probes (entitlements, platform policy probes, containers/redirects, and apply attempts) are:

- mechanically correct about what they observed,
- stable enough to treat as evidence inputs, and
- honest about confounders (apply gating, signing identity, platform policy).

## Open questions (targets)

### A) Entitlements + signing metadata: Security.framework vs codesign

When `book.api.lifecycle entitlements` reports:

- `signing_identifier`
- `entitlements_present`

…how well does that agree with an independent view of the same binary via `codesign` across at least two signing variants on this host (unsigned vs ad-hoc-signed with an explicit entitlements plist)?

Limits to keep explicit:
- “entitlements present” is not “entitlements are effective”; it is only signature metadata visibility.
- ad-hoc signing constraints may prevent some entitlement payloads; record the boundary honestly.

### B) Apply gating classification across entrypoints + harness identity

When `book.api.lifecycle apply-attempt` reports an apply-stage failure (`sandbox_apply` + `errno`) this repo treats it as **apply-stage evidence**, not policy semantics.

Two specific questions:

1. For the *same SBPL input*, how do apply outcomes differ across entrypoints:
   - `sandbox_init` (wrapper SBPL mode)
   - `sandbox_apply` (wrapper blob mode and `book.api.lifecycle apply-attempt`)

2. For a known apply-gated SBPL shape (from the gate-witness corpus), do the observed apply outcomes line up with:
   - wrapper markers (`tool:"sbpl-apply"`)
   - preflight scan classification (`book/tools/preflight preflight.py scan`)

This is explicitly allowed to surface “we don’t know yet”: if outcomes differ by harness identity, that is itself a useful boundary.

## Execution

Primary runner:

```sh
python3 book/experiments/lifecycle-lockdown/run_lockdown.py --out book/experiments/lifecycle-lockdown/out
```

The runner records raw command outputs (stdout/stderr) plus small normalized summaries so the evidence can be re-read without rerunning.

Execution-lane isolation (runtime API, staged via `launchd_clean`):

```sh
python3 -m book.api.runtime run \
  --plan book/experiments/lifecycle-lockdown/plan.json \
  --channel launchd_clean \
  --out book/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce

SANDBOX_LORE_PREFLIGHT_FORCE=1 python3 -m book.api.runtime run \
  --plan book/experiments/lifecycle-lockdown/plan.json \
  --channel launchd_clean \
  --out book/experiments/lifecycle-lockdown/out/runtime/launchd_clean_force
```

Apply inputs note:
- The apply branch uses the `gate-witnesses` corpus SBPL + precompiled blobs under `compile_vs_apply/` (instead of minting new `.sb.bin` files under `out/`) so the repo-wide preflight index manifest does not drift.

## Deliverables

- `out/` artifacts:
  - entitlements: unsigned vs ad-hoc signed probe outputs + codesign outputs + comparison summary
  - apply: wrapper SBPL vs wrapper blob vs `apply-attempt` JSON + preflight scan result + comparison summary
- `Report.md`: what is supportable (`mapped`) vs what remains bounded (`hypothesis`), with explicit limits and evidence paths.
