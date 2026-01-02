# Hardened Runtime – Plan

## Purpose
Build a clean, provenance-stamped decision-stage runtime lane for non-VFS sandbox surfaces on this host. The focus is on operation-based policy evaluation and the acquire-before vs acquire-after boundary for non-file resources (both treated as hypotheses to validate or falsify on this host).

## Scope
- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` only.
- Non-VFS operations only (mach/XPC, sysctl, IOKit, process-info, system-socket, notifications).
- VFS canonicalization is explicitly out-of-scope except as a recorded observation field.

## Inputs
- SBPL profiles under `book/evidence/experiments/hardened-runtime/sb/`.
- Clean channel execution via `python -m book.api.runtime run --plan book/evidence/experiments/hardened-runtime/plan.json --channel launchd_clean`.
- Runtime harness via `book.api.runtime`.
- Plan/registry data generated via `python -m book.api.runtime plan-build --template hardened-runtime --out book/evidence/experiments/hardened-runtime --overwrite` (plan-build skips expected_matrix.json by default; use `--write-expected-matrix` for a static snapshot).

## Outputs
- `out/LATEST/run_manifest.json` (clean-channel provenance bundle).
- `out/LATEST/baseline_results.json` (unsandboxed baseline comparator).
- `out/LATEST/runtime_results.json` + `out/LATEST/runtime_events.normalized.json` (decision-stage evidence).
- `out/LATEST/mismatch_packets.jsonl` (bounded mismatch packets with enumerated reasons).
- `out/LATEST/oracle_results.json` (sandbox_check oracle lane only).
- `out/LATEST/summary.json` + `out/LATEST/summary.md` (status and coverage).
- `out/LATEST/artifact_index.json` (bundle index + digests).

## Plan
1. Stand up the clean-channel harness (launchd staging + apply preflight + run manifest gating).
2. Seed initial non-VFS families (mach-lookup, sysctl-read) with baseline and oracle lanes.
3. Expand families (IOKit, process-info, system-socket, notifications) using the same baseline/oracle/mismatch scaffolding.
4. Add acquire-before vs acquire-after probes for non-file resources to map the warmup boundary (partial, under exploration).

## Status
- Initial scaffold only; no hardened-runtime runs recorded yet.
