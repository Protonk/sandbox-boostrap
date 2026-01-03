# gate-witnesses: minimized apply-gate witnesses

## Purpose

Turn “apply-stage `EPERM`” into a shrinkable, regression-tested boundary object on this world (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

In SANDBOX_LORE terms, an apply-stage `EPERM` is **blocked evidence**: the Profile did not attach to the process label, so no PolicyGraph decision for the intended probe can have occurred. This experiment’s artifacts witness that boundary mechanically (contract-driven markers), rather than narratively (stderr substrings).

## Deliverables

- A small corpus of minimized witness pairs (per target):
  - `minimal_failing.sb` (still apply-stage `EPERM`)
  - `passing_neighbor.sb` (one-deletion neighbor where apply succeeds; bootstrap failures are allowed but recorded)
  - `run.json` / `trace.jsonl` with confirmation distributions and tool digests
- A compile-vs-apply split report for the witness pair:
  - compile (`sandbox_compile_*`) vs apply (`sandbox_apply`) outcomes recorded mechanically via tool markers
  - a tiny micro-variant matrix off the minimal failing construct (one edit per run)
- A derived-only feature summary + coarse clustering over the minimized deltas (no semantic claims).
- A small “corroboration bundle” for the message-filter entitlement hypothesis:
  - `codesign` entitlement presence scan over a few system executables vs the harness wrapper.
  - sandbox-kext string xrefs for the entitlement key and related log messages.
- A validation job that re-runs the witnesses and asserts they still witness the boundary on this world.

## Execution sketch

1. Select 2–3 “apply-gated” targets (start with `/System/Library/Sandbox/Profiles/airlock.sb`) plus 1–2 “applies cleanly” controls.
2. Run `python3 book/tools/preflight/preflight.py minimize-gate ...` with `--confirm N` and check in outputs under `out/witnesses/<target>/`.
3. Generate `out/feature_summary.json` and `out/clusters.json` from the checked-in witness pairs.
4. Add a validation job (under `book/integration/carton/validation/`) that asserts:
   - failing stays `failure_stage=="apply"` with `errno==EPERM`
   - neighbor stays `failure_stage!="apply"` (even if bootstrap fails)
