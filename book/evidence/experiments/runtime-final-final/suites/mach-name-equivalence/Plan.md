# Plan – mach-name-equivalence

## Purpose

Test whether `mach-lookup` (resolve) and `mach-register` (publish) treat a global-name AA and a deterministic variant BB the same way under a single SBPL profile that allows AA and leaves BB to deny-default.

## Baseline & scope

- World: `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Scope: one profile, two names, `mach-lookup` + `mach-register` probes.
- Out of scope: inventing new probes beyond `book.api.runtime` and `book/tools` surfaces.

## Steps

1) Run the plan via the runtime harness (`launchd_clean`).
2) Record scenario-lane outcomes for AA vs BB.
3) If `mach-register` has no operation-stage witness, mark as blocked and avoid semantic claims.

## Deliverables

- Runtime bundle under `book/evidence/experiments/runtime-final-final/suites/mach-name-equivalence/out/`.
- Evidence summary in `Report.md` and a brief run log in `Notes.md`.
