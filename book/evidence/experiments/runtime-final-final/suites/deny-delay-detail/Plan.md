# deny-delay-detail (Plan)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## Goal

Establish a reusable process for diagnosing intermittent kernel deny evidence, and quantify which observer/probe configurations reliably produce deny lines tied to vocab bindings across profiles on this host baseline.

## Inputs and tooling

- PolicyWitness API: `book.api.witness.client`, `book.api.witness.enforcement`, `book.api.witness.compare`.
- Observer: `book.api.witness.observer` (manual `--last` and external range; capture mode if it becomes available).
- Vocab (canonical): `book/integration/carton/bundle/relationships/mappings/vocab/ops.json`, `book/integration/carton/bundle/relationships/mappings/vocab/filters.json`, `book/integration/carton/bundle/relationships/mappings/vocab/ops_coverage.json`.
- Path helpers: `book.api.path_utils` for repo-relative outputs.

## Step 1: Capture the processual knowledge (how we resolved it)

1) **Define the decision ladder**
   - Document the sequence used to resolve intermittent deny evidence:
     - observer mode choice (manual vs external vs capture)
     - probe design changes (ladder probes, per-run unique filenames)
     - stability check (row flips across repeated runs)
   - For each decision, list the evidence basis and the run artifacts that justify the shift.

2) **Emit a short playbook**
   - Produce a minimal, host-scoped troubleshooting flow that starts with a missing deny line and ends with a stable resolved row or a declared limit.
   - Attach links to the canonical artifacts and explicit limits (observer missing, filter inferred, etc.).

## Step 2: Determine what resolves it and how reliably

1) **Reliability matrix design**
   - Define axes:
     - observer mode: manual `--last`, external range, capture (if available)
     - probe families: `downloads_rw`, `fs_op`, `fs_coordinated_op`, `net_op`, `sandbox_check`
     - profiles: `minimal`, `net_client`, `temporary_exception`
     - path mode: path-class vs direct path for Downloads
   - Keep a stable `plan_id` format and per-run `row_id` identifiers.

2) **Run protocol**
   - Run two consecutive passes per configuration.
   - Record:
     - `observed_deny` (boolean)
     - operation/filter mapping status (resolved vs unresolved)
     - limits (observer missing, filter inferred)
   - Compute stability as “resolved rows identical across runs.”

3) **Outputs**
   - `reliability_matrix.json` (machine-readable matrix)
   - `reliability_summary.txt` (human-readable summary)
   - A short list of “reliable” vs “unstable” probe families per observer mode.

## Step 3: Generalize to other situations

1) **Non-file probes**
   - Include `net_op` and `sandbox_check` controls to detect when deny evidence is absent even with permission-shaped failures.

2) **Containerization contrast**
   - For Downloads, compare:
     - path-class targets (container paths)
     - direct host paths (explicit `--allow-unsafe-path`)
   - Record differences in deny evidence and mapping.

3) **Baseline comparison hook**
   - For stable configurations, wire a tri-run comparison using `book.api.witness.compare.compare_action` to capture entitlements vs SBPL vs none baselines.
   - Use the SBPL preflight record to label apply-stage gates.

## Status targets

- Initial status: `partial` until the reliability matrix is populated and a stable configuration is documented.
- Promote to `ok` only after at least one observer/probe configuration produces stable resolved rows across two runs.
