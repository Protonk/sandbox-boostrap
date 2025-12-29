# runtime service contract (SPEC)

This document is the reference contract for `book/api/runtime/` as a repo-level service. It is written for agents and future tooling that need reliable runtime evidence production without importing experiment code or relying on shell state.

Scope note: this is a *service contract* for evidence production and artifact IO. It does not claim global sandbox semantics; it describes what `runtime` writes and what its APIs guarantee on this host baseline.

## 1) Bundle contract

### 1.1 Directory layout (run-scoped bundles)

A plan run writes into a *bundle root* (usually an experiment `out/` directory) using a run-scoped subdirectory:

- `out/<run_id>/...` – the run-scoped bundle directory
- `out/LATEST` – a convenience pointer containing the most recent committed `run_id` (updated only after commit)

Consumers may pass either `out/` or `out/<run_id>/` to `load_bundle()` and related APIs. When `out/LATEST` exists and points to a valid run directory, it is used to resolve the bundle root.

### 1.2 Bundle lifecycle and commit barrier

The bundle lifecycle is recorded in `run_status.json`:

- `state=in_progress` – the run is still writing; strict consumers must refuse to load (no stable contract)
- `state=complete` – the run finished its main work and recorded a final status (the commit barrier is still `artifact_index.json`)
- `state=failed` – the run failed; an index may still exist for debugging

The commit barrier is `artifact_index.json`. A bundle is considered **committed** once `artifact_index.json` exists in the run-scoped directory. `out/LATEST` is updated only after this commit step.

### 1.3 `artifact_index.json` invariants

`artifact_index.json` is a manifest-verified index of artifacts:

- `schema_version`, `run_id`, `world_id`
- `artifacts[]`: each entry includes `path` (repo-relative string), `file_size`, `sha256`, and (when present) per-artifact `schema_version`
- `missing[]`: repo-relative strings for expected artifacts that were absent at index time
- `status`: `ok|partial|failed`

Writer rule: the index is written last (atomic replace) so it can be used as the bundle readiness signal.

### 1.4 Strict vs unverified reading

Two supported read modes exist:

- `load_bundle()` (strict): resolves via `LATEST`, refuses `in_progress`, requires `artifact_index.json`, and verifies digests for indexed artifacts.
- `open_bundle_unverified()` (debug): loads whatever is present and reports `missing` / `digest_mismatches`, but never implies completeness or promotability.

### 1.5 Path-witness IR (`path_witnesses.json`)

`path_witnesses.json` is a derived, run-scoped bundle artifact that records:

- `requested_path` (what the probe asked for),
- `observed_path` (kernel-reported FD spelling via `F_GETPATH`, when available),
- `observed_path_nofirmlink` (alternate FD spelling via `F_GETPATH_NOFIRMLINK`, when available),
- and `normalized_path` (a conservative join key derived from the fields above).

This IR exists so VFS canonicalization work can be expressed as stable inputs/outputs without embedding ad-hoc stderr parsing in experiments.

## 2) Promotion packet contract

### 2.1 Schema and intent

Promotion packets are the **only supported runtime evidence interface** for mapping promotion and downstream consumers. A promotion packet is a JSON object whose fields are repo-relative pointers to bundle artifacts plus a `promotability` block.

Current schema:

- `schema_version: runtime-tools.promotion_packet.v0.2`
- `run_manifest`, `expected_matrix`, `runtime_results`, `runtime_events`, `baseline_results`, `oracle_results`, `mismatch_packets`, `summary`
- optional `path_witnesses`
- optional `impact_map`
- `promotability`:
  - `promotable_decision_stage: bool`
  - `reasons: [ ... ]` (enumerated)
  - `gating_inputs` (the authoritative inputs used to decide promotability)

### 2.2 Promotability rules (decision-stage)

Decision-stage promotion is allowed only when:

- the run manifest indicates `channel=launchd_clean`, and
- apply-preflight exists and reports `apply_ok=true` and `sandbox_check_self.sandboxed != true`, and
- strict bundle integrity checks pass, and
- decision-stage artifacts are present (`runtime_results.json`, `runtime_events.normalized.json`, `expected_matrix.json`)

When these are not met, the packet still exists but must explicitly say it is not promotable via the `promotability` block.

Strict emission mode:

- `emit-promotion --require-promotable` (or `require_promotable=True`) fails unless decision-stage promotable.

## 3) Locking + concurrency

`run_plan()` may run under a bundle-root lock file:

- lock file: `out/.runtime.lock`
- lock modes: `fail` (fail fast) or `wait` (bounded by timeout)

The lock protects:

- creation of `out/<run_id>/...`
- the commit sequence (writing `artifact_index.json`)
- updating `out/LATEST`

## 4) Repair tooling (`reindex-bundle`)

`reindex-bundle` is the operational tool for stale indices:

- `--strict`: verify digests match the current index (fail on mismatch)
- `--repair`: recompute digests/sizes/schema_versions for present artifacts, rewrite the index, and write `repair_log.json`

Repair is explicit and leaves an audit trail. It does not attempt to invent missing artifacts.

## 5) Legacy compatibility and non-goals

- Matrix-based commands exist for legacy runtime workflows (cut/story/golden). They are not the contract boundary for new runtime evidence.
- Mapping generators remain outside runtime; `runtime` standardizes *inputs* via promotion packets.
- The deprecated `sandbox-exec` mechanism is not used for stable runtime evidence production; clean decision-stage runs rely on the in-process apply path and on channel gating (`launchd_clean`).
