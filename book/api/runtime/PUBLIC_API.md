# `runtime` public API (Sonoma 14.4.1 baseline)

This document defines the **supported, stable** public interface for `book.api.runtime`.

Scope:
- Host baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Purpose: produce and consume **tier-disciplined runtime evidence bundles** and **promotion packets** under one contract (clean-channel gating, lane separation, artifact indexing).

Non-goals:
- This is not a mapping generator spec. Mapping promotion lives under `book/graph/mappings/runtime/` and consumes promotion packets.
- This does not define sandbox semantics; it defines *evidence plumbing* (bundle integrity, promotability gates, and lane boundaries).

## Supported import surface

The only supported import surface for callers is:

- `import book.api.runtime as rt`

Callers should treat **only** the symbols exported in `rt.__all__` as stable. Submodules under `book/api/runtime/` exist, but are **internal/legacy** unless explicitly exported.

## Stable library endpoints

### Channels

- `ChannelSpec`, `ChannelName`, `LockMode`

### Plan and registry

- `load_plan(plan_path)`
- `list_plans()`
- `plan_digest(plan_doc)`
- `lint_plan(plan_path)`
- `list_registries()`
- `list_probes(registry_id)`
- `list_profiles(registry_id)`
- `resolve_probe(registry_id, probe_id)`
- `resolve_profile(registry_id, profile_id)`
- `lint_registry(registry_id)`

### Plan templates

- `list_plan_templates()`
- `load_plan_template(template_id)`
- `build_plan_from_template(template_id, out_root, *, overwrite=False, write_expected_matrix=True) -> PlanBuildResult`

### Runtime links

- `load_runtime_links(path=None) -> dict`
- `list_linked_profiles(links_doc) -> list[str]`
- `list_linked_expectations(links_doc) -> list[str]`
- `resolve_profile_link(links_doc, profile_id) -> dict | None`
- `resolve_expectation_link(links_doc, expectation_id) -> dict | None`

### Op summary helpers

- `build_op_runtime_summary(observations, *, world_id=None, inputs=None, input_hashes=None, source_jobs=None, notes=None) -> dict`
- `summarize_ops_from_bundle(bundle_root, *, out_path=None, strict=True) -> dict`
- `summarize_ops_from_packet(packet_path, *, out_path=None, require_promotable=True) -> dict`
- `write_op_runtime_summary(summary_doc, out_path) -> Path`

### Execution and bundle lifecycle

- `run_plan(plan_path, out_root, *, channel, only_profiles=None, only_scenarios=None, dry_run=False) -> RunBundle`
- `load_bundle(out_root) -> RunBundle` (strict)
- `open_bundle_unverified(out_root) -> RunBundle` (debug; never promotable)
- `validate_bundle(out_root) -> ValidationResult`
- `reindex_bundle(out_root, *, repair=False) -> dict`
- `runtime_status() -> dict`

### Promotion packets (contract boundary to mappings/consumers)

- `emit_promotion_packet(bundle_root, out_path, *, require_promotable=False) -> dict`

Promotion packets are the canonical, reviewable “runtime evidence interface” for:
- mapping promotion (`book/graph/mappings/runtime/promote_from_packets.py`)
- runtime consumers (e.g. `book/experiments/field2-atlas/atlas_runtime.py`)

### Inventory

- `build_runtime_inventory(repo_root, out_path) -> dict`

## Stable CLI surface

The canonical CLI entrypoint is:

- `python -m book.api.runtime ...`

Supported commands (stable flags and output schemas):
- `run --plan ... --channel launchd_clean|direct [--dry] [--only-scenario ...] [--only-profile ...]`
- `status`
- `validate-bundle --bundle ...`
- `emit-promotion --bundle ... --out ... [--require-promotable]`
- `reindex-bundle --bundle ... --strict|--repair`
- `list-registries`, `list-probes`, `list-profiles`
- `describe-probe`, `describe-profile`
- `registry-lint`, `plan-lint`
- `list-templates`, `plan-build`
- `summarize-ops`

Anything else exposed by the CLI (legacy matrix helpers) is treated as **compat** and may change as plan-data becomes the only supported runtime execution interface.

## Compatibility promises

- **Bundles are run-scoped**: `out/<run_id>/...`.
- **Commit barrier**: `artifact_index.json` is the bundle “commit” marker; `out/LATEST` updates only after commit.
- **Lanes stay separated**:
  - `baseline` (no policy apply)
  - `scenario` (decision-stage evidence under applied policy)
  - `oracle` (decision oracle lane; never upgraded to syscall-observed claims)
- **Promotability is derived, not caller-controlled**:
  - strict promotion packet emission (`require_promotable=True`) refuses non-promotable bundles
  - non-strict emission includes an explicit `promotability` block so ambiguity is bounded

For the full reference contract, see `book/api/runtime/SPEC.md`.
