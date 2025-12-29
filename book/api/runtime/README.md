# runtime

Unified runtime evidence tooling for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

For agents, the two core ideas are:
- **Plan-data in** (`book/experiments/**/plan.json` + registry JSON), no experiment imports required.
- **Promotion packets out** (`promotion_packet.json`), which become the only supported input to mapping promotion and runtime consumers.

Reference contract/spec: `book/api/runtime/SPEC.md`.

## Public API (stable surface)

This section defines the supported, stable public interface for `book.api.runtime`.

Scope:
- Host baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Purpose: produce and consume tier-disciplined runtime evidence bundles and promotion packets under one contract (clean-channel gating, lane separation, artifact indexing).

Non-goals:
- This is not a mapping generator spec. Mapping promotion lives under `book/graph/mappings/runtime/` and consumes promotion packets.
- This does not define sandbox semantics; it defines evidence plumbing (bundle integrity, promotability gates, and lane boundaries).

### Supported import surface

The only supported import surface for callers is:

```python
import book.api.runtime as rt
```

Callers should treat **only** the symbols exported in `rt.__all__` as stable. Submodules under `book/api/runtime/` exist, but are internal/legacy unless explicitly exported.

### Stable library endpoints

Channels:
- `ChannelSpec`, `ChannelName`, `LockMode`

Plan and registry:
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

Plan templates:
- `list_plan_templates()`
- `load_plan_template(template_id)`
- `build_plan_from_template(template_id, out_root, *, overwrite=False, write_expected_matrix=True) -> PlanBuildResult`

Runtime links:
- `load_runtime_links(path=None) -> dict`
- `list_linked_profiles(links_doc) -> list[str]`
- `list_linked_expectations(links_doc) -> list[str]`
- `resolve_profile_link(links_doc, profile_id) -> dict | None`
- `resolve_expectation_link(links_doc, expectation_id) -> dict | None`

Op summary helpers:
- `build_op_runtime_summary(observations, *, world_id=None, inputs=None, input_hashes=None, source_jobs=None, notes=None) -> dict`
- `summarize_ops_from_bundle(bundle_root, *, out_path=None, strict=True) -> dict`
- `summarize_ops_from_packet(packet_path, *, out_path=None, require_promotable=True) -> dict`
- `write_op_runtime_summary(summary_doc, out_path) -> Path`

Execution and bundle lifecycle:
- `run_plan(plan_path, out_root, *, channel, only_profiles=None, only_scenarios=None, dry_run=False) -> RunBundle`
- `load_bundle(out_root) -> RunBundle` (strict)
- `open_bundle_unverified(out_root) -> RunBundle` (debug; never promotable)
- `validate_bundle(out_root) -> ValidationResult`
- `reindex_bundle(out_root, *, repair=False) -> dict`
- `runtime_status() -> dict`

Promotion packets (contract boundary to mappings/consumers):
- `emit_promotion_packet(bundle_root, out_path, *, require_promotable=False) -> dict`

Promotion packets are the canonical, reviewable runtime evidence interface for:
- mapping promotion (`book/graph/mappings/runtime/promote_from_packets.py`)
- runtime consumers (for example `book/experiments/field2-atlas/atlas_runtime.py`)

Inventory:
- `build_runtime_inventory(repo_root, out_path) -> dict`

### Stable CLI surface

The canonical CLI entrypoint is:

```sh
python -m book.api.runtime ...
```

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

Anything else exposed by the CLI (legacy matrix helpers) is treated as compat and may change as plan-data becomes the only supported runtime execution interface.

### Compatibility promises

- Bundles are run-scoped: `out/<run_id>/...`.
- Commit barrier: `artifact_index.json` is the bundle commit marker; `out/LATEST` updates only after commit.
- Lanes stay separated:
  - `baseline` (no policy apply)
  - `scenario` (decision-stage evidence under applied policy)
  - `oracle` (decision oracle lane; never upgraded to syscall-observed claims)
- Promotability is derived, not caller-controlled:
  - strict promotion packet emission (`require_promotable=True`) refuses non-promotable bundles
  - non-strict emission includes an explicit `promotability` block so ambiguity is bounded

## Runtime evidence contract (short form)

Canonical artifacts and how they interlock:
- **Bundles** (run-scoped): `out/<run_id>/expected_matrix.json`, `runtime_results.json`, `runtime_events.normalized.json`, plus lane-specific artifacts (baseline, oracle). Strictly gated by `artifact_index.json`.
- **Promotion packets**: the only supported interface for runtime evidence promotion and downstream consumers (`promotion_packet.json`).
- **Mapped outputs** (tier: mapped, not bedrock): `book/graph/mappings/runtime/runtime_signatures.json`, `book/graph/mappings/runtime/op_runtime_summary.json`, `book/graph/mappings/runtime/runtime_links.json` (cross-links runtime to ops vocab, system profile digests, and oracle lanes).

Keep oracle-lane data (`runtime_callout_oracle.json`) segregated from decision-stage evidence; it is a side-channel, not a syscall witness.

## Common CLI commands (agent-friendly)

```sh
# 0) Generate plan/registry data from templates (host-neutral).
python -m book.api.runtime list-templates
python -m book.api.runtime plan-build \
  --template vfs-canonicalization \
  --out book/experiments/vfs-canonicalization \
  --overwrite

# 1) Discover and lint plan-data (no execution).
python -m book.api.runtime list-plans
python -m book.api.runtime plan-lint --plan book/experiments/hardened-runtime/plan.json
python -m book.api.runtime registry-lint --registry hardened-runtime

# 2) Run via the clean channel (decision-stage lane).
python -m book.api.runtime run \
  --plan book/experiments/hardened-runtime/plan.json \
  --channel launchd_clean \
  --out book/experiments/hardened-runtime/out

# 3) Validate and emit a promotion packet.
python -m book.api.runtime validate-bundle --bundle book/experiments/hardened-runtime/out
python -m book.api.runtime emit-promotion \
  --bundle book/experiments/hardened-runtime/out \
  --out book/experiments/hardened-runtime/out/promotion_packet.json \
  --require-promotable

# 3b) Summarize op-level runtime results (bundle or promotion packet).
python -m book.api.runtime summarize-ops \
  --bundle book/experiments/runtime-adversarial/out \
  --out book/graph/mappings/runtime/op_runtime_summary.json

# 4) Promote into runtime mappings (mapping layer stays outside runtime).
python book/graph/mappings/runtime/promote_from_packets.py \
  --packets book/experiments/hardened-runtime/out/promotion_packet.json \
  --out book/graph/mappings/runtime
```

## Concepts (minimal)

**Lanes**
- `scenario`: decision-stage run under the applied profile; produces `runtime_results.json` and `runtime_events.normalized.json`.
- `baseline`: run the same probe inputs without applying a policy; used for attribution (ambient vs profile-shaped outcomes).
- `oracle`: separate, explicitly weaker lane produced from callout/oracle views; never implies syscall observation.

**Clean channel gating**
- Decision-stage evidence is only treated as promotable when the run manifest indicates `channel=launchd_clean` and apply-preflight succeeded.
- `emit-promotion --require-promotable` fails fast if the bundle cannot be treated as decision-stage promotable.

**Bundle layout**
- Plan runs write run-scoped bundles: `out/<run_id>/...`
- `out/LATEST` points to the most recent *committed* run directory.
- `artifact_index.json` is the commit barrier; strict bundle loads verify digests and refuse `run_status.state == in_progress`.

## When you need repair or introspection

```sh
python -m book.api.runtime status
python -m book.api.runtime validate-bundle --bundle book/experiments/hardened-runtime/out
python -m book.api.runtime reindex-bundle --bundle book/experiments/hardened-runtime/out --strict
python -m book.api.runtime reindex-bundle --bundle book/experiments/hardened-runtime/out --repair
```

## Notes

- Matrix-based commands (`normalize`, `cut`, `story`, `golden`, `run-all`) remain for legacy workflows. For new runtime evidence, prefer plan-based runs + promotion packets.
- Templates for new probe families/plans live under `book/api/runtime/templates/`.
