# runtime

Unified runtime evidence tooling for the Sonoma baseline
(`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

This is the **only supported path** for plan-based runtime experiments. It
turns plan/registry data into committed bundles and promotion packets with a
single, explicit evidence contract.

Reference contract/spec: `book/api/runtime/SPEC.md`.

## Contract at a glance

- **Inputs are data-only**: `plan.json` + registry JSON (no experiment imports).
- **Execution is centralized**: `python -m book.api.runtime run --plan ... --channel ...`.
- **Outputs are authoritative bundles**: `out/<run_id>/...` with `artifact_index.json`
  as the commit barrier; `out/LATEST` updates only after commit.
- **Promotion packets are the boundary**: `promotion_packet.json` is the only
  supported interface for mappings and downstream consumers.
- **Lanes stay separated**: `scenario` (decision-stage), `baseline`, `oracle`.
- **Promotability is gated**: clean-channel runs (`launchd_clean`) + successful
  apply preflight are required for decision-stage promotion.

## Canonical workflow (do this, not wrappers)

```sh
# 1) Generate or refresh plan/registry data from templates.
python -m book.api.runtime list-templates
python -m book.api.runtime plan-build \
  --template hardened-runtime \
  --out book/evidence/experiments/runtime-final-final/suites/hardened-runtime \
  --overwrite
# Use --write-expected-matrix only when you need a static snapshot; runtime runs
# always emit run-scoped expected_matrix.json bundles.

# 2) Lint the data contract (no execution).
python -m book.api.runtime plan-lint --plan book/evidence/experiments/runtime-final-final/suites/hardened-runtime/plan.json
python -m book.api.runtime registry-lint --registry hardened-runtime

# 3) Run via the clean channel (decision-stage lane).
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/hardened-runtime/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out

# 4) Validate and emit a promotion packet.
python -m book.api.runtime validate-bundle --bundle book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out
python -m book.api.runtime emit-promotion \
  --bundle book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out \
  --out book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out/promotion_packet.json \
  --require-promotable

# 5) Promote into runtime mappings (outside runtime; consumes packets).
python book/graph/mappings/runtime/promote_from_packets.py \
  --packets book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out/promotion_packet.json
```
Outputs land under `book/evidence/graph/mappings/runtime/` and `book/evidence/graph/mappings/runtime_cuts/`.

Optional summary step:

```sh
python -m book.api.runtime summarize-ops \
  --bundle book/evidence/experiments/runtime-final-final/suites/runtime-adversarial/out \
  --out book/evidence/graph/mappings/runtime/op_runtime_summary.json
```

## Bundle and promotion artifacts

**Bundle (authoritative, run-scoped):**
- `out/<run_id>/expected_matrix.json`
- `out/<run_id>/runtime_results.json`
- `out/<run_id>/runtime_events.normalized.json`
- `out/<run_id>/artifact_index.json` (commit barrier)
- `out/<run_id>/run_manifest.json`, `run_status.json`, lane-specific outputs

**Promotion packet (contract boundary):**
- `out/promotion_packet.json` points to a committed bundle and carries a
  promotability decision.

Derived summaries are allowed for convenience, but they must include the bundle
metadata (`run_id`, `artifact_index` digest) and must never be treated as a
second source of truth.

## Evidence discipline (runtime-specific)

**Lanes**
- `scenario`: decision-stage run under applied policy.
- `baseline`: same probes without applying policy (attribution control).
- `oracle`: side-channel / callout lane; never used as syscall evidence.

**Clean-channel gating**
- Decision-stage evidence is promotable only when `run_manifest.channel ==
  "launchd_clean"` and apply preflight succeeded.
- `emit-promotion --require-promotable` refuses bundles that do not meet this
  gate.

**Granular attribution signals**
- Normalized runtime events include `policy_layers` and `intended_op_witnessed`;
  treat `intended_op_witnessed=false` as “not observed,” not an allow/deny.
- `file_confounder` tags file-operation denials with errno-based hints
  (`EPERM` → App Sandbox/MAC, `EACCES` → UNIX/ACL) plus policy-layer attribution.
- `service_confounder` tags `mach-lookup` outcomes as missing-service when
  baseline and scenario probe details agree (helps avoid misattributing
  missing services as policy denials).
- `resource_hygiene` carries `preopen_hints` and `preopen_detected` to flag
  harness-level pre-acquisition that can bias outcomes.
- `path_witnesses.json` includes canonicalization flags (`alias_pair`,
  `nofirmlink_differs`) so path resolution can be analyzed without re-parsing
  stderr.
- `run_status.json` may include a `launchctl_diagnostics` pointer for
  `launchd_clean` runs.
- Process probes inherit sandbox policy across fork/exec; the `inherit`
  entitlement is not the enforcement mechanism and should not be treated as a
  separate allow/deny control.
- For mach/XPC/notification probes, the harness infers a typed filter from
  `anchor_filter_map.json` when the plan omits one (and prefers
  `xpc-service-name` for `xpc_probe`).

## Optional witness observer capture

Set `SANDBOX_LORE_WITNESS_OBSERVER=1` to capture PolicyWitness
`sandbox-log-observer` output during runtime harness probe runs. Observer
reports are written under the run bundle (for example,
`out/<run_id>/observer/*.observer.json`) and attached to raw probe records for
debugging and attribution; they are not promotion inputs. The capture honors
`WITNESS_OBSERVER_MODE=disabled` if you need to suppress external observer
calls.

## Registry and plan contract

- Registry index: `book/api/runtime/plans/registry/index.json`.
- JSON Schemas: `book/api/runtime/plans/registry/schemas/`.
- Plan files do **not** embed `schema_versions`; compatibility is owned by the
  runtime service and the registry upgrade tool.

Use the contract tools:
- `registry-lint` to enforce schema + references.
- `registry-upgrade` to normalize older registries.
- `plan-lint` to enforce plan structure and forbid schema overrides.

## Public API (stable surface)

Import surface:

```python
import book.api.runtime as rt
```

Only symbols exported via `rt.__all__` are stable.

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
- `upgrade_registry(registry_id, *, out_dir=None, overwrite=False)`

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

Promotion packets:
- `emit_promotion_packet(bundle_root, out_path, *, require_promotable=False) -> dict`

Inventory:
- `build_runtime_inventory(repo_root, out_path) -> dict`

## CLI (stable surface)

Canonical entrypoint:

```sh
python -m book.api.runtime ...
```

Stable commands:
- `run --plan ... --channel launchd_clean|direct [--dry] [--only-scenario ...] [--only-profile ...]`
- `status`
- `validate-bundle --bundle ...`
- `emit-promotion --bundle ... --out ... [--require-promotable]`
- `reindex-bundle --bundle ... --strict|--repair`
- `list-registries`, `list-probes`, `list-profiles`
- `describe-probe`, `describe-profile`
- `registry-lint`, `registry-upgrade`, `plan-lint`
- `list-templates`, `plan-build`
- `summarize-ops`

Other CLI helpers (legacy matrix commands) remain compat-only and may change.

## Module layout

- `contracts/`: schemas, marker parsing, normalization helpers.
- `plans/`: plan loading, registry helpers, templates.
- `execution/`: channels, lanes, service orchestration.
- `bundles/`: bundle readers/writers, promotion packet emission.
- `analysis/`: runtime links, inventory, op summaries.
- `native/`: low-level probes and tool shims.
