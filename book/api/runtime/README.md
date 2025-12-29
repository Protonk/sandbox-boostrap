# runtime

Unified runtime evidence tooling for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`).

For agents, the two core ideas are:
- **Plan-data in** (`book/experiments/**/plan.json` + registry JSON), no experiment imports required.
- **Promotion packets out** (`promotion_packet.json`), which become the only supported input to mapping promotion and runtime consumers.

Reference contract/spec: `book/api/runtime/SPEC.md`.
Public API surface: `book/api/runtime/PUBLIC_API.md`.

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
