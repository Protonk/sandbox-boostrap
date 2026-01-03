# API tooling (Sonoma baseline)

This directory collects host-specific helpers for working with Seatbelt on the fixed baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. Use the sections below as a router; each module has a focused role, a short definition, and a minimal usage example. If a module has its own README, follow that link for deeper guidance.

### profile

Definition: Unified surface for SBPL compilation, compiled-blob decoding/inspection, op-table summaries, and structural oracles (replaces `sbpl_compile`, `inspect_profile`, `op_table`, and the former standalone `decoder`/`sbpl_oracle` modules).

Role: Provide a single Python/CLI entrypoint for compiling SBPL, decoding/inspecting compiled blobs, summarizing op-table structure, and running structural oracles.

Example:
```sh
python -m book.api.profile compile book/tools/sbpl/corpus/baseline/sample.sb --out /tmp/sample.sb.bin
python -m book.api.profile decode dump /tmp/sample.sb.bin --summary
python -m book.api.profile inspect /tmp/sample.sb.bin --out /tmp/summary.json
python -m book.api.profile op-table book/evidence/experiments/profile-pipeline/op-table-operation/sb/v1_read.sb --compile --op-count 196
python3 book/tools/sbpl/oracles/network_matrix.py \
  --manifest book/evidence/experiments/field2-final-final/libsandbox-encoder/sb/network_matrix/MANIFEST.json \
  --blob-dir book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix \
  --out /tmp/network_oracle.json
```

Legacy packages (`book.api.sbpl_compile`, `book.api.inspect_profile`, `book.api.op_table`) have been removed; prefer the unified package above.

### file_probe

Definition: Minimal JSON-emitting read/write probe binary (under `book/api/runtime/native/file_probe/`).

Role: Provide a deterministic target for runtime allow/deny checks once a profile is applied.

Example:
```sh
gcc book/api/runtime/native/file_probe/file_probe.c -o /tmp/file_probe
/tmp/file_probe read /etc/hosts
```

### ghidra

Definition: Seatbelt-focused Ghidra scaffold and CLI.

Role: Provide connectors for reverse-engineering tasks (kernel/op-table symbol work) and manage the runtime workspace under `book/dumps/ghidra/`.

Example:
```sh
python -m book.api.ghidra.cli --help
```
See `book/api/ghidra/README.md` for setup and workflow.

### carton

Definition: Integration fixer bundle that freezes host-bound mappings into canonical relationships, views, and contracts.

Role: Use the CARTON CLI to run fixers, rebuild the bundle manifest, and verify drift. The bundle outputs under `book/integration/carton/bundle/` are the authoritative relationships/views/contracts (manifest-pinned) surfaces; there is no CARTON query API in `book/api/`.

Example:
```sh
python -m book.integration.carton build
python -m book.integration.carton diff
python -m book.integration.carton check
```

### runtime

Definition: Unified runtime tooling (observations, mappings, projections, plan-based execution, and harness runner/golden generator).

Role: Normalize harness output into canonical runtime observations, build runtime mappings/stories, and run plan-based probes to emit promotable runtime bundles (`run_manifest.json`, `runtime_results.json`, `artifact_index.json`).

Example:
```sh
python -m book.api.runtime run \
  --plan book/evidence/experiments/runtime-final-final/suites/hardened-runtime/plan.json \
  --channel launchd_clean \
  --out book/evidence/experiments/runtime-final-final/suites/hardened-runtime/out

python -m book.api.runtime status
python -m book.api.runtime list-plans
python -m book.api.runtime plan-lint --plan book/evidence/experiments/runtime-final-final/suites/hardened-runtime/plan.json
python -m book.api.runtime registry-lint --registry hardened-runtime

python -m book.api.runtime golden \
  --matrix book/evidence/experiments/runtime-final-final/suites/runtime-checks/out/expected_matrix.json
```

Preflight (apply-gate avoidance):
- By default, the runtime harness runner runs `book/tools/preflight` for SBPL (`.sb`) and compiled SBPL blobs (`.sb.bin`); on a known apply-gate signature it emits `failure_stage:"preflight"` without attempting apply.
- Override knobs:
  - Disable globally: `SANDBOX_LORE_PREFLIGHT=0`
  - Force apply even if preflight flags a signature: `SANDBOX_LORE_PREFLIGHT_FORCE=1`
  - Per-profile override in `expected_matrix.json`: `"preflight": {"mode": "off"|"force"|"enforce"}`

### witness

Definition: Host-bound Python surface for PolicyWitness.app (`policy-witness` CLI + `sandbox-log-observer`).

Role: Run probes across profiles, capture observer deny evidence, compare baselines, and expose lifecycle/enforcement detail without binding tooling to experiment paths.

Example:
```sh
python - <<'PY'
from pathlib import Path

from book.api.witness import client, outputs

result = client.run_probe(
    profile_id="minimal",
    probe_id="capabilities_snapshot",
    probe_args=[],
    plan_id="witness:sample",
    row_id="capabilities_snapshot",
    output=outputs.OutputSpec(
        bundle_root=Path("book/api/witness/out"),
        bundle_run_id="witness-sample",
    ),
)
print(result.stdout_json or {})
PY
```

Bundle outputs land under `book/api/witness/out/witness-sample/` with
`artifact_index.json` as the commit barrier.

See `book/api/witness/README.md` (Contract section) for API usage and contract fixtures.

Frida harness (PolicyWitness XPC session + attach):
```sh
python -m book.api.witness.frida --profile-id minimal@injectable --probe-id probe_catalog --script book/api/frida/hooks/smoke.js
```

### frida

Definition: Frida runners for spawn/attach, plus a curated hook catalog.

Role: Provide a shared attach/spawn harness for experiments that need in-process instrumentation.

Example:
```sh
python -m book.api.frida.cli run --attach-pid 12345 --script book/api/frida/hooks/smoke.js
```

## CARTON scope notes

- **op_table**: generator/inspection tooling today (see `book.api.profile.op_table`); add to `book/integration/carton/spec/carton_spec.json` only when the mapping shape is stable enough to freeze.
- **runtime**: harness outputs and runtime mappings can be promoted into CARTON by adding stable artifacts to the spec; keep generation-only until the relationship surface is stable.
- **Others (regex_tools, runtime/native/file_probe, ghidra)**: generation/inspection/harness tools; keep outside CARTON unless a frozen contract surface is needed.
