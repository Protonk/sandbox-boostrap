# API tooling (Sonoma baseline)

This directory collects host-specific helpers for working with Seatbelt on the fixed baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. Use the sections below as a router; each module has a focused role, a short definition, and a minimal usage example. If a module has its own README, follow that link for deeper guidance.

### profile_tools

Definition: Unified surface for SBPL compilation, compiled-blob decoding/inspection, op-table summaries, and structural oracles (replaces `sbpl_compile`, `inspect_profile`, `op_table`, and the former standalone `decoder`/`sbpl_oracle` modules).

Role: Provide a single Python/CLI entrypoint for compiling SBPL, decoding/inspecting compiled blobs, summarizing op-table structure, and running structural oracles.

Example:
```sh
python -m book.api.profile_tools compile book/examples/sb/sample.sb --out /tmp/sample.sb.bin
python -m book.api.profile_tools decode dump /tmp/sample.sb.bin --summary
python -m book.api.profile_tools inspect /tmp/sample.sb.bin --out /tmp/summary.json
python -m book.api.profile_tools op-table book/experiments/op-table-operation/sb/v1_read.sb --compile --op-count 196
python -m book.api.profile_tools oracle network-matrix \
  --manifest book/experiments/libsandbox-encoder/sb/network_matrix/MANIFEST.json \
  --blob-dir book/experiments/libsandbox-encoder/out/network_matrix \
  --out /tmp/network_oracle.json
```

Legacy packages (`book.api.sbpl_compile`, `book.api.inspect_profile`, `book.api.op_table`) have been removed; prefer the unified package above.

### file_probe

Definition: Minimal JSON-emitting read/write probe binary (under `book/api/runtime_tools/native/file_probe/`).

Role: Provide a deterministic target for runtime allow/deny checks once a profile is applied.

Example:
```sh
gcc book/api/runtime_tools/native/file_probe/file_probe.c -o /tmp/file_probe
/tmp/file_probe read /etc/hosts
```

### ghidra

Definition: Seatbelt-focused Ghidra scaffold and CLI.

Role: Provide connectors for reverse-engineering tasks (kernel/op-table symbol work) and manage the runtime workspace under `dumps/ghidra/`.

Example:
```sh
python -m book.api.ghidra.cli --help
```
See `book/api/ghidra/README.md` for setup and workflow.

### carton

Definition: Public query surface for CARTON, the frozen IR/mapping set rooted at `book/api/carton/CARTON.json`.

Role: Answer concept-shaped questions about operations, filters, system profiles/profile layers, and runtime signatures without touching raw experiment outputs.

Example:
```sh
python - <<'PY'
from book.api.carton import carton_query
print(carton_query.operation_story("file-read*"))
PY
```
See `book/api/carton/README.md`, `AGENTS.md`, and `API.md` for design, routing, and function contracts.

### runtime_tools

Definition: Unified runtime tooling (observations, mappings, projections, and harness runner/golden generator).

Role: Normalize harness output into canonical runtime observations, build runtime mappings/stories, and run expectation-driven probes to emit `runtime_results.json`.

Example:
```sh
python -m book.api.runtime_tools golden --matrix book/experiments/runtime-checks/out/expected_matrix.json
python -m book.api.runtime_tools run --matrix book/profiles/golden-triple/expected_matrix.json --out book/profiles/golden-triple/
python -m book.api.runtime_tools cut --matrix book/experiments/runtime-checks/out/expected_matrix.json --out /tmp/runtime_cut
```

Preflight (apply-gate avoidance):
- By default, the runtime harness runner runs `book/tools/preflight` for SBPL (`.sb`) and compiled SBPL blobs (`.sb.bin`); on a known apply-gate signature it emits `failure_stage:"preflight"` without attempting apply.
- Override knobs:
  - Disable globally: `SANDBOX_LORE_PREFLIGHT=0`
  - Force apply even if preflight flags a signature: `SANDBOX_LORE_PREFLIGHT_FORCE=1`
  - Per-profile override in `expected_matrix.json`: `"preflight": {"mode": "off"|"force"|"enforce"}`

## CARTON conversion assessment

- **op_table**: could gain a CARTON-backed query layer if op-table fingerprints/alignments are ever promoted to CARTON mappings; today it is generator/inspection tooling (see `book.api.profile_tools.op_table`), not CARTON IR.
- **runtime_tools**: the harness + mapping outputs could be query-able if golden traces/expectations become CARTON mappings with a defined concept; currently generation-only.
- **Others (regex_tools, runtime_tools/native/file_probe, ghidra)**: generation/inspection/harness tools, not CARTON concepts; poor fits for the CARTON query surface in their current form.
