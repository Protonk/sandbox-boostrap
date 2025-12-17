# API tooling (Sonoma baseline)

This directory collects host-specific helpers for working with Seatbelt on the fixed baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`. Use the sections below as a router; each module has a focused role, a short definition, and a minimal usage example. If a module has its own README, follow that link for deeper guidance.

### profile_tools

Definition: Unified surface for SBPL compilation, compiled-blob inspection, and op-table summaries (replaces `sbpl_compile`, `inspect_profile`, `op_table`).

Role: Provide a single Python/CLI entrypoint for compiling SBPL, inspecting compiled blobs, and summarizing op-table structure, with legacy modules left as shims.

Example:
```sh
python -m book.api.profile_tools.cli compile book/examples/sb/sample.sb --out /tmp/sample.sb.bin
python -m book.api.profile_tools.cli inspect /tmp/sample.sb.bin --json /tmp/summary.json
python -m book.api.profile_tools.cli op-table book/experiments/op-table-operation/sb/v1_read.sb --compile --op-count 196
```

### decoder

Definition: Structured decoder for compiled sandbox blobs.

Role: Turn a compiled profile into Python dictionaries (format variant, op_table, nodes, literal pool, tag counts) using the vocab/tag-layout mappings.

Example:
```sh
python - <<'PY'
from pathlib import Path
from book.api import decoder
blob = Path("book/examples/sb/sample.sb.bin").read_bytes()
decoded = decoder.decode_profile_dict(blob)
print(decoded["format_variant"], decoded["op_count"])
PY
```
See `book/api/decoder/README.md` for field details and CLI usage.

The legacy `sbpl_compile`, `inspect_profile`, and `op_table` modules remain as shims to `profile_tools`; prefer the unified package above.

### SBPL-wrapper

Definition: Runtime harness for applying SBPL or compiled blobs to processes.

Role: Wrap `sandbox_init` / `sandbox_apply` to drive runtime probes; on this host, `EPERM` apply gates should be treated as `blocked`.

Example:
```sh
# build the wrapper per book/api/SBPL-wrapper/README
book/api/SBPL-wrapper/wrapper --blob /tmp/sample.sb.bin -- /bin/true
```

### file_probe

Definition: Minimal JSON-emitting read/write probe binary.

Role: Provide a deterministic target for runtime allow/deny checks when paired with SBPL-wrapper.

Example:
```sh
gcc book/api/file_probe/file_probe.c -o /tmp/file_probe
/tmp/file_probe /etc/hosts
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

### sbpl_oracle

Definition: Structural SBPL↔compiled profile “oracle” helpers.

Role: Provide falsifiable, byte-level extraction of SBPL-visible argument structure from compiled blobs (no kernel semantics), backed by experiment corpora.

Example:
```sh
python -m book.api.sbpl_oracle.cli network-matrix \
  --manifest book/experiments/libsandbox-encoder/sb/network_matrix/MANIFEST.json \
  --blob-dir book/experiments/libsandbox-encoder/out/network_matrix \
  --out /tmp/network_oracle.json
```
See `book/api/sbpl_oracle/README.md` for scope and schemas.

### runtime_harness

Definition: Unified runtime harness for golden profiles (replaces `runtime_golden` + `golden_runner`).

Role: Generate golden decodes/expectations/traces and run expectation-driven probes to emit `runtime_results.json`.

Example:
```sh
python -m book.api.runtime_harness.cli generate --matrix book/experiments/runtime-checks/out/expected_matrix.json
python -m book.api.runtime_harness.cli run --matrix book/profiles/golden-triple/expected_matrix.json --out book/profiles/golden-triple/
```

## CARTON conversion assessment

- **op_table**: could gain a CARTON-backed query layer if op-table fingerprints/alignments are ever promoted to CARTON mappings; today it is generator/inspection tooling, not CARTON IR.
- **runtime_harness**: could be query-able if golden traces/expectations become CARTON mappings with a defined concept; currently generation-only.
- **Others (decoder, sbpl_compile, inspect_profile, regex_tools, SBPL-wrapper, file_probe, ghidra)**: generation/inspection/harness tools, not CARTON concepts; poor fits for the CARTON query surface in their current form.
