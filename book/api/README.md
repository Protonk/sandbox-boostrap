# API tooling (Sonoma baseline)

This directory collects host-specific helpers for working with Seatbelt on the fixed baseline in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`. Use the sections below as a router; each module has a focused role, a short definition, and a minimal usage example. If a module has its own README, follow that link for deeper guidance.

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

### sbpl_compile

Definition: Thin wrapper over private `libsandbox` compile entry points.

Role: Compile SBPL text into a compiled blob for use in decoding or experiments.

Example:
```sh
python -m book.api.sbpl_compile.cli book/examples/sb/sample.sb --out /tmp/sample.sb.bin
```

### inspect_profile

Definition: Quick, read-only summary of a compiled blob.

Role: Produce a structural snapshot (format variant, op_count, section sizes, op entries, tag stats, literal runs) before deeper analysis.

Example:
```sh
python -m book.api.inspect_profile.cli /tmp/sample.sb.bin --json /tmp/summary.json
```

### op_table

Definition: Op-table–centric parser and analyzer.

Role: Parse `(allow ...)` ops and filters from SBPL, compute op-table entries and per-entry signatures, and optionally align them to the vocab (`ops.json`, `filters.json`).

Example:
```sh
python -m book.api.op_table.cli book/experiments/op-table-operation/sb/v1_read.sb \
  --compile --op-count 196 \
  --vocab book/graph/mappings/vocab/ops.json \
  --filters book/graph/mappings/vocab/filters.json \
  --json /tmp/op_summary.json
```

### regex_tools

Definition: Helpers for legacy AppleMatch regex blobs from early decision-tree profiles.

Role: Extract compiled `.re` blobs and convert them to Graphviz for inspection; modern graph-based profiles should use `decoder` instead.

Example:
```sh
python -m book.api.regex_tools.extract_legacy legacy.sb.bin out/
python -m book.api.regex_tools.re_to_dot out/legacy.sb.bin.000.re -o out/re.dot
```

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

### runtime_golden

Definition: Helpers for the runtime-checks “golden” profile set.

Role: Compile and decode the golden runtime profiles, summarize decodes, and normalize runtime_results.json into mapping-friendly traces.

Example:
```sh
python -m book.api.runtime_golden.generate
```

### golden_runner

Definition: Harness for running the “golden triple” runtime probes.

Role: Execute expectation-driven probes described in `expected_matrix.json` and emit `runtime_results.json` aligned with the provisional schema.

Example:
```sh
python -m book.api.golden_runner.cli --matrix book/profiles/golden-triple/expected_matrix.json --out book/profiles/golden-triple/
```

## CARTON conversion assessment

- **op_table**: could gain a CARTON-backed query layer if op-table fingerprints/alignments are ever promoted to CARTON mappings; today it is generator/inspection tooling, not CARTON IR.
- **runtime_golden**: could be query-able if golden traces/expectations become CARTON mappings with a defined concept; currently generation-only.
- **Others (decoder, sbpl_compile, inspect_profile, regex_tools, SBPL-wrapper, file_probe, golden_runner, ghidra)**: generation/inspection/harness tools, not CARTON concepts; poor fits for the CARTON query surface in their current form.
