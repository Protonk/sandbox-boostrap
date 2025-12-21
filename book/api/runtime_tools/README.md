# runtime_tools

Unified runtime tooling for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). This package merges the runtime observation/normalization helpers, mapping builders, projections, and the runtime harness runner/generator into one documented surface. It replaces `book/api/runtime` and `book/api/runtime_harness`.

- **CLI:** `python -m book.api.runtime_tools <generate|run> ...`
- **Python (preferred):** import submodules from `book.api.runtime_tools` (`observations`, `runtime_contract`, `mapping_builders`, `runtime_story`, `derived_views`, `runtime_pipeline`, `harness_runner`, `harness_generate`).
- **Native markers:** C/Swift helpers live under `book/api/runtime_tools/native/`.

See `book/api/README.md` for higher-level routing and deprecation notes.

## CLI

Runtime harness commands (same behavior as the former runtime_harness CLI):

```sh
# Generate golden decodes/expectations/traces from runtime-checks outputs.
python -m book.api.runtime_tools generate \
  --matrix book/experiments/runtime-checks/out/expected_matrix.json \
  --runtime-results book/experiments/runtime-checks/out/runtime_results.json

# Run runtime probes for a matrix (writes runtime_results.json).
python -m book.api.runtime_tools run \
  --matrix book/profiles/golden-triple/expected_matrix.json \
  --out book/profiles/golden-triple/
```

## Routing (Python)

Pick the smallest tool for the job:

- **observations:** canonical runtime observation schema + normalization helpers.
  - `RuntimeObservation`, `WORLD_ID`, `normalize_from_paths`, `write_normalized_events`.
- **runtime_contract:** versioned tool-marker parsing and runtime_result schema guards.
- **mapping_builders:** build runtime mappings (traces, scenarios, ops, indexes, manifest).
- **runtime_story:** join op mappings + scenario summaries + vocab into a runtime story; emit legacy `runtime_signatures`/coverage views.
- **derived_views:** derived projections that do not change failure_stage/failure_kind (e.g., callout vs syscall comparison).
- **runtime_pipeline:** higher-level helpers (generate/publish runtime cuts, promote staged artifacts).
- **harness_runner:** run an expected_matrix using the standard runtime probes and shims.
- **harness_generate:** compile/decode golden profiles and normalize runtime-checks outputs.

Examples:

```py
from book.api.runtime_tools import observations, mapping_builders

observations_list = observations.normalize_from_paths(
    "book/profiles/golden-triple/expected_matrix.json",
    "book/profiles/golden-triple/runtime_results.json",
)
index, _ = mapping_builders.write_per_scenario_traces(
    observations_list,
    "book/graph/mappings/runtime/traces",
)
```

```py
from book.api.runtime_tools import runtime_pipeline

paths = runtime_pipeline.generate_runtime_cut(
    "book/experiments/runtime-checks/out/expected_matrix.json",
    "book/experiments/runtime-checks/out/runtime_results.json",
    "/tmp/runtime_cut",
)
print(paths["manifest"])
```

```py
from book.api.runtime_tools import derived_views

comparison = derived_views.callout_vs_syscall_comparison(observations_list)
print(comparison["summary"])
```

## Native tool markers

Shared JSONL marker helpers for runtime tooling live here:

- `book/api/runtime_tools/native/tool_markers.h`
- `book/api/runtime_tools/native/ToolMarkers.swift`
- `book/api/runtime_tools/native/seatbelt_callout_shim.c`
- `book/api/runtime_tools/native/seatbelt_callout_shim.h`

These emit versioned JSONL markers to stderr that are parsed by
`runtime_contract` and stripped out of canonical normalized stderr. Use them in
runtime probes and wrappers instead of ad-hoc stderr parsing.

## Preflight and apply-gate guardrails

The harness runner uses `book/tools/preflight` by default to avoid known
apply-gate signatures on this host. Controls:

- Disable globally: `SANDBOX_LORE_PREFLIGHT=0`
- Force apply even if preflight flags a signature: `SANDBOX_LORE_PREFLIGHT_FORCE=1`
- Per-profile override in `expected_matrix.json`: `"preflight": {"mode": "off"|"force"|"enforce"}`

When preflight blocks a profile, the runtime result is marked `blocked` with
`failure_stage: "preflight"`; this is evidence of a known apply-gate signature,
not policy semantics.
