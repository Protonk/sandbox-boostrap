# runtime_tools

Unified runtime tooling for the Sonoma baseline (`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). This package merges normalization, mapping builders, projections, workflow helpers, and the runtime harness runner/golden generator into one documented surface. It replaces `book/api/runtime` and `book/api/runtime_harness`.

- **Plan-based execution:** run plans through the shared `run_plan`/`run` entrypoint and the launchd clean channel.
- **CLI:** `python -m book.api.runtime_tools <run|normalize|cut|story|golden|promote|mismatch|run-all|list-registries|list-probes|list-profiles|describe-probe|describe-profile|emit-promotion|validate-bundle> ...`
- **Python (preferred):** import subpackages from `book.api.runtime_tools` (`core`, `mapping`, `harness`, `workflow`, `api`).
- **Native markers:** C/Swift helpers live under `book/api/runtime_tools/native/`.

See `book/api/README.md` for higher-level routing and deprecation notes.

## CLI

Runtime harness commands (matrix-based):

```sh
# Generate golden decodes/expectations/traces from runtime-checks outputs.
python -m book.api.runtime_tools golden \
  --matrix book/experiments/runtime-checks/out/expected_matrix.json \
  --runtime-results book/experiments/runtime-checks/out/runtime_results.json

# Run runtime probes for a matrix (writes runtime_results.json).
python -m book.api.runtime_tools run \
  --matrix book/profiles/golden-triple/expected_matrix.json \
  --out book/profiles/golden-triple/

# Build a runtime cut from matrix + results.
python -m book.api.runtime_tools cut \
  --matrix book/experiments/runtime-checks/out/expected_matrix.json \
  --runtime-results book/experiments/runtime-checks/out/runtime_results.json \
  --out /tmp/runtime_cut
```

Plan-based run (recommended for experiments):

```sh
python -m book.api.runtime_tools run \
  --plan book/experiments/hardened-runtime/plan.json \
  --channel launchd_clean \
  --out book/experiments/hardened-runtime/out
```

Registry helpers:

```sh
python -m book.api.runtime_tools list-registries
python -m book.api.runtime_tools list-probes --registry hardened-runtime
python -m book.api.runtime_tools describe-profile --registry hardened-runtime --profile hardened:sysctl_read
```

Bundle validation + promotion packet:

```sh
python -m book.api.runtime_tools validate-bundle --bundle book/experiments/hardened-runtime/out
python -m book.api.runtime_tools emit-promotion \
  --bundle book/experiments/hardened-runtime/out \
  --out book/experiments/hardened-runtime/out/promotion_packet.json
```

## Routing (Python)

Pick the smallest tool for the job:

- **core.models:** canonical dataclasses + `WORLD_ID`.
- **core.normalize:** normalization helpers (`normalize_matrix_paths`, `write_matrix_observations`).
- **core.contract:** versioned tool-marker parsing and runtime_result schema guards.
- **mapping.build:** build runtime mappings (traces, scenarios, ops, indexes, manifest).
- **mapping.story:** join op mappings + scenario summaries + vocab into a runtime story; emit legacy coverage/signatures.
- **mapping.views:** derived projections that do not change failure_stage/failure_kind (e.g., callout vs syscall).
- **harness.runner:** run an expected_matrix using the standard runtime probes and shims.
- **harness.golden:** compile/decode golden profiles and normalize runtime-checks outputs.
- **workflow:** higher-level helpers (build cuts, promote staged artifacts, run profiles end-to-end).

Examples:

```py
from book.api.runtime_tools.core import normalize
from book.api.runtime_tools.mapping import build

observations = normalize.normalize_matrix_paths(
    "book/profiles/golden-triple/expected_matrix.json",
    "book/profiles/golden-triple/runtime_results.json",
)
index, _ = build.write_traces(
    observations,
    "book/graph/mappings/runtime/traces",
)
```

```py
from book.api.runtime_tools import workflow

cut = workflow.build_cut(
    "book/experiments/runtime-checks/out/expected_matrix.json",
    "book/experiments/runtime-checks/out/runtime_results.json",
    "/tmp/runtime_cut",
)
print(cut.manifest)
```

```py
from book.api.runtime_tools.mapping import views

comparison = views.build_callout_vs_syscall(observations)
print(comparison["counts"])
```

```py
from book.api.runtime_tools import api as runtime_api

bundle = runtime_api.run_plan(
    "book/experiments/hardened-runtime/plan.json",
    "book/experiments/hardened-runtime/out",
    channel="launchd_clean",
)
packet = runtime_api.emit_promotion_packet(bundle.out_dir, bundle.out_dir / "promotion_packet.json")
print(packet["schema_version"])
```

## Native tool markers

Shared JSONL marker helpers for runtime tooling live here:

- `book/api/runtime_tools/native/tool_markers.h`
- `book/api/runtime_tools/native/ToolMarkers.swift`
- `book/api/runtime_tools/native/seatbelt_callout_shim.c`
- `book/api/runtime_tools/native/seatbelt_callout_shim.h`

These emit versioned JSONL markers to stderr that are parsed by
`core.contract` and stripped out of canonical normalized stderr. Use them in
runtime probes and wrappers instead of ad-hoc stderr parsing.

## File probe helper

The minimal read/write probe used by runtime harnesses lives under:

- `book/api/runtime_tools/native/file_probe/` (see its README for build/run)

## Preflight and apply-gate guardrails

The harness runner uses `book/tools/preflight` by default to avoid known
apply-gate signatures on this host. Controls:

- Disable globally: `SANDBOX_LORE_PREFLIGHT=0`
- Force apply even if preflight flags a signature: `SANDBOX_LORE_PREFLIGHT_FORCE=1`
- Per-profile override in `expected_matrix.json`: `"preflight": {"mode": "off"|"force"|"enforce"}`

When preflight blocks a profile, the runtime result is marked `blocked` with
`failure_stage: "preflight"`; this is evidence of a known apply-gate signature,
not policy semantics.
