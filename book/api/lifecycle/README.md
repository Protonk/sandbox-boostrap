# lifecycle

Host-specific lifecycle probes for `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

These probes exist to generate *validation IR* under:
- `book/evidence/carton/validation/out/lifecycle/`

and to feed lifecycle mapping generators such as:
- `book/integration/carton/mappings/runtime/generate_lifecycle.py`

## Probes (current)

- `entitlements-evolution`
  - Builds and runs `c/entitlements_example.c`.
  - Writes a compact summary JSON (`entitlements_present`, signing identifier, executable path) to `entitlements.json`.

- `extensions-dynamic`
  - Builds and runs `c/extensions_demo.c`.
  - Writes a short notes log to `extensions_dynamic.md` (status is often `blocked` on this host without special entitlements).

- `platform-policy`
  - Builds and runs `c/platform_policy.c`.
  - Writes a JSONL log to `platform.jsonl` (unsandboxed baseline probes for sysctl/open/mach-lookup outcomes).

- `containers`
  - Builds and runs `swift/containers_demo.swift`.
  - Writes a compact container/redirect JSON report to `containers.json`.

- `apply-attempt`
  - Uses `book/tools/sbpl/wrapper/wrapper` to attempt SBPL apply (compile+apply+exec) and record apply-stage markers.
  - Writes a compact apply attempt JSON report to `apply_attempt.json`.

## Run

Write the default lifecycle outputs:

```sh
python -m book.api.lifecycle write-validation-out
```

Or write one output to an explicit path:

```sh
python -m book.api.lifecycle entitlements --out book/evidence/carton/validation/out/lifecycle/entitlements.json
python -m book.api.lifecycle extensions --out book/evidence/carton/validation/out/lifecycle/extensions_dynamic.md
python -m book.api.lifecycle platform-policy --out book/evidence/carton/validation/out/lifecycle/platform.jsonl
python -m book.api.lifecycle containers --out book/evidence/carton/validation/out/lifecycle/containers.json
python -m book.api.lifecycle apply-attempt --out book/evidence/carton/validation/out/lifecycle/apply_attempt.json
```

Build products are written under `book/api/lifecycle/build/` (not committed).
