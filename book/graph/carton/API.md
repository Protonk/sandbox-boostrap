# CARTON API surface

CARTON is a frozen set of IR and mappings for the Sonoma 14.4.1 host. Use it as the stable interface for host-specific IR instead of reading raw experiment outputs or validation scratch. It is built from the substrate and validation/mapping machinery and surfaced via a small API layer.

Public interface (guarded by the manifest at `book/graph/carton/CARTON.json`):
- `book/graph/mappings/vocab/{ops.json,filters.json}`
- `book/graph/mappings/runtime/runtime_signatures.json`
- `book/graph/mappings/system_profiles/digests.json`
- `book/graph/mappings/carton/operation_coverage.json`
- Helper module: `book/api/carton/carton_query.py` (public entrypoint; see `book/graph/carton/USAGE_examples.md`).

Error and manifest handling:
- `book.api.carton.carton_query` reads paths from `CARTON.json`, checks hashes, and raises `CartonDataError` when mappings are missing/malformed or do not match the manifest.
- Unknown operations raise `UnknownOperationError`; helpers should be ready to handle that when probing for unlisted ops.
- The public query functions otherwise return stable, typed dicts/lists anchored in the CARTON mappings.

Internal plumbing (normally only needed when extending CARTON):
- Validation status + per-job IR under `book/graph/concepts/validation/out/…` (validation → IR layer).
- Mapping generators under `book/graph/mappings/*/generate_*.py` and `run_promotion.py` that normalize experiment IR into stable mappings and feed CARTON.

Stability contract:
- Files listed in `CARTON.json` do not change except via a deliberate regeneration (validation driver → mapping generators → manifest update). Guardrail tests pin their hashes.
- Do not hand-edit CARTON JSON. Regenerate via the validation driver and mapping generators, then refresh the manifest.
- New experiments or mappings should live alongside CARTON; update the manifest only when you intentionally revise the frozen layer for Sonoma 14.4.1.
- Usage examples: `book/graph/carton/USAGE_examples.md` shows how to answer common questions via `book.api.carton.carton_query` and the coverage mapping without diving into raw JSON.
