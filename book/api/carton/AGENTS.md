# AGENTS.md — CARTON layer

You are in `book/api/carton/`, the API and manifest layer for CARTON: the frozen IR/mapping set rooted at `book/api/carton/CARTON.json`.

Use this directory when you need stable, host‑specific facts about the sandbox on this machine, or when you are extending CARTON itself.

When you want to **read facts**, start from the API. When you want to **change what CARTON knows**, start from validation and mappings, then refresh the manifest.

## First moves for agents (reading CARTON)

When an agent needs to answer questions about operations, profiles, filters, or runtime coverage, it should:

1. Import the public API:
   - `from book.api.carton import carton_query`
2. Discover what CARTON knows:
   - `carton_query.list_operations()` — names and IDs of known operations.
   - `carton_query.list_profiles()` — known system profiles/profile layers.
   - `carton_query.list_filters()` — known filters and their vocab identities.
3. Ask concept‑shaped questions:
   - `carton_query.operation_story(op_name)` — where an operation appears in system profiles/profile layers and runtime signatures, with coverage counts.
   - `carton_query.profile_story(profile_id)` — which operations a profile exercises and which runtime signatures touch those operations.
   - `carton_query.filter_story(filter_name)` — vocab identity plus `usage_status` (present‑in‑vocab‑only, referenced‑in‑profiles, referenced‑in‑runtime, unknown) and any known usage.
   - `carton_query.runtime_signature_info(sig_id)` — probes and runtime profile information for a runtime signature.
   - `carton_query.ops_with_low_coverage(threshold)` — operations with low or zero observed coverage.

Error handling:
- `UnknownOperationError` means “this operation name is not in the CARTON vocab”; callers should treat this as “unknown concept” or “typo/host mismatch,” not as a data‑layer failure.
- `CartonDataError` means “CARTON itself is out of sync” (missing mapping, hash mismatch, manifest drift); callers should not try to work around it and should instead run the validation/promotion pipeline.

Agents should treat these helpers as the default way to answer coverage questions, rather than re‑parsing CARTON JSONs or validation outputs by hand.

## Working on CARTON internals

If you are extending or regenerating CARTON:

- **Do**:
  - Use the validation driver under `book/graph/concepts/validation/` to regenerate IR and status files.
  - Use `book/graph/mappings/run_promotion.py` to rebuild runtime/system mappings and CARTON‑derived views (coverage and indices).
  - Use `book/api/carton/create_manifest.py` (or the promotion driver) to refresh `CARTON.json` after mappings change.
  - Keep mappings and manifest free of timestamps; host metadata must come from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
  - Update or add tests under `book/integration/` when you introduce new CARTON surfaces or concept bindings.

- **Do not**:
  - Hand‑edit JSON files that are listed in `CARTON.json`.
  - Point new experiments or docs directly at validation IR or experiment output when CARTON already exposes the concept you need.
  - Introduce new CARTON‑facing mappings outside the promotion/pipeline structure.

For details of CARTON’s role in the overall project and how concepts map to artifacts, read `README.md`. For function‑level API contracts and return shapes, see `API.md`.

