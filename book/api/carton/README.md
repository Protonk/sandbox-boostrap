# CARTON overview

CARTON is the frozen, host-bound IR layer for this project. It records what is currently known about the sandbox on a single world baseline, backed by concrete mappings and a manifest, and exposes that state through a small Python API.

- **Host binding** – CARTON is tied to the Sonoma world baseline recorded in `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`. All CARTON artifacts are generated for that baseline and checked against it.
- **Manifest-driven** – `book/api/carton/CARTON.json` lists the CARTON-facing JSON files and their SHA-256 hashes. Callers reach the data only through this manifest; the API verifies paths and hashes before answering queries.
- **Frozen surface** – Files listed in the manifest do not change except via the validation → mapping → promotion pipeline. CARTON JSONs and the manifest contain no timestamps so they can be regenerated bit-for-bit.

## Dataflow and provenance

At a high level, CARTON sits at the end of a single pipeline:

1. **Validation IR** – Experiments and decoders write JSON under `book/graph/concepts/validation/out/…`. The validation driver runs these jobs and records their status.
2. **Host mappings** – Mapping generators under `book/graph/mappings/*/generate_*.py` turn validation IR into host‑specific mappings, including:
   - Runtime signatures (`runtime/runtime_signatures.json`),
   - System profile digests (`system_profiles/digests.json`),
   - CARTON‑derived views (coverage and concept indices under `mappings/carton/`).
3. **Promotion** – `book/graph/mappings/run_promotion.py` is the entry point from validation IR to mappings. It runs the relevant validation jobs, checks their status, regenerates the mappings above, and then calls the CARTON manifest builder.
4. **Manifest** – `book/api/carton/create_manifest.py` hashes the CARTON‑facing mappings and selected provenance files into `CARTON.json`, using host metadata from the world baseline.
5. **API** – `book/api/carton/carton_query.py` loads `CARTON.json`, verifies hashes, and serves concept‑shaped answers backed by the mappings and indices.

Only the promotion pipeline updates CARTON. Hand‑editing JSON under these paths will be treated as corruption by the manifest and API.

## Concepts realized in CARTON

Concepts are defined in the substrate’s concept inventory; CARTON provides concrete, host-specific representations for a subset of them:\

- **Operation**
  - Vocab: `book/graph/mappings/vocab/ops.json` (operation names and IDs).
  - Coverage: `book/graph/mappings/carton/operation_coverage.json` (where each operation shows up in profiles and runtime signatures).
  - Indices: `book/graph/mappings/carton/operation_index.json` (operation‑centred view used by the API’s operation helpers).
- **Filter**
  - Vocab: `book/graph/mappings/vocab/filters.json`.
  - Index: `book/graph/mappings/carton/filter_index.json` with a finite `usage_status` enum describing what is currently known about where a filter appears.
- **Profile / Profile Layer**
  - System profiles: `book/graph/mappings/system_profiles/digests.json` (profile identities and summary information).
  - Index: `book/graph/mappings/carton/profile_layer_index.json` (operations and runtime signatures grouped by profile identity and layer).
- **Runtime signature / outcome**
  - Runtime signatures: `book/graph/mappings/runtime/runtime_signatures.json` (runtime probes and their outcomes).
  - Coverage and indices: the coverage and index mappings above refer back to these signatures.
- **Concept bindings**
  - `book/graph/mappings/carton/concept_index.json` ties concept‑inventory names (for example, `operation`, `filter`, `profile-layer`, `runtime-signature`) to the specific CARTON mappings and top‑level keys that represent them.
