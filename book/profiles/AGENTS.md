# Profiles directory – AGENT guidance

Scope and host
- This tree holds host-specific profile material for SANDBOX_LORE.
- Host baseline: see `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)`.

Golden triple rules
- Golden profiles must have: SBPL source, decoded PolicyGraph linkage, static expectations (schema: provisional, `expectation_id` join key), and runtime results that align on this host from an unsandboxed caller.
- Platform blobs (`sys:*`) and strict/apply-gate outliers stay in experiments; do not emit them here unless explicitly cleared.

Workflow
- Do not use symlinks or manual copies. Regeneration scripts must write artifacts directly into this tree.
- Keep schema tags as `provisional` until a newer schema is blessed.
- Use substrate vocabularies (ops/filters from `book/graph/mappings/vocab`) and keep profile text host-bound.
