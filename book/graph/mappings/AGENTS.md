# Agents in `book/graph/mappings/`

Purpose:
- Stable host-specific IR for this Sonoma baseline: vocab tables, op-table alignment, anchors, tag layouts, system profile digests/attestations/static checks, runtime expectations/lifecycle traces.

Do:
- Regenerate artifacts via the provided generators:
  - `vocab/generate_attestations.py`
  - `system_profiles/generate_attestations.py`
  - `system_profiles/generate_static_checks.py`
  - `runtime/generate_lifecycle.py`
  - (runtime expectations/traces come from `book/evidence/graph/concepts/validation/out/semantic/runtime_results.json` → normalization script)
- Keep host/build metadata intact; update statuses instead of hand-editing contents.

Don’t:
- Hand-edit mapping JSONs; use the generators and source experiments.
- Change schemas without updating README + consumers.
