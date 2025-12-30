# System profiles

Canonical system-profile digests live here. These profiles (`sys:airlock`, `sys:bsd`, `sys:sample`) are treated as bedrock references for this host/build and carry explicit contract/status metadata tied to the current `world_id`; each canonical entry records its `id`, `role`, `status`, and `world_id` pointer (no new `world_id` values are synthesized here).

Current artifacts:
- `digests.json` – Central canonical-profile mapping with per-profile status and contract:
  - `metadata` now records `status`, `canonical_profiles` status map, `contract_fields`, and `world_id`.
  - Each canonical profile entry carries `world_id`, `status`, `contract`, `observed`, `drift`, and `downgrade_reason` alongside the structural digest (op-table buckets, tag counts, literals, sections, validation).
  - Contract fields are strict (sbpl hash if present, blob sha/size, op-table hash/length, tag counts, tag-layout hash, world pointer). Drift demotes status to `brittle` and records the mismatching fields.
- `static_checks.json` – Decoder-backed invariants (header op_count, section sizes, tag_counts, tag_layout hash) for the same curated blobs; includes `metadata`.
- `attestations.json` + `attestations/*.jsonl` – Cross-linked attestations for system and golden profiles (blob sha256, op-table entries, tag counts, literal/anchor hits, tag-layout hash, vocab versions, runtime links when available); includes `metadata`.
  - The tag-layout hash in static checks is computed from the tag set/order only, so metadata-only edits to `tag_layouts.json` do not trigger contract drift; changing the tag set or structure does.

Role in the substrate and CARTON:
- These digests are compact, decoder-backed views of real platform **Profile layers** and their compiled **PolicyGraphs**. They provide stable examples of op-table shapes, tag distributions, and literal content for system Seatbelt profiles.
- Other experiments (op-table, tag-layouts, anchors, field2) treat these as ground-truth reference profiles when checking structural hypotheses, and the textbook uses them as worked examples of how SBPL templates, entitlements, and containers manifest in compiled policy.
- Attestations connect these static snapshots to vocab/tag-layout versions, anchor coverage, and runtime traces so downstream tools can mechanically join structure ↔ literals ↔ runtime outcomes.
- CARTON manifest: `book/integration/carton/CARTON.json` freezes the hashes/paths for Sonoma 14.4.1 system profile digests and their validation IR as part of the CARTON contract bundle. Downstream coverage/indices inherit the canonical-profile `status` so drift cannot be silently accepted.

Regeneration/demotion:
- Use `book/graph/mappings/system_profiles/generate_digests_from_ir.py` (runs validation + static checks) to refresh digests and enforce contracts. Contract drift automatically demotes per-profile status and records the mismatching fields while keeping the `world_id` pointer.
- `generate_static_checks.py` refreshes the supporting static invariants.
- On drift: CI guardrails catch mismatches. Run `generate_digests_from_ir.py` to record the demotion and drift fields (without changing `world_id`), then regenerate coverage/indices plus the CARTON contracts + manifest so downstream readers and CARTON see the degraded status before committing the change.

Design notes:
- Canonical entries are “bedrock anchors”: they always point back to the frozen host baseline via `world_id`, and the generator treats a world mismatch as corruption rather than an invitation to mint a new pointer.
- Contracts are strict snapshots of the host artifacts. Any drift is recorded and demotes the canonical status; downstream mappings import that status instead of trying to reinterpret it.
