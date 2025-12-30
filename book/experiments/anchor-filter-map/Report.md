# Anchor ↔ Filter ID Mapping – Research Report

## Purpose
Bind anchor labels emitted by `probe-op-structure` to concrete Filter IDs, while avoiding the “string-only anchor identity” trap: the same SBPL literal can legitimately appear in multiple disjoint filter contexts (and in non-filter structural roles). The canonical output is therefore ctx-indexed (`book/graph/mappings/anchors/anchor_ctx_filter_map.json`), with a conservative literal-keyed compatibility view (`book/graph/mappings/anchors/anchor_filter_map.json`) generated from it.

## Baseline & scope
- World: Sonoma baseline from `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
- Inputs:
  - Anchor hits from `book/experiments/probe-op-structure/out/anchor_hits.json`.
  - Field2 inventory (with anchors) from `book/experiments/field2-filters/out/field2_inventory.json`.
  - Filter vocab from `book/graph/mappings/vocab/filters.json`.
  - Existing anchor → field2 hints from `book/graph/mappings/anchors/anchor_field2_map.json`.
- Tooling: `book.api.profile.decoder` for any new probes; existing probe outputs as primary evidence.
- Target artifact: `book/graph/mappings/anchors/anchor_ctx_filter_map.json` (canonical), plus derived `book/graph/mappings/anchors/anchor_filter_map.json` (compatibility view).

## Deliverables / expected outcomes
- `book/graph/mappings/anchors/anchor_ctx_filter_map.json` as the source of truth for anchor→Filter bindings keyed by `anchor_ctx_id`.
- `book/graph/mappings/anchors/anchor_filter_map.json` as a deterministic, conservative derived view keyed by literal string with `ctx_ids` backpointers.
- `book/experiments/anchor-filter-map/out/anchor_filter_candidates.json` summarizing candidate mappings and evidence.
- Guardrail coverage in `book/tests/planes/graph/test_mappings_guardrail.py` for at least one high-confidence anchor → filter-ID pair.
- Notes/Report entries describing ambiguous anchors and how to revisit them.

## Plan & execution log
### Completed
- **Current status**
  - Experiment scaffolded (this Report, Plan, Notes).
  - Baseline candidate extraction done: `out/anchor_filter_candidates.json` holds anchor → {field2_names, field2_values, sources}.
  - Canonical ctx-indexed anchor map published at `book/graph/mappings/anchors/anchor_ctx_filter_map.json`, and legacy literal view regenerated conservatively at `book/graph/mappings/anchors/anchor_filter_map.json` (pins a literal only when all contexts agree).
  - Runtime discriminator run for `com.apple.cfprefsd.agent` (mach-lookup predicate kind):
    - Result (tier `mapped`; host-scoped): the discriminating matrix is consistent with `com.apple.cfprefsd.agent@global-name` on this host; the literal-keyed compatibility view remains blocked because the same literal is observed in multiple contexts.
    - Provenance:
      - `run_id`: `028d4d91-1c9e-4c2f-95da-7fc89ec3635a`
      - Promotion packet: `book/experiments/anchor-filter-map/out/promotion_packet.json`
      - Promotion receipt: `book/graph/mappings/runtime/promotion_receipt.json` (packet `status: used`)
    - Bounded witness summary:
      - Baseline lane: `com.apple.cfprefsd.agent` is observable (`kr=0`), and a bogus name is unregistered (`kr=1102`).
      - Under `(deny default)`: allowing `mach-lookup` unfiltered reaches/permits the lookup; denying by default yields `kr=1100`.
      - Predicate discrimination: allowing `global-name` permits; allowing `local-name` yields `kr=1100`; allowing both permits.
  - Runtime discriminator attempted for `IOUSBHostInterface` (iokit-open-service predicate kind):
    - Result (tier `mapped`; host-scoped): discriminator attempt is recorded (packet/receipt), but baseline lane reports `found=false` in this process context, so no filter-kind lift is justified.
    - Provenance:
      - `run_id`: `bf80e47b-3020-4b13-bfa7-249cfcff8b52`
      - Promotion packet: `book/experiments/anchor-filter-map/iokit-class/out/promotion_packet.json`
      - Promotion receipt: `book/graph/mappings/runtime/promotion_receipt.json` (packet `status: used`)
    - Bounded witness summary:
      - Baseline lane: `IOUSBHostInterface` not found (`found=false`), so the discriminator matrix cannot lift the anchor on this host baseline.
- **1) Scope and setup**
  - Host baseline (OS/build, SIP) recorded in this Report and in `Notes.md`.
  - Inputs confirmed: `probe-op-structure/out/anchor_hits.json`, `field2-filters/out/field2_inventory.json`, vocab (`book/graph/mappings/vocab/filters.json`), anchor → field2 hints (`book/graph/mappings/anchors/anchor_field2_map.json`).
  - Decoder (`book.api.profile.decoder`) validated via existing probes and inventories.
- **2) Baseline data pass**
  - Loaded anchor hits and field2 inventory; identified anchors with clear filter context (paths, mach names, iokit symbols).
  - Built initial candidates for anchor → filter-ID mapping, including conflicting and ambiguous cases.
- **3) Targeted probes (if needed)**
  - None so far; current map is based solely on existing probes and system profiles.
- **4) Synthesis and guardrails**
  - Finalized `book/graph/mappings/anchors/anchor_ctx_filter_map.json` as the canonical ctx-indexed mapping surface; regenerated `book/graph/mappings/anchors/anchor_filter_map.json` as the deterministic derived view.
  - Added a guardrail test (`book/tests/planes/graph/test_mappings_guardrail.py`) that asserts map presence and at least one mapped anchor → filter ID.
  - Updated `ResearchReport.md` and `Notes.md` with current mapping decisions, evidence sources, and remaining ambiguous anchors.

### Maintenance / rerun plan
If the anchor map needs to be updated (for example, new probes or improved decoding), reuse this outline:

1. **Scope and setup**
   - Confirm the baseline (OS/build, SIP) in `book/world/.../world.json`, this Report, and `Notes.md`.
   - Ensure upstream inputs (`probe-op-structure` and `field2-filters` outputs, vocab, anchor_field2 hints) are current.
2. **Baseline data pass**
   - Rebuild `out/anchor_filter_candidates.json` from anchor hits and field2 inventory.
   - Identify anchors with clear filter context and anchors that remain ambiguous.
3. **Targeted probes (if needed)**
   - Craft minimal SBPL probes to disambiguate anchors that still have multiple plausible filters.
   - Decode and rerun anchor extraction; refine the candidate mapping where new evidence appears.
4. **Synthesis and guardrails**
   - Refresh `anchor_filter_map.json` with updated per-anchor status and provenance.
   - Keep the guardrail test in sync so it continues to assert presence and at least one mapped anchor → filter ID.

## Evidence & artifacts
- Anchor hits from `book/experiments/probe-op-structure/out/anchor_hits.json`.
- Field2 inventory from `book/experiments/field2-filters/out/field2_inventory.json`.
- Filter vocabulary from `book/graph/mappings/vocab/filters.json`.
- Intermediate candidates in `book/experiments/anchor-filter-map/out/anchor_filter_candidates.json`.
- Canonical ctx-indexed mapping in `book/graph/mappings/anchors/anchor_ctx_filter_map.json`.
- Derived compatibility view in `book/graph/mappings/anchors/anchor_filter_map.json`.

## Blockers / risks
- Some anchors remain ambiguous and map to multiple plausible filters; these are explicitly marked in the map and may change as decoder/tag layouts improve.
- Mapping quality depends on the current `field2` understanding; decoder or tag-layout revisions may require revisiting specific anchors.

## Next steps
- Design and run targeted SBPL probes for remaining ambiguous anchors to tighten their mappings.
- Refresh `anchor_filter_map.json` and candidates after decoder or field2 mapping improvements.
- Extend guardrail coverage once additional high-confidence anchors are established.
- For a field2-first, runtime-tagged slice (field2 0/5/7 + a static-only candidate), see `book/experiments/field2-atlas/`, which follows field2 as the primary key across anchors, profiles, and runtime traces.
