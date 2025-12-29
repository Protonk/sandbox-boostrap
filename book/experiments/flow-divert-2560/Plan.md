# Plan

## Question
- What is the `field2` payload `2560` seen on `flow-divert` tags, and how does it relate to specific SBPL anchors or operation/filter parameterizations on this host?

## Hypothesis
- The payload is tied to a specific anchor/parameter combination (likely a literal/regex bucket) that surfaces when `flow-divert` filters encode multi-attribute requirements (e.g., domain/type/protocol). Current evidence is incomplete; runtime behavior is unverified.

## Success criteria
- **Characterized opaque**: show deterministically that `2560` encodes a specific boolean structure over {domain,type,protocol} independent of ordering/graph shape; retire from “unknown-high” with a stable label even without an anchor.
- **Anchored**: if possible, tie `2560` to a concrete encoder symbol/slot or runtime-observable discriminator; do not let “find anchor” become unbounded—stop once deterministic structure is proven.

## Approach (phased)
1) **Baseline the unknown** – Reproduce current `2560` sightings from `field2-filters`/`unknown_focus` and `probe-op-structure` decodes; inventory tags/filters/ops carrying it and record neighborhoods.
2) **Compile matrix** – Minimal SBPL probes varying one dimension at a time:
   - Presence: domain-only / type-only / proto-only / pairs / all three.
   - Combinator: `require-all` vs `require-any`; nested vs flat triples.
   - Ordering: permute clause order to detect normalization vs ordering artifacts.
   - Negative controls: similar combinators on a different network-ish family; flow-divert pairs (no triple) to see if `2560` tracks “triple-ness.”
   - Build each under `sb/`, compile to `sb/build/`, decode with `book/api/profile_tools/decoder/`.
3) **Normalized decode records** – Emit joinable records per specimen (spec_id,node_id) with tag, raw field2 payload/u16_role, successors, literal refs; store under `out/` for matrix-wide queries.
4) **Optional runtime/encoder trace** – Only if needed to distinguish competing explanations; record apply gates/EPERMs as evidence.
5) **Cross-checks** – Compare to `anchor_filter_map`, field2 atlas, tag-layout contracts; ensure mapping is deterministic under the matrix.
6) **Synthesis** – If deterministic, retire `2560` from unknowns (characterized opaque) with guardrail; only map to an anchor if backed by a witness.

## Status
- **Not started** (skeleton only; no probes run yet).
