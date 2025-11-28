# Probe Op Structure – Research Report (Sonoma / macOS 14.4.1)

## Purpose

Design richer SBPL probes that vary operations, filters, and metafilters to expose filter-specific nodes and op-table behavior, overcoming the “generic path/name dominance” seen in minimal single-filter profiles. The goal is to extract clearer `field2` ↔ filter-ID signals and structural patterns that can be reused by other experiments.

## Baseline and scope

- Host: macOS 14.4.1 (23E224), Apple Silicon, SIP enabled (same baseline as other experiments).
- Vocab artifacts: `book/graph/concepts/validation/out/vocab/ops.json` (196 entries, status: ok), `filters.json` (93 entries, status: ok).
- Related work:
  - `field2-filters`: showed that tiny single-filter profiles mainly surface generic path/name `field2` values.
  - `op-table-operation`: provides op-table bucket behavior for small operation sets.
  - `node-layout`: structural patterns for nodes/tags with various filter shapes.

## Plan (summary)

1. Define a probe matrix that intentionally mixes multiple filters/ops and deeper metafilters (require-any/all) with strong literals to aid identification.
2. Implement/compile these probes and decode them with full vocab length.
3. Traverse graphs from relevant op entries to collect `field2`, tags, and literals, tying literals to likely filters.
4. Analyze cross-probe differences to isolate filter-specific `field2` values and structural markers.
5. Add guardrails/tests once stable mappings emerge.

## Current status

- Experiment scaffold created (`Plan.md`, `Notes.md`, this report). Probe matrix and SBPL implementations are pending.

## Expected outcomes

- A set of richer probe profiles that surface filter-specific `field2` values beyond the generic path/name scaffolding.
- Provisional mappings of `field2` ↔ filter-ID supported by multiple probes.
- Structural notes (tags/branch shapes) that correlate with particular filters/metafilters.
- Reusable guardrails for key mappings.
