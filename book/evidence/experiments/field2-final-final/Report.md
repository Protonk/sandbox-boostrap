# Field2 Final Final — Research Report

Status: partial

## Purpose
Provide a single, unified experiment surface for field2 on the Sonoma baseline. This experiment consolidates static field2 inventories, anchor/tag structural scans, encoder emission witnesses, targeted probe suites, and runtime-backed atlas construction into one reproducible pipeline.

## Position in the repo
This is the only active field2 experiment. It replaces the previous field2-focused experiments and is now the canonical location for all field2 evidence within `book/evidence/experiments/`.

## Structure
The experiment is organized as submodules under this root:
- `field2-filters/` — inventories and unknown census.
- `field2-atlas/` — static+runtime atlas outputs with packet-only consumption.
- `probe-op-structure/` — anchor/tag/field2 structural scans.
- `anchor-filter-map/` — runtime discriminator matrices for anchor→filter bindings.
- `libsandbox-encoder/` — encoder matrices and byte-level network witnesses.
- `flow-divert-2560/` — triple-token characterization.
- `bsd-airlock-highvals/` — high/opaque payload probes.

## Loop (frontier → tranche → packet → delta → promote/retire)
This experiment runs as a single-claim loop. Userland-only evidence feeds a ranked frontier (`book/tools/policy/ratchet/frontier_build.py`), a tranche selector picks exactly one field2 claim to decide (`book/tools/policy/ratchet/tranche_select.py`), `sandbox_check()` provides a fast discriminator preflight, runtime-adversarial produces a promotion packet for the micro-suite, and packet-only consumers emit a mapping delta or an explicit retire decision. The loop does not accept partials as semantics: apply-stage failures remain blocked, and each cycle either changes a mapping surface or retires a claim with a witness trail.

## Progress ratchet
The loop is enforced by a progress gate (`book/integration/tests/graph/test_field2_progress_gate.py`) and a milestone ledger: `active_milestone.json` defines the current finite test list and `decisions.jsonl` records each decided claim with packet identity, lane attribution, and delta/retire evidence. `book/tools/policy/ratchet/ratchet_driver.py` widens the milestone by excluding already-decided claims so the gate is forced red until new items are decided.

## Evidence paths (canonical)
- Inventory: `book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json`.
- Unknown census: `book/evidence/experiments/field2-final-final/field2-filters/out/unknown_nodes.json`.
- Anchor hits: `book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json`.
- Atlas static: `book/evidence/experiments/field2-final-final/field2-atlas/out/static/field2_records.jsonl`.
- Atlas derived: `book/evidence/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/...`.
- Frontier: `book/evidence/experiments/field2-final-final/out/frontier.json`.
- Tranche: `book/evidence/experiments/field2-final-final/out/tranche.json`.
- Milestone: `book/evidence/experiments/field2-final-final/active_milestone.json`.
- Decisions: `book/evidence/experiments/field2-final-final/decisions.jsonl`.

## Current status
- Static inventories are current for the seed slice and the high/unknown census.
- Runtime atlas remains partial and depends on promotion packets from runtime-adversarial and anchor-filter-map; packet-only consumption is enforced.
- Encoder matrices and flow-divert triple-only witnesses are preserved as static, structural evidence.
 - Loop scaffolding is in place to make tranche selection and packet-backed updates mechanical and single-claim by default.

## Notes on scope and limits
- All claims are host-bound to the Sonoma baseline and require explicit witness artifacts.
- Apply-stage failures remain `blocked` and are not treated as policy semantics.
- This experiment does not change mappings directly; it produces evidence that can be promoted through the standard validation → mappings pipeline.
