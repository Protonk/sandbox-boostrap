# CARTON Reorg Plan (Inventory Graph)

Purpose: replace the scattered promotion/lane manifests with a single, typed
inventory graph in CARTON that tracks evidence/tools/api and grows into a
semantic IR with Swift-enforced invariants.

## Goals
- Keep a single "I am sure" step for any meaningful change in tools/api/evidence.
- Track contract surfaces (anything with "spec." or "schema." in the path).
- Keep failure surfacing localized to the disturbed plane (tools/api/evidence).
- Make CARTON a real semantic graph we can query and enforce with Swift.

## Scope (initial)
- Track under: `book/tools/`, `book/api/`, `book/evidence/`.
- Exclude experiments for now; add experiment evidence piecemeal later.
- Always track any path containing `spec.` or `schema.` (case-insensitive).

## Inventory IR (new CARTON artifact)
- Output path:
  - `book/integration/carton/bundle/relationships/inventory/inventory_graph.json`
- Node kinds: `tool`, `api`, `evidence`, `mapping`, `test`, `contract`
- Edge kinds: `produces`, `consumes`, `guards`, `declares`
- Use repo-relative paths via `book.api.path_utils`.
- Register in `book/integration/carton/core/registry.py` so it lands in
  `book/integration/carton/bundle/CARTON.json`.

## Tracking Rules
- `contract` sensitivity is automatic for any path containing `spec.` or `schema.`.
- JSON files default to `semantic_json` digests; binaries default to `bytes`.
- Prose docs (README, Notes, Plan) are ignored unless explicitly tagged as
  `contract`.
- Evidence edges encode both:
  - "evidence went here" (`produces`)
  - "evidence from here is relied upon there" (`consumes`)

## Agent Workflow ("I am sure")
- New command: `python -m book.integration.carton track`
- Behavior:
  - Scan scope roots, refresh inventory graph, and update CARTON spec/manifest
    for inventory artifacts only (no mapping regeneration).
  - Emit clear failures when an eligible artifact is untracked.

## Swift Enforcement (semantic IR)
- Swift loads `inventory_graph.json` and enforces invariants, for example:
  - every `contract` is declared by at least one `tool` or `api`
  - every `evidence` node is consumed by at least one `mapping` or `test`
  - every `mapping` node is guarded by at least one `test`
- Swift can emit an impact report listing affected tests for any inventory drift.

## Test Surfacing
- Add plane-specific tests that load the inventory graph:
  - tools plane: missing/changed tool entries fail tools tests
  - api plane: missing/changed contract entries fail contracts tests
  - evidence plane: missing/changed evidence entries fail runtime/graph tests
- CARTON check continues to validate manifest integrity and artifact digests.

## Rollout (staged)
1. Add inventory graph generator + CLI (`track`).
2. Register inventory graph in CARTON registry/spec/manifest.
3. Add Swift loader + minimal invariants.
4. Add plane tests to surface drift at the disturbed test.
5. Backfill evidence edges incrementally, starting with runtime packets and
   mapping inputs.
