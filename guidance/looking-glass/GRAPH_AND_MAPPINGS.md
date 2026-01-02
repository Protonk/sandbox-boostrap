# looking-glass — GRAPH_AND_MAPPINGS (how the repo encodes knowledge)

This bundle explains the “static spine” of SANDBOX_LORE: the concept inventory, the graph generator, and the host-bound mappings that downstream tooling and CARTON depend on.

Scope: concept + mapping artifacts and how they are generated. It does **not** cover runtime harness runs (see `RUNTIME_AND_WITNESS_TOOLCHAIN.md`) or SBPL compilation/decoding details (see `PROFILE_TOOLCHAIN.md`).

Baseline anchor: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## 1) Concepts: names you’re allowed to use

SANDBOX_LORE tries to prevent “vibes-based taxonomy” by keeping a concept inventory and vocabulary map that tooling can validate against.

Primary sources:
- Substrate definitions: `book/substrate/Concepts.md` (and adjacent substrate files)
- Concept inventory: `book/graph/concepts/CONCEPT_INVENTORY.md`

Generated outputs (by the Swift graph target):
- `book/graph/concepts/concepts.json` — normalized concept inventory (IDs, names, tags).
- `book/graph/concepts/concept_map.json` — canonical term map (“what do we mean by X?”).
- `book/graph/concepts/concept_text_map.json` — text snippets keyed by concept IDs.

The point: when an agent invents a new term, it should either be added explicitly or treated as a gap, not silently smuggled in as “obvious”.

## 2) The graph generator (Swift): typed invariants over ad hoc scripts

The graph generator exists to keep the repo’s shared IR consistent and regenerable.

Run it:
```sh
cd book/graph
swift run
```

What it does (high level):
- Parses substrate + concept inventory sources.
- Emits the concept JSON slices above.
- Emits validation metadata and light cross-checks so drift is visible.
- Encodes “must not drift” invariants as Swift data structures so the build fails loudly.

Why Swift here: it’s deliberately small, typed, and reviewable; it functions like a “schema compiler” for the repo’s conceptual layer.

## 3) Validation IR: normalized experiment outputs

Experiments often write messy outputs into `book/experiments/*/out/`. The validation driver normalizes selected results into a committed, queryable IR tree:

- `book/graph/concepts/validation/out/`
  - `metadata.json` — world binding and baseline knobs (SIP/tcc_state/profile format variant, etc.).
  - `validation_status.json` — job status summary.
  - `index.json` — index of validation artifacts and their status.

Treat this as the “stable landing zone” for evidence that is meant to be consumed by mapping generators.

## 4) Host mappings: pinned IR you can build on

Mappings under `book/graph/mappings/` are the durable, world-stamped “facts” the repo builds on.

Common categories:

### 4.1 Vocab (`book/graph/mappings/vocab/`)

The operation + filter vocabulary is the naming/ID spine for everything else.

- `ops.json` — operation IDs + names (bedrock).
- `filters.json` — filter IDs + names (bedrock).
- `ops_coverage.json` — coverage/projection summaries (mapped/operational).

These tables are host-derived (from dyld/lib slices), not assumed stable across macOS.

### 4.2 System profile anchors (`book/graph/mappings/system_profiles/`)

Canonical “system profile” blobs are treated as structural anchors. The mapping files here encode:
- which canonical profiles exist (by id like `sys:bsd`, `sys:airlock`),
- what their stable contract fields are (digests, op-table hashes, tag layout hashes),
- and what drift is allowed vs refused.

These anchors allow many other mapping generators to work without re-decoding the world from scratch every time.

### 4.3 Anchors (`book/graph/mappings/anchors/`)

Anchor maps tie decoded structural slots (for example, the “field2” u16 payload position) to stable meanings for specific tags/contexts.

Examples:
- `anchor_field2_map.json`
- `anchor_filter_map.json`
- `anchor_ctx_filter_map.json`

### 4.4 Runtime projections (`book/graph/mappings/runtime/`)

Runtime projections are promoted summaries derived from runtime promotion packets.

Examples:
- `runtime_coverage.json`
- `runtime_signatures.json`
- `lifecycle.json`

These are mapped-tier and scenario-scoped: they are strong within their bounded witness sets, but not universal semantics claims.

## 5) Mapping generation/promotion (how mappings are updated)

Mapping generators live under `book/graph/mappings/**/generate_*.py` and are orchestrated by a single supported entrypoint:

```sh
python book/graph/mappings/run_promotion.py
```

The intent is to keep “regen” as a bounded, reviewable operation:
- inputs are validation IR + pinned sources,
- outputs are world-stamped mapping JSON,
- downstream projections (CARTON) can then be refreshed deterministically.

## 6) Reverse-engineering inputs (where static extraction comes from)

Some mappings are sourced from:
- dyld-derived slices under `book/graph/mappings/dyld-libs/` (for vocab harvesting), and/or
- Ghidra outputs under `book/dumps/ghidra/out/` (for kernel/policy constraints and xref work).

Ghidra work is a supporting witness braid: it constrains what implementations can be doing, but by itself is not “policy semantics.”

