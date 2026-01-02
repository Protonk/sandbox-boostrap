# Runtime Adversarial Backlog

Upstream bundle: run_id `738fc3d0-1d12-4608-9a97-90addfbc8d4c`, artifact_index sha256 `21a0c9f45f038bd8afdcdbc5dcd7ff409b36e85b23b5b3ae277d003e0ec9cc80`.

## Field2 ambiguity (weak or unresolved field2↔runtime associations)
Source: `book/experiments/field2-final-final/field2-atlas/out/derived/738fc3d0-1d12-4608-9a97-90addfbc8d4c/runtime/field2_runtime_results.json`

- none (field2=1 now has a dedicated mount-relative-path discriminator and is runtime-backed).

## Shape/semantics disagreement (metamorphic invariance failures)
Source: `book/experiments/runtime-final-final/suites/graph-shape-vs-semantics/out/derived/738fc3d0-1d12-4608-9a97-90addfbc8d4c/graph_shape_semantics_summary.json`

- none (path_edges now classified as canonicalization-aware equivalence; counterexamples empty for this run).

## Runtime-adversarial partials/mismatches (decision-stage divergence or prereq-limited)
Source: `book/experiments/runtime-final-final/suites/runtime-adversarial/out/738fc3d0-1d12-4608-9a97-90addfbc8d4c/mismatch_packets.jsonl`

- none (remaining mismatches are canonicalization-boundary path_edges entries already bounded by path-witness evidence).
