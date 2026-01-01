# Runtime Adversarial Backlog

Upstream bundle: run_id `7fb35590-c5c0-4187-8949-f534fbd43045`, artifact_index sha256 `c9454b3010e2f9a35b085254b5283758c474f66c8a49fba8bf2820ddc3533f75`.

## Field2 ambiguity (weak or unresolved field2↔runtime associations)
Source: `book/experiments/field2-atlas/out/derived/7fb35590-c5c0-4187-8949-f534fbd43045/runtime/field2_runtime_results.json`

- none (field2=2 now resolves via `adv:xattr:allow-foo-read`; seed slice is runtime-backed).

## Shape/semantics disagreement (metamorphic invariance failures)
Source: `book/experiments/graph-shape-vs-semantics/out/derived/7fb35590-c5c0-4187-8949-f534fbd43045/graph_shape_semantics_summary.json`

- none (path_edges now classified as canonicalization-aware equivalence; counterexamples empty for this run).

## Runtime-adversarial partials/mismatches (decision-stage divergence or prereq-limited)
Source: `book/experiments/runtime-adversarial/out/7fb35590-c5c0-4187-8949-f534fbd43045/mismatch_packets.jsonl`

- none (remaining mismatches are canonicalization-boundary path_edges entries already bounded by path-witness evidence).
