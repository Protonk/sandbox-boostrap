# Runtime Adversarial Backlog

Upstream bundle: run_id `ec3df76c-6559-421b-8203-c32709667ffc`, artifact_index sha256 `a1482ddceb3cf636143be8cdc7c8bbbeedfce681a9f4d7fa069dd07a08d0808d`.

## Field2 ambiguity (weak or unresolved field2↔runtime associations)
Source: `book/experiments/field2-atlas/out/derived/ec3df76c-6559-421b-8203-c32709667ffc/runtime/field2_runtime_results.json`

- none (field2=3 now resolves via `adv:file_mode:allow-private`; seed slice is runtime-backed).

## Shape/semantics disagreement (metamorphic invariance failures)
Source: `book/experiments/graph-shape-vs-semantics/out/derived/ec3df76c-6559-421b-8203-c32709667ffc/graph_shape_semantics_summary.json`

- none (path_edges now classified as canonicalization-aware equivalence; counterexamples empty for this run).

## Runtime-adversarial partials/mismatches (decision-stage divergence or prereq-limited)
Source: `book/experiments/runtime-adversarial/out/ec3df76c-6559-421b-8203-c32709667ffc/mismatch_packets.jsonl`

- none (remaining mismatches are canonicalization-boundary path_edges entries already bounded by path-witness evidence).
