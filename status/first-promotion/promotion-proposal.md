# Promotion proposal: bedrock mappings for the current world

This note proposes promoting a small set of graph-level facts to “bedrock” status, whereby we can treat the mappings below as implicitly true for this `world_id` while keeping evidence trails clear enough that disagreements can still be surfaced and investigated.

The three candidates are:
- Operation vocabulary (196 operations).
- Modern compiled profile format and tag layout.
- Canonical decoded system profiles: `sys:airlock`, `sys:bsd`, and `sys:sample`.

All three already sit at the intersection of multiple experiments and mappings; this proposal is about making that status explicit.

## Validation model

The project learns things like op-table alignments and tag layouts by starting from small, concrete questions and building experiments around them. For op-table work, this typically means writing minimal SBPL profiles that exercise one or two operations in controlled ways, compiling them via the SBPL tooling, decoding the resulting blobs with the shared decoder, and comparing the observed op-table entries against expectations. When patterns hold across multiple probe profiles, those observations are cross-checked against independently decoded system profiles and only then distilled into mapping generators under `book/graph/mappings/`. The mappings are therefore summaries of repeatable probe behaviour plus system-profile structure, not first-pass guesses.

Using a mix of system blobs and synthetic profiles, and running them through different validation jobs, is important because it reduces the chance that a single tool chain or input source is biasing the result. System profiles come from Apple’s own SBPL and compilation pipeline; synthetic probes are authored in this repo to isolate specific ideas. Both are decoded by shared infrastructure, but they enter the pipeline through different paths (installed profiles versus experiment-local SBPL) and are checked by different scripts (system-profile digest jobs, op-table experiments, runtime harnesses). When all of these agree on a structural claim—such as how tags are laid out or how a bucket lines up with an operation—that agreement is stronger than any one source on its own.

Within this model, a mapping or artifact being marked `status: ok` means that, for the current world baseline, the relevant experiments have run, the generators have produced outputs without unresolved discrepancies, and the basic structural invariants and cross-checks for that slice are satisfied. Other statuses capture different conditions: `partial` reflects limited coverage or known gaps, `brittle` flags results that tend to change under small perturbations or tool updates, and `blocked` records places where apply gates, crashes, or missing inputs prevent us from gathering enough evidence. `ok` is a statement about current evidence, not a permanent guarantee.

## Candidate 1 — Operation vocabulary

**What it claims**

The Operation Vocabulary Map for this host is the 196-entry table in [`book/graph/mappings/vocab/ops.json`](book/graph/mappings/vocab/ops.json), mapping SBPL operation names to numeric IDs.

**Evidence**

- `ops.json` is host-tagged and explicitly marked `status: ok`.  
- It is attested against real compiled blobs in [`book/graph/mappings/vocab/attestations.json`](book/graph/mappings/vocab/attestations.json), which records SHA-256 and size for reference binaries and ties them back to the vocab hash.  
- The same operation IDs appear, unchanged, in op-table alignment outputs ([`book/graph/mappings/op_table/op_table_vocab_alignment.json`](book/graph/mappings/op_table/op_table_vocab_alignment.json)) and in decoded system profile digests ([`book/graph/mappings/system_profiles/digests.json`](book/graph/mappings/system_profiles/digests.json)). That gives a consistent 196-op inventory across vocab harvest, synthetic SBPL probes, and real system profiles.

**Independence and paths**

- The [vocab-from-cache experiment](book/experiments/vocab-from-cache) reads ordered operation and filter name tables directly out of the dyld cache, producing `out/operation_names.json` / `out/filter_names.json` and then `ops.json`/`filters.json`.  
- [op-table-operation](book/experiments/op-table-operation) and [op-table-vocab-alignment](book/experiments/op-table-vocab-alignment) compile synthetic SBPL, decode op-tables and node regions, and record how buckets behave and where single-operation profiles land.  
- The [system-profile-digest experiment](book/experiments/system-profile-digest) adds a third view by decoding curated system profiles and recording op-table shapes in `system_profiles/digests.json`.  

Taken together, dyld-derived vocab tables, synthetic op-table behaviour, and real system profiles converge on the same 196-operation inventory and IDs.

## Candidate 2 — Profile format and tag layout

**What it claims**

Modern compiled profiles on this host follow a specific “modern-heuristic” format, and literal/regex-bearing node tags share a stable layout as captured in [`book/graph/mappings/tag_layouts/tag_layouts.json`](book/graph/mappings/tag_layouts/tag_layouts.json).

**Evidence**

- `tag_layouts.json` describes record sizes, edge fields, and payload fields for a small set of tags on this host.  
- Independent decodes of `airlock.sb.bin`, `bsd.sb.bin`, and `sample.sb.bin` in [`book/graph/mappings/system_profiles/static_checks.json`](book/graph/mappings/system_profiles/static_checks.json) all report the same `tag_layout_hash`, confirming that the layout matches what the decoder sees across multiple blobs.  
- Op-table probe summaries in [`book/graph/mappings/op_table/op_table_operation_summary.json`](book/graph/mappings/op_table/op_table_operation_summary.json) also parse cleanly under the same format and tag layout.

**Independence and paths**

- The [tag-layout-decode experiment](book/experiments/tag-layout-decode) works purely from decoded blobs: canonical system profiles are ingested, tag histograms and literal-bearing nodes are collected, and per-tag layouts are inferred and written to `tag_layouts.json`.  
- The [libsandbox-encoder experiment](book/experiments/field2-final-final/libsandbox-encoder) approaches the same question from the compiler side, using SBPL matrices plus a trimmed `libsandbox` slice under `book/graph/mappings/dyld-libs/` to confirm, at the byte level, how filter IDs and arguments are written into node records for key tags.  

The fact that header-aligned layouts seen in compiled blobs match the encodings reconstructed from libsandbox’s emit paths is what justifies treating the tag layouts as structural facts rather than decoder accidents.

## Candidate 3 — Canonical system profiles

**What it claims**

For this host, the decoded structure of `sys:airlock`, `sys:bsd`, and `sys:sample` in the system-profile mappings is a faithful, stable summary of the compiled profiles Apple ships.

**Evidence**

- The three profiles have SHA-anchored digests in [`book/graph/mappings/system_profiles/digests.json`](book/graph/mappings/system_profiles/digests.json) (format variant, op_count, op_table, source path).  
- They have independent structural checks in [`book/graph/mappings/system_profiles/static_checks.json`](book/graph/mappings/system_profiles/static_checks.json) (section sizes, op_table_hash, tag_counts, tag_layout_hash).  
- They have richer attestations in `book/graph/mappings/system_profiles/attestations/*.jsonl` that enumerate literal strings, anchors, and other structural details.  
- The same SHAs show up again in [`book/graph/mappings/runtime/golden_expectations.json`](book/graph/mappings/runtime/golden_expectations.json) for `sys:bsd` and `sys:airlock`, tying those blobs to runtime-facing experiments.

**Independence and paths**

- System SBPL (`/System/Library/Sandbox/Profiles/*.sb`) is compiled and extracted to `.sb.bin` blobs, then decoded into digests and static checks.  
- The [system-profile-digest experiment](book/experiments/system-profile-digest) owns the decoding and normalization step into `system_profiles/digests.json`.  
- Runtime-facing experiments ([runtime-checks](book/experiments/runtime-final-final/suites/runtime-checks) and [sbpl-graph-runtime](book/experiments/runtime-final-final/suites/sbpl-graph-runtime)) exercise related profiles (recompiled `bsd`, golden microprofiles, selected synthetic bucket profiles) through the SBPL wrapper and compare observed allow/deny behaviour with expectations derived from decoded graphs.  

On this host, platform blobs are apply-gated, but the agreement between decoded structure and runtime outcomes for the golden set indicates that the static IR matches the policies the kernel enforces where the harness can run.

## Cross-check routes

For these candidates, cross-checks run along two broad routes. One route starts from Apple’s artifacts—dyld cache slices for Sandbox.framework and `libsandbox`, and SBPL sources under `/System/Library/Sandbox/Profiles`—and extracts what those components say about operations, filters, and profile structure. The other route starts from compiled profile blobs (system blobs and synthetic SBPL compiled via `sbpl_compile`), decodes them with the shared ingestion tools, and treats the resulting PolicyGraphs as the ground truth for how Seatbelt policies are laid out on this host.

Because the kernel-side evaluator is treated as a black box, agreement between these two routes is the main way the project justifies using the static IR as a proxy for “what the sandbox actually sees.” For operations, this means dyld-derived vocab tables, op-table experiments, and system-profile digests all imply the same ID assignments. For tag layouts, blob-side inference and compiler-side reconstruction tell the same story about how nodes are structured. For system profiles, static decodes and runtime probes (where they can run) point to the same effective policies.

## Promotion criteria and current status

Within this world, promotion from an experiment-local result to a shared `status: ok` mapping happens when:
- the relevant experiments have been run and documented,
- the mapping has been distilled into `book/graph/mappings/*` and used by at least one other tool or experiment, and
- the results are consistent across the independent routes that touch the same concept.

For the three clusters above, those conditions are met today: vocab tables are tied to dyld and to decoded profiles, tag layouts are supported by both blob decodes and libsandbox analysis, and canonical system profiles have stable digests with runtime-linked SHAs. Marking these mappings as bedrock is a way of recording that consensus for the Sonoma baseline, while still leaving room to revisit them if future experiments or host changes surface genuine discrepancies. 
