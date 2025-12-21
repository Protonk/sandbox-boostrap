# Runtime probes

Runtime probe outputs that are stable enough to reuse live here. These are versioned to the Sonoma baseline (23E224) and come from the same harness used by `book/graph/concepts/validation/out/semantic/runtime_results.json`.

Current artifacts:
- `expectations.json` — manifest keyed by `profile_id` (plus `metadata`) with host/build/SIP metadata, blob path + SHA256, status (`ok`/`partial`/`blocked`), probe count, and the trace file path.
- `traces/*.jsonl` — normalized per-profile probe rows (`profile_id`, `probe_name`, operation name/id, inputs, expected vs actual, match/status, command, exit code) with vocab IDs attached. Sources point back to the validation log for provenance.
- `lifecycle.json` + `lifecycle_traces/*.jsonl` — normalized lifecycle probes (entitlements, extensions) with status per scenario, host/build metadata, and source log pointers.
- `golden_expectations.json` — golden runtime profile manifest (bucket4, bucket5, metafilter_any, strict_1, sys:bsd deny-only, sys:airlock EPERM) with blob hashes and modes; includes `metadata`.
- `traces/golden_traces.jsonl` — normalized probe rows for the golden set from runtime-checks.
- `golden_decodes.json` + `decoded_blobs/` — compiled blobs and slim decode summaries (node_count, op_count, tag_counts, literal_strings) for the same golden set; includes `metadata`.
- `runtime_signatures.json` — small IR derived from validation outputs (`field2_ir.json` + normalized runtime results) summarizing probe outcomes by profile plus a field2 summary; regenerated via `book/graph/mappings/runtime/generate_runtime_signatures.py` (which runs the validation driver `--tag smoke`) and folded into CARTON.
- CARTON: see `book/api/carton/CARTON.json` for frozen hashes/paths of the runtime mappings/IR that are included in CARTON for Sonoma 14.4.1.

Status update (permissive host):
- Latest refresh ran under the permissive host context (`--yolo`), so apply-stage EPERM cleared for runtime-checks and runtime-adversarial probes.
- `runtime_signatures.json`, `runtime_coverage.json`, and `expectations.json` now reflect decision-stage outcomes again; `sys:airlock` remains preflight-blocked and `path_edges` mismatches persist as the known VFS-canonicalization boundary.

Claims and limits (current host cut):
- For the operations that have both runtime-checks and runtime-adversarial coverage today—file-read*, file-write*, and mach-lookup—the decoded PolicyGraph IR (vocab, op-table, tag layouts where used, and graphs) agrees with kernel enforcement even under adversarial SBPL constructions (structural/metafilter variants and mach global/local literal/regex probes).
- The one systematic divergence observed so far is `/tmp` → `/private/tmp` behavior in a synthetic path profile, attributed to VFS canonicalization outside the PolicyGraph model and recorded as such; it is not treated as a decoder bug.
- This justifies treating the static IR as a dependable stand-in for kernel behavior for those covered ops on this host, but not as a universal theorem over all 196 operations; use `book/graph/mappings/vocab/ops_coverage.json` to see which ops have runtime evidence, and extend `runtime-adversarial` when you need similar backing for others.

Role in the substrate:
- Adds the enforcement layer to the static mappings: which Operations (by vocab ID) and inputs were allowed/denied under specific compiled profiles on this host.
- Lets consumers mechanically join runtime outcomes to static structure (op-table vocab, digests, tag layouts) without re-parsing validation logs.
- Status fields carry through harness limits (e.g., partial bucket5 traces, apply gates) so downstream users do not silently upgrade brittle evidence.
 - Lifecycle traces record higher-level policy inputs (entitlements/extension attempts) and their outcomes, grounding lifecycle concepts without rerunning brittle probes.

Regeneration:
- Rerun `book/graph/concepts/validation/out/semantic/runtime_results.json` (via `runtime-checks`) and normalize into this folder using the loader (see `expectations.json` for the expected shape). Keep host/build metadata aligned with `validation/out/metadata.json`.
- Rerun `book/graph/mappings/runtime/generate_lifecycle.py` after updating lifecycle probes in `book/graph/concepts/validation/out/lifecycle/` to refresh `lifecycle.json` and `lifecycle_traces/`.
