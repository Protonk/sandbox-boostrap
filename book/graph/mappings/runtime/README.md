# Runtime probes

Runtime probe outputs that are stable enough to reuse live here. These are versioned to the Sonoma baseline (23E224) and come from runtime promotion packets (clean launchd channel).

Current artifacts:
- `expectations.json` — manifest keyed by `profile_id` (plus `metadata`) with host/build/SIP metadata, blob path + SHA256, status (`ok`/`partial`/`blocked`), probe count, and the trace file path.
- `traces/*.jsonl` — normalized per-profile probe rows (`profile_id`, `probe_name`, operation name/id, inputs, expected vs actual, match/status, command, exit code) with vocab IDs attached. Sources point back to the validation log for provenance.
- `lifecycle.json` + `lifecycle_traces/*.jsonl` — normalized lifecycle probes (entitlements, extensions) with status per scenario, host/build metadata, and source log pointers.
- `golden_expectations.json` — golden runtime profile manifest (bucket4, bucket5, metafilter_any, strict_1, sys:bsd deny-only, sys:airlock EPERM) with blob hashes and modes; includes `metadata`.
- `traces/golden_traces.jsonl` — normalized probe rows for the golden set from runtime-checks.
- `golden_decodes.json` + `decoded_blobs/` — compiled blobs and slim decode summaries (node_count, op_count, tag_counts, literal_strings) for the same golden set; includes `metadata`.
- `runtime_signatures.json` — small IR derived from promotion packets plus `field2_ir.json`, summarizing probe outcomes by profile plus a field2 summary; regenerated via `book/graph/mappings/runtime/promote_from_packets.py` and folded into CARTON.
- `op_runtime_summary.json` — per-operation runtime summary (counts, mismatches, blocked stages) derived from promotion packets; aligns with `runtime_cuts/ops.json`.
- `runtime_links.json` — cross-link index tying runtime observations to profiles, ops vocab, system profile digests, and oracle lanes.
- `runtime_callout_oracle.json` — sandbox_check oracle lane derived from seatbelt-callout markers (decision-only; not syscall outcomes).
- `packet_set.json` — ordered list of promotion packets considered for promotion on this host baseline (config input).
- `promotion_receipt.json` — machine-readable receipt showing which packets were used/rejected (and why) for the current promoted cut.
- CARTON: see `book/integration/carton/bundle/CARTON.json` for frozen hashes/paths of the runtime mappings/IR that are included in CARTON for Sonoma 14.4.1.

Status update (launchd clean run):
- Latest refresh ran via the runtime launchd-clean channel (`python -m book.api.runtime run --plan ... --channel launchd_clean`), which avoids the Desktop TCC block by staging to `/private/tmp`; decision-stage outcomes are current for runtime-checks and runtime-adversarial.
- Clean-channel runs emit promotion packets (`book/experiments/*/out/promotion_packet.json`), and generators refuse to promote decision-stage artifacts unless `channel=launchd_clean`.
- `sys:airlock` remains preflight-blocked on this host; treat that profile as blocked evidence.
- `runtime_signatures.json` and `runtime_coverage.json` remain `partial` due to scoped mismatches (structural/path families), not due to apply gates.

Claims and limits (current host cut):
- Decision-stage outcomes are current for runtime-checks and runtime-adversarial; mismatches remain in structural/path families and keep coverage/status at `partial`.
- The sandbox_check oracle lane (`runtime_callout_oracle.json`) is additive evidence only; do not treat it as syscall outcomes.
- The `/tmp` → `/private/tmp` boundary is still recorded (via normalized path fields and the focused VFS canonicalization experiment) and remains a known divergence outside the PolicyGraph model.
- Use `book/graph/mappings/vocab/ops_coverage.json` and explicit status fields to gauge what is currently runtime-backed vs blocked on this host.

Role in the substrate:
- Adds the enforcement layer to the static mappings: which Operations (by vocab ID) and inputs were allowed/denied under specific compiled profiles on this host.
- Lets consumers mechanically join runtime outcomes to static structure (op-table vocab, digests, tag layouts) without re-parsing validation logs.
- Status fields carry through harness limits (e.g., partial bucket5 traces, apply gates) so downstream users do not silently upgrade brittle evidence.
 - Lifecycle traces record higher-level policy inputs (entitlements/extension attempts) and their outcomes, grounding lifecycle concepts without rerunning brittle probes.

Regeneration:
- Rerun runtime-checks and runtime-adversarial via the runtime launchd-clean channel so promotion packets are emitted; generators refuse to promote decision-stage artifacts unless the run manifest says `channel=launchd_clean`.
- Run `book/graph/mappings/runtime/promote_from_packets.py` (defaults to `packet_set.json`) to rebuild `runtime_cuts/`, `runtime_story`, `runtime_coverage`, `runtime_callout_oracle`, and `runtime_signatures.json` from promotion packets, and to refresh `promotion_receipt.json`.
- `op_runtime_summary.json` is regenerated by the same promotion path; see `book/graph/mappings/runtime/generate_op_runtime_summary.py` for the standalone entrypoint.
- `runtime_links.json` is regenerated by the same promotion path; see `book/graph/mappings/runtime/generate_runtime_links.py` for the standalone entrypoint.
- Rerun `book/graph/mappings/runtime/generate_lifecycle.py` after updating lifecycle probes in `book/graph/concepts/validation/out/lifecycle/` to refresh `lifecycle.json` and `lifecycle_traces/`.
