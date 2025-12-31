# policywitness-deny-atlas (Report)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` (Sonoma 14.4.1 / 23E224, arm64).

## Purpose

Build an entitlement-lane deny atlas for this host using PolicyWitness and the external observer. The atlas should separate permission-shaped failures that are observer-backed from those that are not, so later work can cite denials without overclaiming.

## Scope

- Uses PolicyWitness probes (`book.api.witness.client.run_probe`) with observer capture.
- Uses operation/filter vocabulary from the bedrock mappings:
  - `book/graph/mappings/vocab/ops.json`
  - `book/graph/mappings/vocab/filters.json`
  - `book/graph/mappings/vocab/ops_coverage.json`
- Produces mapped-tier evidence only when a deny is observed by the external observer and the log line can be mapped to the vocab. Permission-shaped failures without deny evidence are hypothesis-tier.
- File deny lines frequently omit an explicit primary filter; these are mapped with `filter_inferred` as a limit.
- Stage/lane: `operation` / `scenario`.

## Hypotheses and falsification steps

H1 (mapped): For each base PolicyWitness profile, there exists at least one probe in a fixed "deny set" that yields an observer-backed deny line whose operation and primary filter map to the bedrock vocab.  
Falsify by running the deny set (see Plan) across all base profiles; any profile that yields no observer-backed deny lines or yields only unmapped operations/filters falsifies H1 for that profile.

H2 (hypothesis): Permission-shaped failures without observer evidence are common and should not be treated as denials in the atlas.  
Falsify by showing that, for the same permission-shaped outcomes, the observer consistently reports deny lines (observed_deny true) with a matching PID/process name and an operation/filter mapping.

H3 (mapped): The deny atlas is stable across repeated runs within the same host baseline (same profile + probe yields the same observed operation/filter pair).  
Falsify by re-running a fixed subset of probes and observing a different operation/filter pair or a non-deny outcome under identical inputs.

H4 (hypothesis): Some permission-shaped failures are non-sandbox failures (e.g., `connection_refused`) and should be explicitly tagged as non-deny outcomes.  
Falsify by capturing observer-backed deny lines for these cases, or by mapping them to a sandbox operation/filter in the observer output.

## Deliverables / expected outcomes

- `Report.md`, `Plan.md`, `Notes.md` for the experiment.
- `out/<run_id>/deny_atlas.json`: profile x probe x operation x filter x target, with evidence tier per record.
- `out/<run_id>/runs.jsonl`: per-probe records (probe result + observer report + parsed log excerpt).
- Optional `out/<run_id>/summary.json`: counts by profile and operation.

## Plan & execution log

- `smoke-0f3bee8f-2cbc-4339-a076-f1fc023094f9`: no elevation → `xpc_error` (Sandbox restriction, error 159). Observer skipped due to missing pid/process name.
- `smoke-8ecb378c-fd7f-443a-8575-b7faf951ed43`: `--capture-sandbox-logs` run; host capture failed with `missing child_pid for sandbox log capture`.
- `smoke-f0db6faf-1afb-429d-ba0d-720499effdbb`: manual observer (`--last 30s`); 27 records, 7 mapped denies across `minimal`, `net_client`, `temporary_exception`. Observed operations: `file-read-data`, `file-write-create` (filter inferred), and `network-outbound` (explicit `remote` filter).
- `smoke-fd118439-a88a-44c6-954d-5c80afba9714`: manual observer with time-range + correlation id; fewer mapped denies (6) and `minimal` produced no mapped denies. Treat as brittle capture.
- `smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156`: manual observer (`--last 30s`) + correlation id; 27 records, 12 mapped denies across all three profiles. Observed operations: `file-read-data`, `file-write-create` (filter inferred), and `network-outbound` (explicit `remote` filter). This is the current best atlas output.
- Stability check: comparing `smoke-f0db6faf-1afb-429d-ba0d-720499effdbb` vs `smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156` shows 7 row_ids flipping between hypothesis and mapped (including `temporary_exception.net_op_tcp_connect_control` mapped → hypothesis). Stability is not yet demonstrated.

## Evidence and tiers

- **Bedrock**: operation/filter vocab mapping paths listed above (from `book/graph/concepts/BEDROCK_SURFACES.json`).
- **Mapped**: observer-backed deny lines that include an operation and primary filter which can be mapped to vocab.
- **Hypothesis**: permission-shaped outcomes without observer evidence or without a reliable mapping to vocab.

## Evidence & artifacts

- `book/experiments/policywitness-deny-atlas/out/smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156/deny_atlas.json` (current best atlas output).
- `book/experiments/policywitness-deny-atlas/out/smoke-dc03c1fb-270e-4a75-901c-6ecdfd557156/runs.jsonl` (full per-probe ledger).
- `book/experiments/policywitness-deny-atlas/out/smoke-fd118439-a88a-44c6-954d-5c80afba9714/deny_atlas.json` (brittle time-range capture comparison).

## Risks / blockers

- XPC connection failures (e.g., "Sandbox restriction") may block some profiles.
- Observer may return zero deny lines even when permission-shaped failures occur.
- Log formats may omit or rename operation/filter fields; parsing must be conservative.
- Time-range observer windows can miss denies; the `--last` mode is currently more reliable.
- Mapped rows can shift between runs; the atlas is currently `partial` until a stability check passes.

## Next steps

- Re-run the `--last` observer mode for `minimal` + one profile to check stability of mapped operations/filters.
- Decide whether `filter_inferred` remains mapped-tier or must downgrade to hypothesis; if downgraded, add a probe or observer mode that yields explicit primary filters.
- Expand the deny set to include a non-file operation that yields explicit filter metadata (to reduce inference).
- Once observer capture is stable, expand from the smoke subset to a full profile sweep.

We hope this atlas yields a clear, reproducible separation between "permission-shaped failure" and "observer-backed deny" for entitlements-lane probes on this host. That separation makes later reasoning about sandbox policy less fragile and prevents accidental promotion of hypothesis-tier outcomes to mapped claims.

We also hope the atlas provides a concrete coverage lens: which operations and filters are observed in practice under entitlement profiles, and which remain vocab-only. That gives us a principled way to prioritize new probes and to align mapped evidence with bedrock vocabulary on this baseline.
