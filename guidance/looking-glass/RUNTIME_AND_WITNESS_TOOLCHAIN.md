# looking-glass — RUNTIME_AND_WITNESS_TOOLCHAIN (producing behavior evidence)

This bundle describes SANDBOX_LORE’s “live evidence” surfaces: the plan-based Seatbelt runtime harness and the PolicyWitness.app harness for App Sandbox/entitlements.

Scope: runtime evidence production and its contract artifacts. It does **not** try to summarize sandbox semantics (see `SANDBOX.md`) or re-state the evidence tier taxonomy (see `WORLD_AND_EVIDENCE.md`).

Baseline anchor: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## 1) Runtime evidence is not “a command failed”

The repo is structured around a simple rule:

> Runtime results only become evidence when they are written as contract-shaped artifacts with world binding, stage/lane labeling, and a promotability decision.

The two most important runtime evidence envelopes are:
- committed runtime bundles (Seatbelt runtime harness), and
- PolicyWitness bundles (App Sandbox harness).

Both use `artifact_index.json` as a commit barrier.

## 2) Seatbelt runtime harness: `book.api.runtime`

`book.api.runtime` is the repo’s unified runtime surface for plan-based runs and bundle/promotion tooling.

### 2.1 What it runs

At a high level, the runtime harness:
- compiles or loads a policy (SBPL or blob),
- attempts to apply/attach it (subject to gating),
- runs probes under controlled channels,
- normalizes results into structured JSON outputs.

The harness is stage-aware and is designed to avoid “stderr archaeology.”

### 2.2 The common run loop (plan -> bundle -> promotion packet)

Run a plan:
```sh
python -m book.api.runtime run --plan <plan.json> --channel launchd_clean --out <out_dir>
```

Emit a promotion packet:
```sh
python -m book.api.runtime emit-promotion --bundle <out_dir> --out <out_dir>/promotion_packet.json --require-promotable
```

Promote runtime packets into mappings:
```sh
python book/graph/mappings/runtime/promote_from_packets.py --packets <packet.json>
```

This writes promoted outputs under `book/evidence/graph/mappings/runtime/` and `book/evidence/graph/mappings/runtime_cuts/` (and a receipt at `book/evidence/graph/mappings/runtime/promotion_receipt.json` by default).

These three steps are the supported way to turn “we ran something” into “the repo can build on this.”

### 2.3 Bundle contract (what to look for in outputs)

A plan run writes into a run-scoped directory and becomes “committed” when `artifact_index.json` exists.

Key artifacts commonly referenced:
- `run_status.json` — bundle lifecycle (`in_progress|complete|failed`).
- `artifact_index.json` — commit barrier; lists artifacts + hashes + sizes.
- `run_manifest.json` — run identity, world binding, channel, and other run metadata.
- `expected_matrix.json` — what the run intended to test.
- `runtime_results.json` — scenario lane results.
- `runtime_events.normalized.json` — normalized events with confounder hints.
- `baseline_results.json` — baseline lane controls.
- `oracle_results.json` — oracle lane outputs (weaker evidence lane).
- `mismatch_packets.json` — mismatch classification outputs (when present).
- `path_witnesses.json` — FD-reported path spellings to keep VFS canonicalization visible.

If an output tree lacks `artifact_index.json`, treat it as debug/unverified.

### 2.4 Preflight (apply-gate avoidance)

The runtime harness integrates apply-gate preflight. This exists because on the baseline host, some policy shapes cannot be attached from a generic harness identity.

Behavioral intent:
- If preflight predicts a known apply gate, record an apply-adjacent non-decision (often labeled `failure_stage:"preflight"`) rather than attempting apply and misclassifying the result.

Common knobs (env vars):
- `SANDBOX_LORE_PREFLIGHT=0` — disable preflight globally.
- `SANDBOX_LORE_PREFLIGHT_FORCE=1` — force apply even when preflight flags gating.

The point of these knobs is to keep “apply-stage gating” separate from “operation-stage deny.”

## 3) App Sandbox + entitlements harness: PolicyWitness (`book.api.witness`)

Seatbelt runtime runs are about applying profiles and observing operation-stage outcomes. App Sandbox questions (entitlements, sandbox container behavior, sandbox-log deny attribution) are handled by a different harness: PolicyWitness.app.

### 3.1 What PolicyWitness is

PolicyWitness is a bundled macOS app with sandboxed XPC services and a host-side CLI. It supports:
- running probes inside sandboxed services under different profiles/variants,
- capturing deny attribution using `sandbox-log-observer` (outside the sandbox),
- producing contract-shaped JSON results.

Bundle location:
- `book/tools/witness/PolicyWitness.app`

### 3.2 `book.api.witness` (the Python surface)

`book.api.witness` wraps the CLI contract and produces structured outputs that other tooling can consume without binding to experiment-specific paths.

Typical use cases:
- one-shot probe runs (`xpc run`),
- attach-first sessions (`xpc session`) to avoid racey attach/observe sequences,
- baseline comparisons across entitlements/SBPL/none execution paths,
- sandbox-log observation for deny evidence.

Contract fixtures (stable interface pins):
- `book/tools/witness/fixtures/contract/`

The existence of these fixtures is important: it means the harness is treated as a contract surface, not an ad hoc tool.

### 3.3 Output commit barrier

Like runtime bundles, witness bundle outputs use `artifact_index.json` as the commit barrier.

Design partner takeaway: if someone is citing PolicyWitness results, ask for the committed bundle directory (not just a pasted stdout blob).

## 4) Common failure-class confusions (and how the tooling avoids them)

The runtime and witness toolchains are designed to prevent four common category errors:

1) **Apply-stage failure ≠ denial**
   - If attach fails (`apply` stage), no PolicyGraph decision happened.
2) **Bootstrap failure ≠ denial**
   - If the probe doesn’t start cleanly, the sandbox never evaluated the intended operation.
3) **Observer-only deny evidence ≠ syscall observation**
   - `sandbox-log-observer` provides attribution signals, not full kernel tracing.
4) **Baseline constraints impersonate sandbox**
   - TCC / hardened runtime / SIP / canonicalization can produce denial-shaped outcomes.

The toolchain encodes stage/lane labeling and commit barriers to keep these errors visible.
