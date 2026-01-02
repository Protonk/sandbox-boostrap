# preflight-blob-digests

## Purpose

Extend the preflight guardrail beyond SBPL source (`.sb`) by recognizing **specific compiled profile blobs** (`.sb.bin`) via `sha256` digest on this host baseline.

This experiment produces a small digest corpus of blobs that are witnessed to be **apply-gated for the harness identity** (apply-stage `EPERM`). The goal is operational: prevent tools and probes from repeatedly crashing into the same blocked apply surface when only a compiled blob is available.

## Baseline & scope

- World: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`
- Input kind: compiled profile blobs (`*.sb.bin`)
- Evidence sources:
  - Minimized witness corpus: `book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json`
  - Direct blob-apply measurements for canonical `sys:*` fixtures: `out/blob_apply_matrix.outside_harness.json`
- Non-goals:
  - explaining *why* apply gating happens (see `book/evidence/experiments/runtime-final-final/suites/gate-witnesses/Report.md` and `troubles/EPERMx2.md`)
  - inferring anything about PolicyGraph decisions or Operation+Filter semantics

## Status

Current state:
- Digest corpus: `out/apply_gate_blob_digests.json` lists 9 apply-gated blob digests (witness-derived + `sys:airlock` fixture + validated micro-variants).
- Validation IR: `book/evidence/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json` is the tool-consumed source for `.sb.bin` preflight.
- Tool behavior: `book/tools/preflight/preflight.py` classifies `.sb.bin` inputs by digest membership (`signature="apply_gate_blob_digest"`).

## Plan & execution log

This experiment proceeded in six steps (mirroring the “ideal sequence”):

1. Static inventory of in-repo blobs (`out/repo_sb_bin_inventory.json`).
2. Join inventory ↔ canonical `sys:*` digests ↔ preflight digest corpus (`out/sys_digest_join.json`).
3. Confirm digest determinism (repeat compiles) and parity across compilation surfaces (`out/compile_determinism.json`).
4. (Folded into step 3) Python `book.api.profile` vs SBPL-wrapper parity.
5. Classify the canonical `sys:*` fixture blobs via `sandbox_apply` outside any globally gated context (`out/blob_apply_matrix.outside_harness.json`).
6. Add control digests + a flip detector so “EPERM == apply gate” cannot be misread when the environment is globally gated (`out/control_digests.json`, `out/apply_matrix_comparison.json`).
7. Expand the digest corpus from additional apply-validation batches and keep “structural signal” work as explicitly partial/brittle (`out/blob_apply_matrix.structural_validation_batch*.json`, `out/structural_signature_*.json`).

## Observations (current cut)

Static inventory (from `out/repo_sb_bin_inventory.json`):
- In-repo `*.sb.bin`: 335 files, 172 unique digests (77 duplicate digests).

Canonical `sys:*` blobs (from `out/sys_digest_join.json`):
- `sys:airlock` (`33d1a72e…`) is now in the apply-gate digest corpus (preflight blocks it by digest).
- `sys:bsd` (`c6fe205f…`) and `sys:sample` (`a82e5aa8…`) are not blocked by digest (preflight remains conservative: “unknown” is not a success claim).

Digest determinism/parity (from `out/compile_determinism.json`):
- For two SBPL inputs (`v0_empty.sb` and the `mach_bootstrap` deny-message-filter witness), sha256 digests are stable across 5 repeated compiles, and Python `book.api.profile` output matches SBPL-wrapper output byte-for-byte.

Blob apply matrix (from `out/blob_apply_matrix.*.json`):
- In the harness context (`label: in_harness`), the control blob is apply-gated (`control_ok=false`) and all tested blobs fail `sandbox_apply` with apply-stage `EPERM` (global gating; not profile-specific evidence).
- In a control-ok context (`label: outside_harness`):
  - `airlock.sb.bin` fails at apply-stage `EPERM` (`sandbox_apply`).
  - `bsd.sb.bin` and `sample.sb.bin` both apply successfully (`sandbox_apply rc==0`), but do not reach a clean exec/run in this minimal probe setup (bootstrap/abort behavior is recorded in the matrix output).

## Lessons (so far)

- For compiled blobs, a digest list is a safer “avoidance” mechanism than attempting to decode or apply: it is mechanically checkable and cannot be misread as “the sandbox denied X”.
- Digest classification is only safe if you also carry a “global gating” control: in this repo’s harness context, `sandbox_apply` is often globally gated, and that is not profile-specific evidence.
- This corpus should stay intentionally small: it is a list of confirmed blocked-entrypoint blobs, not a universal classifier for all `.sb.bin`.

## Artifacts

- Inventory + joins
  - `out/repo_sb_bin_inventory.json` — sha256 inventory for all in-repo `*.sb.bin` blobs.
  - `out/sys_digest_join.json` — canonical `sys:*` digests joined against the inventory and the digest corpus.
- Determinism/parity
  - `out/compile_determinism.json` — repeated compiles (Python `book.api.profile` vs SBPL-wrapper) for two SBPL inputs.
- Apply-stage evidence
  - `out/blob_apply_matrix.in_harness.json` — demonstrates global apply gating inside the harness context (`control_ok=false`).
  - `out/blob_apply_matrix.outside_harness.json` — `sys:*` fixture apply results in a control-ok context.
  - `out/apply_matrix_comparison.json` — detects outcome flips and tags one context as globally gated.
  - `out/control_digests.json` — small set of “known not apply-gated” control digests with evidence.
- Digest corpus + tool wiring
  - `out/apply_gate_blob_digests.json` — canonical list of apply-gated digests (input to validation job).
  - `book/evidence/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json` — tool-consumed IR.
  - `book/tools/preflight/preflight.py` — `.sb.bin` preflight classifier.

## Regeneration

From repo root:

```sh
# 1) inventory + join (static)
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/inventory_repo_blobs.py \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/repo_sb_bin_inventory.json
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/join_with_sys_digests.py \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/sys_digest_join.json

# 2) compile determinism/parity (static-ish; no apply)
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/compile_determinism.py \
  --sbpl book/evidence/experiments/profile-pipeline/op-table-operation/sb/v0_empty.sb \
  --sbpl book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/minimal_failing.sb \
  --runs 5 \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/compile_determinism.json

# 3) blob apply matrix (requires an execution context where the control blob is not apply-gated)
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/blob_apply_matrix.py \
  --label outside_harness \
  --blob book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin \
  --blob book/evidence/graph/concepts/validation/fixtures/blobs/bsd.sb.bin \
  --blob book/evidence/graph/concepts/validation/fixtures/blobs/sample.sb.bin \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.outside_harness.json

# 4) (optional) record the globally gated harness context for contrast
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/blob_apply_matrix.py \
  --label in_harness \
  --blob book/evidence/graph/concepts/validation/fixtures/blobs/airlock.sb.bin \
  --blob book/evidence/graph/concepts/validation/fixtures/blobs/bsd.sb.bin \
  --blob book/evidence/graph/concepts/validation/fixtures/blobs/sample.sb.bin \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.in_harness.json

# 5) comparisons + controls
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/compare_apply_matrices.py \
  --matrix book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.in_harness.json \
  --matrix book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.outside_harness.json \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/apply_matrix_comparison.json
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/collect_control_digests.py \
  --apply-matrix book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.in_harness.json \
  --apply-matrix book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.outside_harness.json \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/control_digests.json

# 6) regenerate digest corpus (witnesses + outside-harness apply matrix)
python3 book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/collect_gate_blob_digests.py \
  --apply-matrix book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/blob_apply_matrix.outside_harness.json \
  --out book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/apply_gate_blob_digests.json

PYTHONPATH=$PWD python3 -m book.graph.concepts.validation --experiment preflight-blob-digests
```

## Open questions

This experiment can also support broader, still-open (and largely static/unblocked) questions:

- What fraction of in-repo `*.sb.bin` blobs are currently covered by “apply-gated by digest” vs “unknown”?
- Do any canonical `sys:*` blobs (as curated in `book/evidence/graph/mappings/system_profiles/digests.json`) overlap with the apply-gate digest corpus? (Answer so far: `sys:airlock` does; `sys:bsd` and `sys:sample` do not.)
- Are compiled blob digests deterministic across repeated compiles on this world, and consistent across compilation surfaces? (Answer so far: yes for two SBPL inputs, across Python `book.api.profile` and SBPL-wrapper, 5/5 runs each.)
- Can we maintain a small “known not-apply-gated” digest control set to detect environment-wide apply gating vs profile-specific gating?

## Structural signal listening (in progress; partial/brittle)

Digest lists are the **bedrock** avoidance mechanism for `.sb.bin` preflight (exact-match, witness-backed). The next extension is to explore whether compiled blobs contain a **structural signal** that correlates with the current apply-gate witness set.

This work is explicitly **partial/brittle** until expanded and regression-tested: a structural signal is useful for triage and ranking, but it is not (yet) a substitute for witness-backed digest classification.

### Artifacts (structural signal listening)

- Frozen labeled sets (positive + controls): `out/structural_signal_sets.json`
- Decoded structural features (149/149 digests): `out/blob_structural_features.json`
- Candidate signature set (labeled-set only): `out/structural_signature_candidates.json`
- Candidate scans across the in-repo digest corpus:
  - `out/structural_signature_scan.json` (high-precision threshold, default)
  - `out/structural_signature_scan.p75.json` (relaxed threshold for validation planning)
- Apply-validation batches (control_ok context):
  - `out/blob_apply_matrix.structural_validation_batch1.json`
  - `out/blob_apply_matrix.structural_validation_batch2.json`
  - `out/blob_apply_matrix.structural_validation_batch3_scan_shortlist.json`

### Early candidates

From `out/structural_signature_candidates.json` (derived from a small but still-limited labeled set; see `out/structural_signal_sets.json` for the current counts):

- A small “core tag” set emerged for OR/AND exploration (see `core_tags` in `out/structural_signature_candidates.json`).
- The strongest “rare predicate” candidate so far is `node_count_eq_op_count` (perfect precision on the current labeled set, but low recall), which isolates the “tag 9 only” micro-variant family.
- Tag 9 presence is no longer a high-precision signal after adding broader controls that also contain tag 9 (for example, App Sandbox templates); it remains useful only as a coarse ranking feature.
- A “density/ratio” feature family (literal-pool bytes ratio, op-table uniqueness ratio) produced plausible high-precision candidates on a smaller control set, but batch3 validation added new non-gated controls that match those ratios, reducing them to low/medium precision. This is expected and is treated as a **useful falsification**: these ratios are not (yet) durable apply-gate predictors.

These are **not** promoted to a classifier: they are triage signals only until expanded and regression-checked.

### Apply-validation (batch1)

In `out/blob_apply_matrix.structural_validation_batch1.json` (run with `control_ok=true`):

- Two previously-unlabeled digests are confirmed **apply-gated** (apply-stage `EPERM`) for the harness identity:
  - `4043e71f…` (`base_v2_inner_deny_async_external_method.sb.bin`)
  - `a450d277…` (`base_v2_inner_deny_external_trap.sb.bin`)
- Several structurally interesting blobs produced an “unknown” result: the wrapper emitted the *pre-apply* entitlement-check marker, but then emitted **no** apply/exec markers and no canonical stderr text, while exiting `127`. This is treated as a **measurement limitation** (post-apply reporting suppressed), not as apply-gate evidence.

### Apply-validation (batch2)

In `out/blob_apply_matrix.structural_validation_batch2.json` (run with `control_ok=true`):

- Three additional digests are confirmed **apply-gated** (apply-stage `EPERM`) for the harness identity:
  - `d39f451b…` (`base_v1_inner_deny_async_external_method.sb.bin`)
  - `62d86920…` (`base_v1_inner_deny_external_trap.sb.bin`)
  - `67871c25…` (`base_v2_mach_bootstrap_deny_message_send.sb.bin`)
- Several broader corpus blobs applied successfully (apply-report `rc==0`) and now serve as additional “not apply-gated” controls on this world.

### Apply-validation (batch3; scan-shortlisted)

In `out/blob_apply_matrix.structural_validation_batch3_scan_shortlist.json` (run with `control_ok=true`):

- No new apply-gated digests were discovered: all tested blobs except the lingering “unknown” case applied successfully (`sandbox_apply rc==0`).
- Several scan-shortlisted blobs that initially looked “high-risk” by structural ratio (for example, `named_mDNSResponder.sb.bin` and `file_ftp_proxy.sb.bin`) are confirmed **not apply-gated** and are now part of the control set.
- The `base_v2_inner_allow_external_method.sb.bin` micro-variant (`125a3268…`) remains “unknown” due to suppressed post-apply reporting (wrapper exits `127` after emitting only the pre-apply entitlement marker). This remains a measurement limitation, not apply-gate evidence.

Planning notes and next validation targets live in `Plan.md`, and all structural-signal artifacts stay under `book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests/out/` until/unless we decide to promote any of them.
