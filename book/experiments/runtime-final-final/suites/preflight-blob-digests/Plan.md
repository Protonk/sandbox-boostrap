# preflight-blob-digests plan

This file is the “what’s next” plan for the experiment. The canonical narrative and current conclusions live in `Report.md`.

## Structural signal listening (in progress; partial/brittle)

We want a **structural signal** for compiled blobs (`.sb.bin`) that is:

- **host-scoped** to `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`
- **phase-disciplined**: it predicts “likely apply-gated” (apply-stage `EPERM`) without implying anything about PolicyGraph decisions
- treated as **partial/brittle** until we have a broader witness set

The target is not “explain why” or “generalize across macOS”; it’s to reduce dead ends when we only have `.sb.bin`.

### Inputs (current)

- Positive set: known apply-gated digests from `out/apply_gate_blob_digests.json` (and the validation IR generated from it).
- Control set: known not-apply-gated digests from `out/control_digests.json`.
- Corpus: all in-repo `*.sb.bin` from `out/repo_sb_bin_inventory.json`.

### Approach (sketch)

1. Extract stable structural features per digest (op-table ids, tag histogram, section sizes, literal-string counts) using existing `book/api/profile` helpers (avoid new parsers).
2. Identify small “rule-like” candidate signatures that separate the positive set from the control set.
3. Scan the repo inventory to find additional digests matching each candidate signature (these are hypotheses only).
4. Validate candidates by running `sandbox_apply` via SBPL-wrapper **outside any globally gated context**, always recording a non-apply-gated control digest in the same run.
5. Keep outputs and signature candidates in `book/experiments/runtime-final-final/suites/preflight-blob-digests/out/` until they are stable enough to consider promotion.

### Current cut (what exists now)

- Frozen labeled sets: `out/structural_signal_sets.json`
- Structural features per digest: `out/blob_structural_features.json`
- Candidate signatures (labeled-set only): `out/structural_signature_candidates.json`
- Candidate scans across the corpus:
  - `out/structural_signature_scan.json` (high-precision threshold)
  - `out/structural_signature_scan.p75.json` (relaxed threshold for planning)
- Apply-validation batches:
  - `out/blob_apply_matrix.structural_validation_batch1.json`
  - `out/blob_apply_matrix.structural_validation_batch2.json`
  - `out/blob_apply_matrix.structural_validation_batch3_scan_shortlist.json`

### Next steps (structural signal listening)

- Tighten candidate shortlists so they are not dominated by “fp=0 on a tiny control set” artifacts (e.g., require tp>=2, and/or cap corpus match rate).
- Expand the control (known-not-apply-gated) set by applying a few structurally diverse, non-gated blobs in control_ok contexts.
- Validate a small number of *unknown* digests chosen by rare predicates (e.g., `node_count_eq_op_count`) rather than broad tag ORs.
- Treat “post-apply reporting suppressed” outcomes (wrapper emits pre-apply markers but no post-apply markers/stderr) as a distinct measurement limitation and keep them out of the apply-gate witness set.
- Add one additional “structure-only” feature family if needed (for example: tag-count ratios, op-table entry uniqueness, literal-pool density), but keep any derived signatures explicitly partial/brittle until validated. (Current: derived ratio scalars are implemented and already show false positives once controls expand.)
