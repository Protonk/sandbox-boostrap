# Runtime Adversarial Suite – Research Report (Sonoma 14.4.1, arm64, SIP on)

## Purpose
Deliberately stress static↔runtime alignment for this host using adversarial SBPL profiles. Phase 1 covers structural variants and path/literal edges; mach-lookup variants extend coverage to a non-filesystem op. Outputs: expected/runtime matrices, mismatch summaries, and impact hooks to downgrade bedrock claims if mismatches appear.

## Baseline & scope
- World: `sonoma-14.4.1-23E224-arm64` (`book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`).
- Harness: `book.api.golden_runner.run_expected_matrix` + runtime-checks shims; compile/decode via `book.api.sbpl_compile` and `book.api.decoder`.
- Profiles: `struct_flat`, `struct_nested` (structural variants); `path_edges` (path/literal edge stress); `mach_simple_allow`, `mach_simple_variants` (mach-lookup variants). Custom SBPL only; no platform blobs.
- Outputs live in `sb/`, `sb/build/`, and `out/`.

## Current status
- Scaffolded experiment with SBPL sources, build directory, and driver script `run_adversarial.py`.
- Expected/runtime/mismatch/impact JSON schemas defined; guardrail test added.
- Structural variants round-trip (allow/deny probes match); path/literal edge family yields runtime denies on `/tmp` allow probes, categorized as `path_normalization` and annotated in `impact_map.json`.
- Mach family added (allow specific global-name via literal vs regex/nested); see case study below for runtime outcomes.
- Artifacts seeded via `run_adversarial.py`; rerun to refresh after edits.

## Case study – path_edges
- Static intent: allow literal `/tmp/runtime-adv/edges/a` and subpath `/tmp/runtime-adv/edges/okdir/*`, deny `/private/tmp/runtime-adv/edges/a` and the `..` literal to catch traversal. Decoder predicts allows on `/tmp/...` probes via literal/subpath filters.
- Runtime: both `/tmp/...` allow probes return deny with `EPERM` (open target) despite static allow; `/private/tmp` deny and `..` deny align.
- Interpretation: mismatch attributed to VFS canonicalization (`/tmp` → `/private/tmp`) prior to PolicyGraph evaluation rather than tag/layout divergence. Treated as out-of-scope for static IR; captured in `impact_map.json` with `out_of_scope:VFS_canonicalization` and no downgrade to bedrock mappings.

## Case study – mach_variants
- Static intent: allow `mach-lookup` for `com.apple.cfprefsd.agent` only; `mach_simple_variants` uses regex/nesting but aims for the same allow/deny surface (explicit deny on a bogus service).
- Runtime: with baseline allows added for process exec and system reads, both profiles now allow the target service and deny the bogus one; no mismatches recorded. `impact_map.json` marks these expectation_ids as reinforcing the mach-lookup vocab/op-table assumptions (op ID 96).
- Conclusion: mach runtime coverage is now `ok` for this allow/deny pair; further mach/XPC variants can extend coverage.

## Case study – mach_local (local-name literal vs regex)
- Static intent: `mach_local_literal` and `mach_local_regex` both allow `mach-lookup` on local-name `com.apple.cfprefsd.agent` and deny a bogus `com.apple.sandboxadversarial.fake`; regex variant mirrors the literal intent via `local-name-regex`.
- Runtime: allows for the real service and denies for the bogus name match static expectations for both profiles.
- Impact: reinforces bedrock assumptions that `mach-lookup` maps to op ID 96 and that current tag/layout + op-table decoding for mach filters aligns with kernel behavior across literal and regex local-name variants. (Path_edges remains the lone mismatch, scoped to `/tmp` → `/private/tmp` VFS canonicalization out of PolicyGraph scope.)

## Evidence & artifacts
- SBPL sources: `book/experiments/runtime-adversarial/sb/*.sb`.
- Expected/runtime outputs: `book/experiments/runtime-adversarial/out/{expected_matrix.json,runtime_results.json,mismatch_summary.json,impact_map.json}`.
- Mapping stub: `book/graph/mappings/runtime/adversarial_summary.json` (world-level counts).
- Guardrails: `book/tests/test_runtime_adversarial.py` plus dyld slice manifest/checker `book/graph/mappings/dyld-libs/{manifest.json,check_manifest.py}` enforced by `book/tests/test_dyld_libs_manifest.py`.
- Runtime-backed ops: `ops_coverage.json` marks `file-read*`, `file-write*`, and `mach-lookup` as having runtime evidence via runtime-checks and runtime-adversarial families; use it to decide when new probes are needed for other ops.

## Claims and limits
- Covered ops/shapes: Phase 1 adversarial probes cover file-read*/file-write* (bucket-4/bucket-5 filesystem profiles and structural/metafilter variants) and `mach-lookup` (global-name and local-name, literal and regex, simple vs nested forms).
- Static↔runtime alignment: for these ops and shapes, decoded PolicyGraph IR (vocab, tag layouts where used, op-tables, and graphs) matches kernel behavior even under deliberately adversarial constructions; structural variants and mach families all agree with static expectations.
- Bounded mismatch: the only systematic divergence observed is the `/tmp` → `/private/tmp` behavior in `path_edges`, explicitly classified as VFS canonicalization outside the PolicyGraph model and recorded in `impact_map.json` as out-of-scope, not as a decoder bug.
- Scope of claims: this justifies treating the static PolicyGraph IR as a bedrock stand-in for kernel enforcement for the covered ops on this host, but it is not a universal theorem over all 196 operations; for ops without `runtime_evidence: true` in `ops_coverage.json`, agents should design new probes or treat claims as more tentative.
- Routing: when you need empirically grounded behavior for file-read*, file-write*, or mach-lookup on this world, treat the existing IR plus `runtime-adversarial` outputs (`expected_matrix.json`, `runtime_results.json`, `mismatch_summary.json`, `impact_map.json`) as canonical; when stepping outside those ops, consult `ops_coverage.json` and extend `runtime-adversarial` first.

## Next steps
- Run `run_adversarial.py` to regenerate artifacts; inspect `mismatch_summary.json` and annotate `impact_map.json` for any mismatches.
- Extend families (header/format toggles, field2/tag ambiguity, additional non-filesystem ops) once current cases are stable.
- Wire a validation selector if promotion to shared runtime mappings is desired.
