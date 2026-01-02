# Runtime Contract Tracking Sheet

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.
Coordination: this file is the only coordination surface for the two big steps.

## Invariant (enforced in both steps)
- Any derived output must be bundle-derived and stamped with `(run_id, artifact_index digest)` and must never become an alternate authority surface.

## Smoke run ritual (after each big step)
1. `python -m book.api.runtime status`
2. `python -m book.api.runtime run --plan <plan.json> --channel <channel>`
3. Verify committed bundle contains `artifact_index.json` and expected lane-scoped artifacts
4. `make -C book test`

## Experiments (keep these three rows updated)

### metadata-runner
- canonical invocation: `python -m book.api.runtime run --plan book/experiments/metadata-runner/plan.json --channel launchd_clean --out book/experiments/metadata-runner/out`
- authoritative outputs (bundle + packet): committed bundle under `book/experiments/metadata-runner/out/<run_id>/artifact_index.json`; optional packet at `book/experiments/metadata-runner/out/promotion_packet.json`
- downstream consumers + allowed reads: `book/graph/concepts/validation/metadata_runner_experiment_job.py` and `book/integration/tests/runtime/test_metadata_runner_outputs.py` should read `runtime_events.normalized.json` from the committed bundle only (resolve via `out/LATEST` + `artifact_index.json`)

### lifecycle-lockdown
- canonical invocation: `python3 book/experiments/lifecycle-lockdown/run_lockdown.py --out book/experiments/lifecycle-lockdown/out` plus runtime lane run `python -m book.api.runtime run --plan book/experiments/lifecycle-lockdown/plan.json --channel launchd_clean --out book/experiments/lifecycle-lockdown/out/runtime/launchd_clean_enforce` (optional `SANDBOX_LORE_PREFLIGHT_FORCE=1` for force)
- authoritative outputs (bundle + packet): runtime bundles under `book/experiments/lifecycle-lockdown/out/runtime/<lane>/<run_id>/` with `artifact_index.json` and `baseline_results.json` (reachability lane); non-bundle cross-check outputs under `book/experiments/lifecycle-lockdown/out/entitlements/` and `book/experiments/lifecycle-lockdown/out/apply/`; no promotion packet today
- downstream consumers + allowed reads: none outside the experiment; only `book/experiments/lifecycle-lockdown/Report.md` should cite bundle artifacts (`artifact_index.json` and run-scoped outputs)

### runtime-adversarial
- canonical invocation: `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean --out book/experiments/runtime-adversarial/out`
- authoritative outputs (bundle + packet): `book/experiments/runtime-adversarial/out/<run_id>/artifact_index.json` (bundle authority) and `book/experiments/runtime-adversarial/out/promotion_packet.json` (consumer boundary; `out/LATEST` is convenience only)
- downstream consumers + allowed reads: `book/experiments/field2-final-final/field2-atlas` and `book/experiments/graph-shape-vs-semantics` must consume `book/experiments/runtime-adversarial/out/promotion_packet.json` only; runtime mapping generators also consume the packet; no consumer should read `out/LATEST` directly

### field2-atlas
- canonical invocation: `PYTHONPATH=$PWD python3 book/experiments/field2-final-final/field2-atlas/atlas_static.py` then `PYTHONPATH=$PWD python3 book/experiments/field2-final-final/field2-atlas/atlas_build.py --packet <promotion_packet.json> --out-root book/experiments/field2-final-final/field2-atlas/out/derived`
- authoritative outputs (bundle + packet): derived outputs only: `book/experiments/field2-final-final/field2-atlas/out/static/field2_records.jsonl` plus `book/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/runtime/field2_runtime_results.json`, `book/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/atlas/field2_atlas.json`, `book/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/atlas/summary.json`, and `book/experiments/field2-final-final/field2-atlas/out/derived/<run_id>/consumption_receipt.json`; upstream packet supplied by caller
- downstream consumers + allowed reads: `book/integration/tests/graph/test_field2_atlas.py` derives outputs from a promotion packet and validates provenance stamps; inputs must come from the packet (no `out/LATEST` scraping)

### graph-shape-vs-semantics
- canonical invocation: run runtime-adversarial plan (see above), emit a promotion packet, then `python3 book/experiments/graph-shape-vs-semantics/summarize_struct_variants.py --packet <promotion_packet.json> --out-root book/experiments/graph-shape-vs-semantics/out/derived`
- authoritative outputs (bundle + packet): derived summary `book/experiments/graph-shape-vs-semantics/out/derived/<run_id>/graph_shape_semantics_summary.json` plus `consumption_receipt.json`; upstream packet supplied by caller
- downstream consumers + allowed reads: none external; summary is derived and upstream access must remain packet-only

## Coupling scans (repo-wide grep results)

### Scan A: `book/experiments/runtime-adversarial/out/` or `out/LATEST` references (excluding `out/`, runtime-adversarial itself, runtime mappings)
Command:
```sh
rg -n "book/experiments/runtime-adversarial/out/|out/LATEST" book --glob '!**/out/**' --glob '!**/*.jsonl' --glob '!book/experiments/runtime-adversarial/**' --glob '!book/graph/mappings/runtime/**' --glob '!book/graph/mappings/runtime_cuts/**'
```
Results:
```
book/integration/tests/runtime/test_runtime_promotion_contracts.py:59:            "book/experiments/runtime-adversarial/out/promotion_packet.json",
book/graph/mappings/vocab/ops_coverage.json:8:      "book/experiments/runtime-adversarial/out/expected_matrix.json",
book/experiments/runtime-closure/Report.md:19:Run via the runtime CLI so the committed bundle is the authority (`out/LATEST` points to the most recent committed run):
book/api/runtime/bundles/reader.py:8:- `out/LATEST` is a convenience pointer to the most recent committed run and is
book/api/runtime/SPEC.md:14:- `out/LATEST` – a convenience pointer containing the most recent committed `run_id` (updated only after commit)
book/api/runtime/SPEC.md:16:Consumers may pass either `out/` or `out/<run_id>/` to `load_bundle()` and related APIs. When `out/LATEST` exists and points to a valid run directory, it is used to resolve the bundle root.
book/api/runtime/SPEC.md:26:The commit barrier is `artifact_index.json`. A bundle is considered **committed** once `artifact_index.json` exists in the run-scoped directory. `out/LATEST` is updated only after this commit step.
book/api/runtime/SPEC.md:100:- updating `out/LATEST`
book/api/runtime/execution/service.py:10:- Updating `out/LATEST` only after the run-scoped bundle is committed so callers
book/api/runtime/execution/service.py:199:    # Bundle roots resolve via `out/LATEST` to the most recent committed run.
book/api/runtime/execution/service.py:763:        # 3) update out/LATEST pointer
book/api/runtime/README.md:17:  as the commit barrier; `out/LATEST` updates only after commit.
book/experiments/hardened-runtime/Plan.md:18:- `out/LATEST/run_manifest.json` (clean-channel provenance bundle).
book/experiments/hardened-runtime/Plan.md:19:- `out/LATEST/baseline_results.json` (unsandboxed baseline comparator).
book/experiments/hardened-runtime/Plan.md:20:- `out/LATEST/runtime_results.json` + `out/LATEST/runtime_events.normalized.json` (decision-stage evidence).
book/experiments/hardened-runtime/Plan.md:21:- `out/LATEST/mismatch_packets.jsonl` (bounded mismatch packets with enumerated reasons).
book/experiments/hardened-runtime/Plan.md:22:- `out/LATEST/oracle_results.json` (sandbox_check oracle lane only).
book/experiments/hardened-runtime/Plan.md:23:- `out/LATEST/summary.json` + `out/LATEST/summary.md` (status and coverage).
book/experiments/hardened-runtime/Plan.md:24:- `out/LATEST/artifact_index.json` (bundle index + digests).
book/experiments/hardened-runtime/README.md:24:The run emits artifacts under `book/experiments/hardened-runtime/out/<run_id>/` and updates `book/experiments/hardened-runtime/out/LATEST`. Every JSON artifact carries a `schema_version`. The canonical entrypoint is the Artifact Index:
book/experiments/hardened-runtime/Report.md:15:- `out/LATEST/run_manifest.json` reports `channel=launchd_clean` with `sandbox_check_self` and staging context.
book/experiments/hardened-runtime/Report.md:16:- `out/LATEST/runtime_events.normalized.json` includes decision-stage events (not apply/preflight only).
book/experiments/hardened-runtime/Report.md:17:- `out/LATEST/baseline_results.json` and `out/LATEST/oracle_results.json` are present and remain separate lanes.
book/experiments/hardened-runtime/Report.md:18:- `out/LATEST/artifact_index.json` lists all core artifacts with digests and schema versions.
book/experiments/hardened-runtime/Report.md:28:- `out/LATEST/run_manifest.json` reports `channel=launchd_clean` with staged root under `/private/tmp`.
book/experiments/hardened-runtime/Report.md:29:- Decision-stage events are present in `out/LATEST/runtime_events.normalized.json`.
book/experiments/hardened-runtime/Report.md:30:- `out/LATEST/baseline_results.json` shows unsandboxed success for mach/sysctl/notification/process-info probes, while sandboxed runs deny under the current profiles.
book/experiments/hardened-runtime/Report.md:34:- Clean-channel run provenance (`out/LATEST/run_manifest.json`) and apply preflight (`out/LATEST/apply_preflight.json`).
book/experiments/hardened-runtime/Report.md:35:- Baseline comparator (`out/LATEST/baseline_results.json`) recorded from unsandboxed probes.
book/experiments/hardened-runtime/Report.md:36:- Decision-stage runtime outputs (`out/LATEST/runtime_results.json`, `out/LATEST/runtime_events.normalized.json`).
book/experiments/hardened-runtime/Report.md:37:- Oracle lane (`out/LATEST/oracle_results.json`) separated from syscall-observed outcomes.
book/experiments/hardened-runtime/Report.md:38:- Bounded mismatches (`out/LATEST/mismatch_packets.jsonl`) with enumerated `mismatch_reason`.
book/experiments/hardened-runtime/Report.md:39:- Summary (`out/LATEST/summary.json`, `out/LATEST/summary.md`).
book/experiments/hardened-runtime/Report.md:40:- Artifact index (`out/LATEST/artifact_index.json`) that pins paths, digests, and schema versions for the run.
book/experiments/hardened-runtime/Report.md:46:- Outputs: `book/experiments/hardened-runtime/out/LATEST/` (see Deliverables).
book/experiments/field2-final-final/field2-atlas/Notes.md:14:- Promoted runtime cut from runtime-adversarial (`python3 -m book.api.runtime promote --staging book/experiments/runtime-adversarial/out/runtime_mappings`) and regenerated `runtime_story`, `runtime_coverage`, and `expectations`.
book/experiments/field2-final-final/field2-atlas/Notes.md:19:- Refreshed via launchd clean channel; field2=1 mismatch now has a bounded packet in `book/experiments/runtime-adversarial/out/mismatch_packets.jsonl`, and field2=2560 carries a partial-triple control + baseline witness in `out/runtime/field2_runtime_results.json`.
book/experiments/field2-final-final/field2-atlas/Report.md:30:- Field2 1 (`mount-relative-path`): Anchored via `/etc/hosts` and present in `sys:sample` tag 8; runtime scenario `adv:path_edges:allow-subpath` is deny where expected allow. The mismatch is captured as a packet in `book/experiments/runtime-adversarial/out/mismatch_packets.jsonl` with baseline/oracle/normalization controls and labeled `canonicalization_boundary`.
book/experiments/field2-final-final/field2-atlas/Report.md:39:- Mismatch packets: `book/experiments/runtime-adversarial/out/mismatch_packets.jsonl` (decision-stage mismatch bundles).
book/experiments/field2-final-final/field2-atlas/Report.md:40:- Promotion packet: `book/experiments/runtime-adversarial/out/promotion_packet.json` (required for runtime events + baseline results + run manifest unless `--allow-legacy` is passed).
book/experiments/field2-final-final/anchor-filter-map/Report.md:17:Use the runtime CLI so the committed bundle is the only authority (resolve the latest run via `out/LATEST`):
book/experiments/runtime-checks/Report.md:13:- Output location: run-scoped bundles under `book/experiments/runtime-checks/out/<run_id>/` (resolve via `out/LATEST`).
book/experiments/runtime-checks/Report.md:16:Run via the runtime CLI and treat the committed bundle as the authority (`out/LATEST` points to the most recent committed run):
book/experiments/runtime-checks/Report.md:36:  - Expected probe matrix in `out/LATEST/expected_matrix.json` covers bucket-4 (`v1_read`) and bucket-5 (`v11_read_subpath`) synthetic profiles, runtime shapes (`allow_all`, `metafilter_any`), and system blobs (`airlock`, `bsd`) flagged for blob mode (airlock marked expected-fail locally).
book/experiments/runtime-checks/Report.md:40:  - Latest rerun executed via `python -m book.api.runtime run --plan book/experiments/runtime-checks/plan.json --channel launchd_clean` (staged to `/private/tmp`); decision-stage outcomes are current for the runtime-checks matrix and only `sys:airlock` remains preflight-blocked. `out/LATEST/runtime_results.json` now carries seatbelt-callout markers (sandbox_check oracle lane) for file/mach probes.
book/experiments/runtime-checks/Report.md:41:  - Clean-channel runs now emit `out/LATEST/run_manifest.json` and `out/LATEST/apply_preflight.json` (sandbox_check self check + baseline metadata). Mapping generators require `channel=launchd_clean` before promoting decision-stage artifacts.
book/experiments/runtime-checks/Report.md:46:  - Listed the operations and concrete probes for bucket-4 and bucket-5 profiles (e.g., `file-read*` on `/etc/hosts` and `/tmp/foo`, `file-write*` to `/etc/hosts` / `/tmp/foo`), captured in `out/LATEST/expected_matrix.json`.
book/experiments/runtime-checks/Report.md:63:   - Refine expected allow/deny outcomes based on decoder bucket assignments and tag signatures; update `out/LATEST/expected_matrix.json` as needed.
book/experiments/runtime-checks/Report.md:65:   - Run plan-based probes via `python -m book.api.runtime run --plan book/experiments/runtime-checks/plan.json --channel launchd_clean` and read results from `out/LATEST/runtime_results.json`.
book/experiments/runtime-checks/Report.md:71:- Probe matrix in `book/experiments/runtime-checks/out/LATEST/expected_matrix.json` describing profiles, probes, and expected outcomes.
book/experiments/runtime-checks/Report.md:72:- Runtime results in `book/experiments/runtime-checks/out/LATEST/runtime_results.json` and `book/experiments/runtime-checks/out/LATEST/runtime_events.normalized.json`.
book/experiments/runtime-checks/Report.md:73:- Clean-channel manifests: `book/experiments/runtime-checks/out/LATEST/run_manifest.json` (provenance bundle) and `book/experiments/runtime-checks/out/LATEST/apply_preflight.json` (sandbox_check self check).
book/experiments/runtime-checks/Report.md:74:- Sandbox_check callouts: `book/experiments/runtime-checks/out/LATEST/runtime_results.json` includes `seatbelt_callouts` markers for file/mach probes (oracle lane only).
book/experiments/field2-final-final/probe-op-structure/Report.md:67:- Latest run: `book/experiments/field2-final-final/probe-op-structure/out/39f84aa5-86b4-466d-b5d9-f510299bbd0a/` (see `book/experiments/field2-final-final/probe-op-structure/out/LATEST`).
book/experiments/field2-final-final/probe-op-structure/Report.md:96:Run via the runtime CLI and treat the run-scoped bundle as the authority (`out/LATEST` points to the most recent committed run):
book/experiments/graph-shape-vs-semantics/Report.md:15:- Harness: `python -m book.api.runtime run --plan book/experiments/runtime-adversarial/plan.json --channel launchd_clean` (bundle outputs under `book/experiments/runtime-adversarial/out/LATEST/`).
book/experiments/graph-shape-vs-semantics/Report.md:21:- Inputs: `runtime-adversarial` expected/runtime matrices in `book/experiments/runtime-adversarial/out/LATEST/`.
book/experiments/graph-shape-vs-semantics/Report.md:30:   - Produces per-profile, per-probe runtime results in `book/experiments/runtime-adversarial/out/LATEST/runtime_results.json` (including expectation IDs, allow/deny, match flags, errno, commands).
book/experiments/archive/op-coverage-and-runtime-signatures/Report.md:26:   - `python -m book.api.runtime emit-promotion --bundle book/experiments/runtime-adversarial/out --out book/experiments/runtime-adversarial/out/promotion_packet.json`
book/experiments/preflight-blob-digests/Notes.md:62:  - `python3 book/experiments/preflight-blob-digests/blob_apply_matrix.py --label structural_validation_batch3_scan_shortlist --blob book/experiments/gate-witnesses/out/micro_variants/base_v2_inner_allow_external_method.sb.bin --blob book/experiments/sandbox-init-params/out/named_mDNSResponder.sb.bin --blob book/experiments/field2-final-final/libsandbox-encoder/out/matrix_v1.sb.bin --blob book/experiments/sandbox-init-params/out/file_ftp_proxy.sb.bin --blob book/experiments/field2-final-final/libsandbox-encoder/sb/matrix_v1_domain30.sb.bin --blob book/experiments/field2-final-final/bsd-airlock-highvals/sb/build/airlock_system_fcntl_literal_guard.sb.bin --blob book/experiments/field2-final-final/bsd-airlock-highvals/sb/build/bsd_tag26_matrix.sb.bin --blob book/experiments/field2-final-final/field2-filters/sb/build/bsd_tail_context.sb.bin --blob book/experiments/runtime-adversarial/out/sb_build/net_outbound_deny.sb.bin --blob book/experiments/sbpl-graph-runtime/out/deny_all.sb.bin --out book/experiments/preflight-blob-digests/out/blob_apply_matrix.structural_validation_batch3_scan_shortlist.json`
book/experiments/vfs-canonicalization/Plan.md:77:  - Stored in `out/derived/runtime_results.json` (derived from `out/LATEST/runtime_events.normalized.json` + `out/LATEST/path_witnesses.json`, includes bundle metadata and a `records` list).
book/experiments/vfs-canonicalization/Plan.md:79:  - For each `(profile_id, requested_path)` we record an initial expectation in `out/LATEST/expected_matrix.json`, generated from the runtime plan template. The base `/tmp` family encodes the observed canonicalization pattern (including the `/var/tmp` control), while the additional variants default to a literal-only baseline so mismatches are the signal.
book/experiments/vfs-canonicalization/Plan.md:86:- `python -m book.api.runtime run --plan book/experiments/vfs-canonicalization/plan.json --channel launchd_clean` emits a committed bundle under `out/<run_id>/` and updates `out/LATEST`.
book/experiments/vfs-canonicalization/Plan.md:87:- `python -m book.api.runtime emit-promotion --bundle book/experiments/vfs-canonicalization/out/LATEST --out book/experiments/vfs-canonicalization/out/promotion_packet.json --require-promotable` (when promotion is intended).
book/experiments/vfs-canonicalization/Plan.md:94:- `out/LATEST/expected_matrix.json` – object with profile-scoped probe expectations:
book/experiments/vfs-canonicalization/Plan.md:214:  - `out/LATEST/expected_matrix.json` and `out/derived/runtime_results.json` exist.
book/experiments/vfs-canonicalization/Report.md:6:Run via the runtime CLI and treat the run-scoped bundle as the authority (`out/LATEST` points to the most recent committed run):
book/experiments/vfs-canonicalization/Report.md:27:  - Runtime execution via `python -m book.api.runtime run --plan book/experiments/vfs-canonicalization/plan.json --channel launchd_clean` (bundle under `out/<run_id>/`, `out/LATEST` points to the most recent committed run).
book/experiments/vfs-canonicalization/Report.md:33:  - `out/LATEST/expected_matrix.json` – plan-derived expectations (profile → probe list).
book/experiments/vfs-canonicalization/Report.md:34:  - `out/LATEST/runtime_results.json` – raw runtime harness results (per scenario).
book/experiments/vfs-canonicalization/Report.md:35:  - `out/LATEST/runtime_events.normalized.json` – normalized runtime observations (per scenario).
book/experiments/vfs-canonicalization/Report.md:36:  - `out/LATEST/path_witnesses.json` – file probe FD path witnesses (per scenario).
```

### Scan B: code paths reading bundle layouts or promotion packets (filtered to code; excludes runtime mappings)
Command:
```sh
rg -n --glob '*.{py,sh,js,ts,swift}' "out/LATEST|out/[0-9a-f-]{8}|runtime_events\\.normalized\\.json|runtime_results\\.json|artifact_index\\.json|promotion_packet\\.json" book --glob '!**/out/**' --glob '!book/api/runtime/**' --glob '!book/graph/mappings/runtime/**' --glob '!book/graph/mappings/runtime_cuts/**'
```
Results:
```
book/graph/mappings/system_profiles/generate_attestations.py:13:- `book/graph/concepts/validation/out/semantic/runtime_results.json` (optional link)
book/experiments/field2-final-final/field2-atlas/atlas_build.py:6:- out/runtime/field2_runtime_results.json (from atlas_runtime.py)
book/experiments/field2-final-final/field2-atlas/atlas_build.py:30:RUNTIME_PATH = Path(__file__).with_name("out") / "runtime" / "field2_runtime_results.json"
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:5:and emits `out/runtime/field2_runtime_results.json`. It reuses canonical runtime
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:29:    REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "promotion_packet.json"
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:32:    REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "runtime_events.normalized.json",
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:39:DEFAULT_OUTPUT = Path(__file__).with_name("out") / "runtime" / "field2_runtime_results.json"
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:203:            "promotion_packet.json missing; run runtime emit-promotion or pass --allow-legacy to use legacy paths"
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:206:        raise RuntimeError("promotion_packet.json missing runtime_events; refuse legacy fallback without --allow-legacy")
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:452:        help="Path to promotion_packet.json",
book/experiments/field2-final-final/field2-atlas/atlas_runtime.py:463:        help="Output path for field2_runtime_results.json",
book/graph/concepts/validation/runtime_checks_experiment_job.py:2:Validation job for the runtime-checks experiment. Normalizes runtime_results.json
book/graph/concepts/validation/runtime_checks_experiment_job.py:19:RUNTIME_RESULTS = EXP_ROOT / "runtime_results.json"
book/graph/concepts/validation/metadata_runner_experiment_job.py:4:Normalizes the experiment's bespoke runtime_results.json into contract-shaped
book/graph/concepts/validation/metadata_runner_experiment_job.py:22:RUNTIME_RESULTS = EXP_ROOT / "runtime_results.json"
book/graph/concepts/validation/metadata_runner_experiment_job.py:26:IR_PATH = ROOT / "book/graph/concepts/validation/out/experiments/metadata-runner/runtime_events.normalized.json"
book/experiments/archive/entitlement-diff/run_probes.py:3:simple network/mach probes. Results are written to out/runtime_results.json.
book/experiments/archive/entitlement-diff/run_probes.py:227:    out_path = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "runtime_results.json"
book/experiments/vfs-canonicalization/derive_outputs.py:49:    artifact_index_path = run_dir / "artifact_index.json"
book/experiments/vfs-canonicalization/derive_outputs.py:160:    events = _load_json(run_dir / "runtime_events.normalized.json")
book/experiments/vfs-canonicalization/derive_outputs.py:243:    _write_json(out_dir / "runtime_results.json", runtime_summary)
book/experiments/metadata-runner/run_metadata.py:288:    out_path = OUT_DIR / "runtime_results.json"
book/experiments/metadata-runner/run_metadata.py:304:    normalized_path = OUT_DIR / "runtime_events.normalized.json"
book/experiments/graph-shape-vs-semantics/summarize_struct_variants.py:8:PROMOTION_PACKET = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "promotion_packet.json"
book/integration/tests/runtime/test_metadata_runner_outputs.py:7:RESULTS_PATH = ROOT / "book" / "experiments" / "metadata-runner" / "out" / "runtime_events.normalized.json"
book/integration/tests/runtime/test_metadata_runner_outputs.py:13:    assert isinstance(data, list) and data, "runtime_events.normalized.json should be a non-empty list"
book/integration/tests/runtime/test_runtime_results_metafilter.py:11:    data = load_bundle_json(out_root, "runtime_results.json")
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:68:        _write_json(run_dir / "runtime_results.json", {})
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:69:        _write_json(run_dir / "runtime_events.normalized.json", [])
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:70:        expected_artifacts.extend(["expected_matrix.json", "runtime_results.json", "runtime_events.normalized.json"])
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:96:    out_path = tmp_path / "promotion_packet.json"
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:117:    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:135:    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:157:    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:193:    # No artifact_index.json here: strict load must fail, but debug open must not.
book/integration/tests/runtime/test_runtime_tools_component_promotion_packet.py:198:    packet = runtime_api.emit_promotion_packet(run_dir, tmp_path / "promotion_packet.json")
book/integration/tests/graph/test_anchor_filter_map_cfprefsd_runtime_lift.py:52:    want = "book/experiments/field2-final-final/anchor-filter-map/out/promotion_packet.json"
book/integration/tests/runtime/test_hardened_runtime_artifacts.py:38:    artifact_index_path = bundle_dir / "artifact_index.json"
book/integration/tests/runtime/test_hardened_runtime_artifacts.py:40:    runtime_results_path = bundle_dir / "runtime_results.json"
book/integration/tests/runtime/test_hardened_runtime_artifacts.py:58:        runtime = load_bundle_json(OUT_DIR, "runtime_results.json")
book/integration/tests/runtime/test_hardened_runtime_artifacts.py:68:        assert artifact_index_path.exists(), "missing artifact_index.json"
book/integration/tests/runtime/test_runtime_pipeline.py:51:    results_path = tmp_path / "runtime_results.json"
book/integration/tests/runtime/test_runtime_pipeline.py:87:    results_path = tmp_path / "runtime_results.json"
book/integration/tests/runtime/test_runtime_pipeline.py:103:    results_path = tmp_path / "runtime_results.json"
book/integration/tests/graph/test_field2_atlas.py:57:    runtime_doc = load_json(ROOT / "book" / "experiments" / "field2-atlas" / "out" / "runtime" / "field2_runtime_results.json")
book/integration/tests/runtime/test_runtime_tools_component_reindex_bundle.py:23:    index_path = bundle.out_dir / "artifact_index.json"
book/integration/tests/runtime/test_runtime_contract_guardrails.py:33:    "artifact_index.json",
book/integration/tests/runtime/test_runtime_contract_guardrails.py:45:    "runtime_events.normalized.json",
book/integration/tests/runtime/test_runtime_contract_guardrails.py:46:    "runtime_results.json",
book/integration/tests/runtime/test_vfs_canonicalization_outputs.py:18:    """Shape guardrail: expected_matrix.json and derived runtime_results.json exist and have basic structure."""
book/integration/tests/runtime/test_vfs_canonicalization_outputs.py:20:    results = load_json(DERIVED_ROOT / "runtime_results.json")
book/integration/tests/runtime/test_vfs_canonicalization_outputs.py:33:    assert isinstance(results, dict), "runtime_results.json should be an object"
book/integration/tests/runtime/test_vfs_canonicalization_outputs.py:35:    assert isinstance(records, list) and records, "runtime_results.json should include records"
book/integration/tests/runtime/test_vfs_canonicalization_outputs.py:48:    results = load_json(DERIVED_ROOT / "runtime_results.json")
book/integration/tests/runtime/test_runtime_results_system_profiles.py:9:    data = load_bundle_json(out_root, "runtime_results.json")
book/integration/tests/runtime/test_runtime_adversarial.py:22:    runtime_results = load_bundle_json(OUT_DIR, "runtime_results.json")
book/integration/tests/runtime/test_runtime_events_files.py:23:            load_bundle_json(ROOT / "book" / "experiments" / "runtime-adversarial" / "out", "runtime_events.normalized.json"),
book/integration/tests/runtime/test_runtime_events_files.py:27:            load_json(ROOT / "book" / "experiments" / "metadata-runner" / "out" / "runtime_events.normalized.json"),
book/integration/tests/runtime/test_runtime_events_files.py:31:            load_bundle_json(ROOT / "book" / "experiments" / "vfs-canonicalization" / "out", "runtime_events.normalized.json"),
book/integration/tests/runtime/test_sbpl_graph_runtime_strict_case.py:8:RESULTS_PATH = ROOT / "book" / "profiles" / "golden-triple" / "runtime_results.json"
book/integration/tests/runtime/test_runtime_tools_service_bundle.py:28:    assert (bundle.out_dir / "artifact_index.json").exists()
book/integration/tests/runtime/test_runtime_tools_service_bundle.py:35:    index_doc = json.loads((bundle.out_dir / "artifact_index.json").read_text())
book/integration/tests/runtime/test_runtime_tools_service_bundle.py:87:    out_path = tmp_path / "promotion_packet.json"
book/integration/tests/runtime/test_runtime_tools_service_bundle.py:131:    assert not (run_dir / "artifact_index.json").exists()
book/integration/tests/runtime/test_runtime_tools_service_bundle.py:153:    assert (run_dir / "artifact_index.json").exists()
book/integration/tests/runtime/test_runtime_promotion_contracts.py:43:    if "promotion_packet.json missing" not in atlas_text:
book/integration/tests/runtime/test_runtime_promotion_contracts.py:58:            "book/experiments/runtime-checks/out/promotion_packet.json",
book/integration/tests/runtime/test_runtime_promotion_contracts.py:59:            "book/experiments/runtime-adversarial/out/promotion_packet.json",
book/integration/tests/runtime/test_runtime_promotion_contracts.py:60:            "book/experiments/hardened-runtime/out/promotion_packet.json",
book/integration/tests/runtime/test_runtime_promotion_contracts.py:61:            "book/experiments/field2-final-final/anchor-filter-map/out/promotion_packet.json",
book/integration/tests/runtime/test_runtime_promotion_contracts.py:62:            "book/experiments/field2-final-final/anchor-filter-map/iokit-class/out/promotion_packet.json",
book/integration/tests/runtime/test_runtime_golden.py:12:RUNTIME_RESULTS = BUNDLE_DIR / "runtime_results.json"
book/integration/tests/runtime/test_network_outbound_guardrail.py:38:    results = load_bundle_json(OUT_ROOT, "runtime_results.json")
```

### Scan C: metadata-runner scripts/ad-hoc outputs
Command:
```sh
rg -n "runtime_results\\.json|decode_profiles\\.json|run_metadata\\.py|metadata_runner|metadata-runner" book/experiments/metadata-runner --glob '!**/out/**'
```
Results:
```
book/experiments/metadata-runner/Notes.md:4:- Swift runner (`book/api/runtime/native/metadata_runner/metadata_runner.swift`) uses `sandbox_init` with SBPL input and issues `lstat`/`getattrlist`/`setattrlist`/`fstat` (read-metadata) and `chmod`/`utimes`/`fchmod`/`futimes`/`lchown`/`fchown`/`fchownat`/`lutimes` (metadata write proxies), emitting JSON.
book/experiments/metadata-runner/Notes.md:5:- `run_metadata.py` compiles SBPL probes, builds the runner, seeds fixtures via canonical paths, and runs the matrix across alias/canonical paths for both operations and all syscalls; outputs land in `out/runtime_results.json` and `out/decode_profiles.json`.
book/experiments/metadata-runner/Notes.md:9:- Migrated the Swift runner source to `book/api/runtime/native/metadata_runner` and updated the driver to build via the shared build script.
book/experiments/metadata-runner/Notes.md:10:- Local build attempt of `book/api/runtime/native/metadata_runner/build.sh` failed with Swift module cache permission errors and an SDK/compiler mismatch; the script itself is correct but the toolchain needs alignment to run.
book/experiments/field2-final-final/metadata-runner/check_structural.py:3:Cross-check anchors/tags/field2 against anchor_filter_map for metadata-runner profiles.
book/experiments/metadata-runner/EPERM.md:1:# EPERM handling for metadata-runner
book/experiments/metadata-runner/EPERM.md:17:   - `python3 book/experiments/metadata-runner/run_metadata.py`
book/experiments/metadata-runner/EPERM.md:18:   - Inspect `out/runtime_results.json` for `status`/`errno` and `out/decode_profiles.json` for anchor presence.
book/experiments/metadata-runner/EPERM.md:21:   - `swiftc book/api/runtime/native/metadata_runner/metadata_runner.swift book/api/runtime/native/ToolMarkers.swift /tmp/seatbelt_callout_shim.o -o /tmp/metadata_runner_test`  
book/experiments/metadata-runner/EPERM.md:23:   - `/tmp/metadata_runner_test --sbpl /tmp/simple_meta.sb --op file-read-metadata --path /private/tmp/foo` → `OK`  
book/experiments/metadata-runner/EPERM.md:24:   - `/tmp/metadata_runner_test --sbpl /tmp/simple_meta.sb --op file-read-metadata --path /tmp/foo` → `EPERM`
book/experiments/metadata-runner/Report.md:19:- Driver `run_metadata.py` builds the runner, compiles SBPL, ensures fixtures under canonical paths, runs the full matrix (profiles × ops × alias/canonical), and writes `out/runtime_results.json` plus `out/decode_profiles.json`.
book/experiments/metadata-runner/Report.md:24:- Outbound artifacts (`out/runtime_results.json`, `out/decode_profiles.json`) reflect the intended path anchors and the observed allow/deny matrix without empty/parse failures.
book/experiments/metadata-runner/Report.md:35:- Swift runner (`book/api/runtime/native/metadata_runner/metadata_runner.swift`) uses `sandbox_init` with SBPL input; driver `run_metadata.py` compiles probes, builds the runner via the shared build script, seeds fixtures, and emits runtime/decode outputs.
book/experiments/metadata-runner/Report.md:41:- Runner + driver: `book/api/runtime/native/metadata_runner/metadata_runner.swift`, `book/experiments/metadata-runner/run_metadata.py` (builds `book/api/runtime/native/metadata_runner/metadata_runner`).
book/experiments/metadata-runner/Report.md:42:- Outputs: `out/runtime_results.json` (matrix run) and `out/decode_profiles.json` (anchor summaries); `out/anchor_structural_check.json` (cross-check vs anchor_filter_map for available anchors).
book/experiments/metadata-runner/run_metadata.py:31:RUNNER_DIR = REPO_ROOT / "book" / "api" / "runtime" / "native" / "metadata_runner"
book/experiments/metadata-runner/run_metadata.py:32:RUNNER_BIN = RUNNER_DIR / "metadata_runner"
book/experiments/metadata-runner/run_metadata.py:153:    out_path = OUT_DIR / "decode_profiles.json"
book/experiments/metadata-runner/run_metadata.py:169:        p.write_text(f"metadata-runner fixture for {p.name}\n")
book/experiments/metadata-runner/run_metadata.py:278:            "entrypoint": "metadata_runner",
book/experiments/metadata-runner/run_metadata.py:288:    out_path = OUT_DIR / "runtime_results.json"
```
